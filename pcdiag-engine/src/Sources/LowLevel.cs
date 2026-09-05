using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace PcDiag.Sources
{
    // Fatos lidos direto da CPU pela instrucao CPUID - nao do WMI, nao do
    // registro. Nenhuma camada do Windows entre a pergunta e a resposta:
    // e o silicio respondendo.
    public sealed class CpuIdFacts
    {
        public CpuIdFacts()
        {
            Caches = new List<CacheDescriptor>();
        }

        public string Vendor { get; set; }
        public string BrandString { get; set; }
        public int Family { get; set; }
        public int Model { get; set; }
        public int Stepping { get; set; }
        public uint MaxLeaf { get; set; }
        public uint MaxExtendedLeaf { get; set; }

        public bool Sse2 { get; set; }
        public bool Avx { get; set; }
        public bool Avx2 { get; set; }
        public bool Fma { get; set; }
        public bool Avx512F { get; set; }
        public bool Aes { get; set; }
        public bool RdRand { get; set; }
        public bool OsAvxEnabled { get; set; }

        public bool Hypervisor { get; set; }
        public string HypervisorVendor { get; set; }

        public bool InvariantTsc { get; set; }
        public bool DigitalThermalSensor { get; set; }
        public bool TurboBoost { get; set; }
        public bool ThermalMonitor { get; set; }
        public bool HardwareFeedback { get; set; }

        public List<CacheDescriptor> Caches { get; set; }

        public string FeatureSummary()
        {
            List<string> f = new List<string>();
            if (Sse2) f.Add("SSE2");
            if (Avx) f.Add("AVX");
            if (Avx2) f.Add("AVX2");
            if (Fma) f.Add("FMA3");
            if (Avx512F) f.Add("AVX-512F");
            if (Aes) f.Add("AES-NI");
            if (RdRand) f.Add("RDRAND");
            if (InvariantTsc) f.Add("TSC invariante");
            return f.Count == 0 ? "nenhuma extensao detectada" : string.Join(", ", f.ToArray());
        }
    }

    public sealed class CacheDescriptor
    {
        public int Level { get; set; }
        public string Kind { get; set; }     // Dados | Instrucao | Unificado
        public int SizeKb { get; set; }
        public int Ways { get; set; }
        public int LineBytes { get; set; }

        public override string ToString()
        {
            return "L" + Level + " " + Kind + ": " + SizeKb + " KB, " + Ways + " vias, linha de " + LineBytes + " B";
        }
    }

    // ================================================================
    //  Ponte para o codigo de maquina emitido em NativeCode.cs.
    //
    //  Tudo aqui e opcional por construcao: se a alocacao de pagina
    //  executavel for barrada (antivirus, Arbitrary Code Guard, processo de
    //  32 bits), TryCreate devolve null COM MOTIVO e o diagnostico continua
    //  com o caminho gerenciado. Nenhum teste vira "aprovado" por causa
    //  disso - vira "nao executado".
    // ================================================================
    public sealed class LowLevelEngine : IDisposable
    {
        // 14 acumuladores independentes. FMA tem latencia de 4 a 5 ciclos e
        // vazao de 2 por ciclo: com menos de ~10 cadeias independentes o laco
        // fica preso na latencia e a CPU nunca chega perto do consumo maximo,
        // que e justamente o que este teste precisa provocar.
        public const int Accumulators = 14;
        public const int InnerSteps = 4096;

        // Limite de exatidao: os acumuladores sao float de 32 bits, exatos
        // ate 2^24. Passar disso faria a soma parar de crescer e o teste
        // acusaria "erro de calculo" numa CPU perfeitamente sadia.
        public const int MaxBlocksPerCall = 256;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void CpuIdFn(uint leaf, uint subleaf, IntPtr output);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ulong TscFn();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ulong XgetbvFn(uint index);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void BurnFn(ulong blocks, IntPtr buffer);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void StreamWriteFn(IntPtr destination, IntPtr source, ulong bytes);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void StreamReadFn(IntPtr source, ulong bytes);

        private ExecutableCode _page;
        private CpuIdFn _cpuid;
        private TscFn _tsc;
        private XgetbvFn _xgetbv;
        private BurnFn _burn;
        private StreamWriteFn _streamWrite;
        private StreamReadFn _streamRead;

        public CpuIdFacts Facts { get; private set; }
        public bool UsesFma { get; private set; }

        public string BurnDescription
        {
            get
            {
                return UsesFma
                    ? "FMA de 256 bits (AVX2), " + Accumulators + " cadeias independentes"
                    : "SSE2 de 128 bits, " + Accumulators + " cadeias independentes";
            }
        }

        public bool StreamingAvailable { get { return _streamWrite != null; } }

        // Bytes do buffer de trabalho de cada thread de carga.
        public int BurnBufferBytes { get { return UsesFma ? 512 : 256; } }
        public int BurnLanes { get { return UsesFma ? 8 : 4; } }

        private LowLevelEngine() { }

        public static LowLevelEngine TryCreate(out string unavailableReason)
        {
            unavailableReason = null;

            if (IntPtr.Size != 8)
            {
                unavailableReason = "processo de 32 bits; as rotinas de baixo nivel sao x86-64.";
                return null;
            }

            // IntPtr.Size==8 so prova que o
            // PROCESSO e de 64 bits - num notebook ARM64 (Snapdragon X,
            // Surface Pro X) rodando PcDiag.exe x64 sob emulacao, o processo
            // TAMBEM e de 64 bits (IntPtr.Size==8), mas a CPU real nao
            // entende as instrucoes x86-64 montadas aqui (CPUID, RDTSC,
            // VFMADD231PS...) - o emulador as traduz, e todo numero que sai
            // daqui (marca, familia/modelo, caches, extensoes, largura de
            // banda de memoria) fica rotulado como "medido no silicio" sendo,
            // na verdade, ficcao do tradutor. GetNativeSystemInfo devolve a
            // arquitetura REAL do processador (nao a do processo, que o
            // WOW64/emulador esconde) - recusa quando for ARM (5) ou ARM64
            // (12), os dois casos onde codigo x64 nativo so roda via
            // emulacao.
            Native.SystemInfoLite nativeInfo = Native.GetSystemInfoNative();
            if (nativeInfo != null && (nativeInfo.Architecture == "ARM" || nativeInfo.Architecture == "ARM64"))
            {
                unavailableReason = "CPU nativa e " + nativeInfo.Architecture +
                    "; as rotinas de baixo nivel sao x86-64 e so rodariam sob emulacao, invalidando a medida.";
                return null;
            }

            LowLevelEngine engine = new LowLevelEngine();
            try
            {
                engine.Build();
                return engine;
            }
            catch (Exception ex)
            {
                engine.Dispose();
                unavailableReason = ex.GetType().Name + ": " + ex.Message;
                return null;
            }
        }

        private void Build()
        {
            _page = new ExecutableCode(16384);

            IntPtr cpuidAddress = _page.Add(BuildCpuId());
            IntPtr tscAddress = _page.Add(BuildRdtsc());
            IntPtr xgetbvAddress = _page.Add(BuildXgetbv());

            _page.MakeExecutable();

            _cpuid = (CpuIdFn)Marshal.GetDelegateForFunctionPointer(cpuidAddress, typeof(CpuIdFn));
            _tsc = (TscFn)Marshal.GetDelegateForFunctionPointer(tscAddress, typeof(TscFn));
            _xgetbv = (XgetbvFn)Marshal.GetDelegateForFunctionPointer(xgetbvAddress, typeof(XgetbvFn));

            Facts = ReadCpuIdFacts();

            // Segunda pagina: os lacos de carga so podem ser montados depois de
            // saber, pelo proprio CPUID, quais instrucoes esta CPU aceita.
            UsesFma = Facts.Avx2 && Facts.Fma && Facts.OsAvxEnabled;

            ExecutableCode burnPage = new ExecutableCode(16384);
            try
            {
                IntPtr burnAddress = burnPage.Add(UsesFma ? BuildFmaBurn() : BuildSseBurn());
                IntPtr writeAddress = IntPtr.Zero, readAddress = IntPtr.Zero;
                if (UsesFma)
                {
                    writeAddress = burnPage.Add(BuildStreamWrite());
                    readAddress = burnPage.Add(BuildStreamRead());
                }

                burnPage.MakeExecutable();

                _burn = (BurnFn)Marshal.GetDelegateForFunctionPointer(burnAddress, typeof(BurnFn));
                if (UsesFma)
                {
                    _streamWrite = (StreamWriteFn)Marshal.GetDelegateForFunctionPointer(writeAddress, typeof(StreamWriteFn));
                    _streamRead = (StreamReadFn)Marshal.GetDelegateForFunctionPointer(readAddress, typeof(StreamReadFn));
                }
            }
            catch
            {
                burnPage.Dispose();
                throw;
            }

            _burnPage = burnPage;
        }

        private ExecutableCode _burnPage;

        // ---------- rotinas montadas ----------

        // void cpuid(uint leaf /*ECX*/, uint subleaf /*EDX*/, uint* out4 /*R8*/)
        private static byte[] BuildCpuId()
        {
            X64Assembler a = new X64Assembler();
            a.PushRbx();                                        // RBX e nao-volatil na ABI e CPUID o destroi
            a.MovR32R32(X64Assembler.RAX, X64Assembler.RCX);    // eax = leaf
            a.MovR32R32(X64Assembler.RCX, X64Assembler.RDX);    // ecx = subleaf
            a.Cpuid();
            a.MovMemR32(X64Assembler.R8, 0, X64Assembler.RAX);
            a.MovMemR32(X64Assembler.R8, 4, X64Assembler.RBX);
            a.MovMemR32(X64Assembler.R8, 8, X64Assembler.RCX);
            a.MovMemR32(X64Assembler.R8, 12, X64Assembler.RDX);
            a.PopRbx();
            a.Ret();
            return a.ToArray();
        }

        // ulong rdtsc()
        private static byte[] BuildRdtsc()
        {
            X64Assembler a = new X64Assembler();
            a.Lfence();                                          // impede que a leitura suba na fila de execucao
            a.Rdtsc();
            a.ShlR64Imm(X64Assembler.RDX, 32);
            a.OrR64(X64Assembler.RAX, X64Assembler.RDX);
            a.Ret();
            return a.ToArray();
        }

        // ulong xgetbv(uint index /*ECX*/)
        private static byte[] BuildXgetbv()
        {
            X64Assembler a = new X64Assembler();
            a.Xgetbv();
            a.ShlR64Imm(X64Assembler.RDX, 32);
            a.OrR64(X64Assembler.RAX, X64Assembler.RDX);
            a.Ret();
            return a.ToArray();
        }

        // Salva/restaura XMM6-XMM15, que a ABI x64 obriga a preservar.
        private const int SavedXmmBytes = 0xA0;

        private static void SaveXmm(X64Assembler a)
        {
            a.SubR64Imm(X64Assembler.RSP, SavedXmmBytes);
            for (int i = 6; i <= 15; i++)
                a.MovupsStore(X64Assembler.RSP, (i - 6) * 16, i);
        }

        private static void RestoreXmm(X64Assembler a)
        {
            for (int i = 6; i <= 15; i++)
                a.MovupsLoad(i, X64Assembler.RSP, (i - 6) * 16);
            a.AddR64Imm(X64Assembler.RSP, SavedXmmBytes);
        }

        // void burn(ulong blocks /*RCX*/, float* buffer /*RDX*/)
        //
        //   buffer[0..7]   = vetor de uns
        //   buffer[8..15]  = padrao somado a cada passo (1,2,...,8)
        //   buffer[16..]   = estado final dos 14 acumuladores
        //
        // Cada passo faz acc = 1.0*padrao + acc. Como o padrao e inteiro
        // pequeno e float de 32 bits e exato ate 2^24, o resultado final e
        // previsivel ao ultimo bit: qualquer divergencia e erro de calculo
        // real da CPU - instabilidade, overclock ou degradacao. E o mesmo
        // principio de verificacao que o Prime95 usa.
        private static byte[] BuildFmaBurn()
        {
            X64Assembler a = new X64Assembler();
            SaveXmm(a);

            a.VmovupsLoad(14, X64Assembler.RDX, 0);    // ymm14 = uns
            a.VmovupsLoad(15, X64Assembler.RDX, 32);   // ymm15 = padrao

            for (int i = 0; i < Accumulators; i++) a.VxorpsSelf(i);

            a.Label("outer");
            a.MovR32Imm(X64Assembler.R10, InnerSteps);

            a.Label("inner");
            for (int i = 0; i < Accumulators; i++) a.Vfmadd231ps(i, 14, 15);
            a.SubR32Imm(X64Assembler.R10, 1);
            a.Jnz("inner");

            a.SubR64Imm(X64Assembler.RCX, 1);
            a.Jnz("outer");

            for (int i = 0; i < Accumulators; i++)
                a.VmovupsStore(X64Assembler.RDX, 64 + (i * 32), i);

            a.Vzeroupper();                            // evita a penalidade de transicao AVX/SSE ao voltar
            RestoreXmm(a);
            a.Ret();
            return a.ToArray();
        }

        // Mesmo contrato, para CPU sem AVX2/FMA (anterior a 2013).
        //
        //   buffer[0..3]  = padrao (1,2,3,4)
        //   buffer[4..]   = estado final dos 14 acumuladores
        private static byte[] BuildSseBurn()
        {
            X64Assembler a = new X64Assembler();
            SaveXmm(a);

            a.MovupsLoad(15, X64Assembler.RDX, 0);
            for (int i = 0; i < Accumulators; i++) a.XorpsSelf(i);

            a.Label("outer");
            a.MovR32Imm(X64Assembler.R10, InnerSteps);

            a.Label("inner");
            for (int i = 0; i < Accumulators; i++) a.Addps(i, 15);
            a.SubR32Imm(X64Assembler.R10, 1);
            a.Jnz("inner");

            a.SubR64Imm(X64Assembler.RCX, 1);
            a.Jnz("outer");

            for (int i = 0; i < Accumulators; i++)
                a.MovupsStore(X64Assembler.RDX, 16 + (i * 16), i);

            RestoreXmm(a);
            a.Ret();
            return a.ToArray();
        }

        // void streamWrite(void* dst /*RCX*/, void* src /*RDX*/, ulong bytes /*R8*/)
        //
        // Usa vmovntdq (armazenamento nao-temporal): a escrita vai direto a
        // memoria sem passar pelo cache. Sem isso o teste mediria o cache L3
        // e reportaria "banda de memoria" dezenas de vezes maior que a real.
        //
        // O padrao e lido do source SO UMA VEZ, ANTES do laco - o laco
        // cronometrado so escreve, entao o numerador (bytes escritos, contado
        // por quem chama esta rotina) corresponde ao trafego real de escrita,
        // sem trafego de leitura adicional inflando o total.
        private static byte[] BuildStreamWrite()
        {
            X64Assembler a = new X64Assembler();
            for (int i = 0; i < 4; i++) a.VmovdqaLoad(i, X64Assembler.RDX, i * 32);

            a.Label("loop");
            for (int i = 0; i < 4; i++) a.Vmovntdq(X64Assembler.RCX, i * 32, i);
            a.AddR64Imm(X64Assembler.RCX, 128);
            a.SubR64Imm(X64Assembler.R8, 128);
            a.Jnz("loop");
            a.Sfence();                                // publica os armazenamentos nao-temporais
            a.Vzeroupper();
            a.Ret();
            return a.ToArray();
        }

        // void streamRead(void* src /*RCX*/, ulong bytes /*RDX*/)
        private static byte[] BuildStreamRead()
        {
            X64Assembler a = new X64Assembler();
            a.Label("loop");
            for (int i = 0; i < 4; i++) a.VmovdqaLoad(i, X64Assembler.RCX, i * 32);
            a.AddR64Imm(X64Assembler.RCX, 128);
            a.SubR64Imm(X64Assembler.RDX, 128);
            a.Jnz("loop");
            a.Vzeroupper();
            a.Ret();
            return a.ToArray();
        }

        // ---------- interface publica ----------

        public uint[] CpuId(uint leaf, uint subleaf)
        {
            uint[] result = new uint[4];
            IntPtr buffer = Marshal.AllocHGlobal(16);
            try
            {
                _cpuid(leaf, subleaf, buffer);
                for (int i = 0; i < 4; i++)
                    result[i] = unchecked((uint)Marshal.ReadInt32(buffer, i * 4));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
            return result;
        }

        public ulong ReadTsc()
        {
            return _tsc();
        }

        internal BurnFn BurnRoutine { get { return _burn; } }

        // As rotinas de maquina decrementam "bytes" em passos fixos de 128 e
        // nao tem nenhuma checagem de limite propria - um tamanho que nao
        // seja multiplo de 128, ou um ponteiro desalinhado (vmovdqa/vmovntdq
        // exigem alinhamento de 32 bytes), pode levar a acesso fora do buffer
        // ou a uma falha nao gerenciavel na fronteira nativa. Valida os dois
        // requisitos aqui, na fronteira gerenciada/nativa, para transformar
        // isso em um ArgumentException tratavel em vez de corromper memoria
        // do processo.
        private static void ValidateStreamArgs(IntPtr pointer, ulong bytes, string paramName)
        {
            if (bytes == 0 || bytes % 128 != 0)
                throw new ArgumentException("bytes precisa ser multiplo de 128 (e > 0), recebido " + bytes + ".", "bytes");
            if ((pointer.ToInt64() & 31L) != 0)
                throw new ArgumentException("ponteiro precisa estar alinhado em 32 bytes.", paramName);
        }

        public void StreamWrite(IntPtr destination, IntPtr source, ulong bytes)
        {
            ValidateStreamArgs(destination, bytes, "destination");
            ValidateStreamArgs(source, bytes, "source");
            _streamWrite(destination, source, bytes);
        }

        public void StreamRead(IntPtr source, ulong bytes)
        {
            ValidateStreamArgs(source, bytes, "source");
            _streamRead(source, bytes);
        }

        // ---------- decodificacao do CPUID ----------

        private CpuIdFacts ReadCpuIdFacts()
        {
            CpuIdFacts f = new CpuIdFacts();

            uint[] leaf0 = CpuId(0, 0);
            f.MaxLeaf = leaf0[0];
            f.Vendor = RegistersToText(leaf0[1], leaf0[3], leaf0[2]);

            // Precisa sobreviver ao escopo do "if (f.MaxLeaf >= 1)" abaixo
            // para ser reaproveitado na checagem de AVX-512F, la embaixo em
            // "f.MaxLeaf >= 7" - ver comentario la.
            ulong xcr0 = 0;
            bool osxsave = false;

            if (f.MaxLeaf >= 1)
            {
                uint[] leaf1 = CpuId(1, 0);
                uint version = leaf1[0];

                int stepping = (int)(version & 0xF);
                int baseModel = (int)((version >> 4) & 0xF);
                int baseFamily = (int)((version >> 8) & 0xF);
                int extendedModel = (int)((version >> 16) & 0xF);
                int extendedFamily = (int)((version >> 20) & 0xFF);

                // A decisao de somar a familia/modelo estendidos precisa ser
                // feita contra o BaseFamily ORIGINAL, guardado antes de
                // qualquer soma - somar primeiro e checar depois usaria o
                // valor ja modificado na comparacao, dando um resultado
                // errado especialmente sensivel em CPUs AMD Zen.
                int family = baseFamily == 0xF ? baseFamily + extendedFamily : baseFamily;
                int model = (baseFamily == 0x6 || baseFamily == 0xF) ? baseModel + (extendedModel << 4) : baseModel;

                f.Family = family;
                f.Model = model;
                f.Stepping = stepping;

                uint ecx = leaf1[2], edx = leaf1[3];
                f.Sse2 = Bit(edx, 26);
                f.Fma = Bit(ecx, 12);
                f.Aes = Bit(ecx, 25);
                f.Avx = Bit(ecx, 28);
                f.RdRand = Bit(ecx, 30);
                f.Hypervisor = Bit(ecx, 31);
                f.ThermalMonitor = Bit(edx, 29);

                // AVX so pode ser usado se o SISTEMA tambem salvar o estado
                // dos registradores de 256 bits na troca de contexto. Testar
                // apenas o bit da CPU e o erro classico: o processo morre com
                // instrucao ilegal em Windows com AVX desabilitado por
                // politica ou por hipervisor antigo.
                osxsave = Bit(ecx, 27);
                if (osxsave)
                {
                    try
                    {
                        xcr0 = _xgetbv(0);
                        f.OsAvxEnabled = (xcr0 & 0x6) == 0x6;
                    }
                    catch { f.OsAvxEnabled = false; osxsave = false; }
                }
            }

            if (f.MaxLeaf >= 6)
            {
                uint[] leaf6 = CpuId(6, 0);
                f.DigitalThermalSensor = Bit(leaf6[0], 0);
                f.TurboBoost = Bit(leaf6[0], 1);
                f.HardwareFeedback = Bit(leaf6[2], 0);
            }

            if (f.MaxLeaf >= 7)
            {
                uint[] leaf7 = CpuId(7, 0);
                f.Avx2 = Bit(leaf7[1], 5);

                // O bit de CPUID.7.EBX[16] so diz que o SILICIO suporta
                // AVX-512F - nao que o estado ZMM esta
                // realmente habilitado para uso. Sem OSXSAVE (CPUID.1.ECX[27])
                // e sem os bits 5,6,7 do XCR0 (opmask + ZMM_Hi256 + Hi16_ZMM)
                // ligados no registro que o proprio sistema operacional
                // configura, executar uma instrucao AVX-512 gera excecao de
                // instrucao invalida - exatamente como o AVX2 ja e tratado
                // via OsAvxEnabled um pouco acima. Em firmware que desabilita
                // AVX-512, por politica, ou sob hipervisor que nao expoe o
                // recurso ao guest, o bit de CPUID pode continuar ligado
                // mesmo assim; so o XCR0 revela o estado real habilitado.
                f.Avx512F = Bit(leaf7[1], 16) && osxsave && ((xcr0 & 0xE6) == 0xE6);
            }

            uint[] ext0 = CpuId(0x80000000, 0);
            f.MaxExtendedLeaf = ext0[0];

            if (f.MaxExtendedLeaf >= 0x80000004)
            {
                StringBuilder brand = new StringBuilder(48);
                for (uint leaf = 0x80000002; leaf <= 0x80000004; leaf++)
                {
                    uint[] r = CpuId(leaf, 0);
                    brand.Append(RegistersToText(r[0], r[1], r[2], r[3]));
                }
                f.BrandString = brand.ToString().Trim();
            }

            if (f.MaxExtendedLeaf >= 0x80000007)
                f.InvariantTsc = Bit(CpuId(0x80000007, 0)[3], 8);

            if (f.Hypervisor)
            {
                uint[] hv = CpuId(0x40000000, 0);
                string vendor = RegistersToText(hv[1], hv[2], hv[3]).Trim();
                f.HypervisorVendor = vendor.Length > 0 ? vendor : "nao identificado";
            }

            ReadCaches(f);
            return f;
        }

        // Topologia de cache. A folha 4 e da Intel; a AMD expoe o equivalente
        // na folha estendida 0x8000001D. Ambas usam o mesmo formato de campos.
        private void ReadCaches(CpuIdFacts f)
        {
            uint leaf;
            if (f.Vendor != null && f.Vendor.IndexOf("AMD", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                if (f.MaxExtendedLeaf < 0x8000001D) return;
                leaf = 0x8000001D;
            }
            else
            {
                if (f.MaxLeaf < 4) return;
                leaf = 4;
            }

            for (uint index = 0; index < 8; index++)
            {
                uint[] r = CpuId(leaf, index);
                int type = (int)(r[0] & 0x1F);
                if (type == 0) break;                  // fim da lista

                CacheDescriptor c = new CacheDescriptor();
                c.Level = (int)((r[0] >> 5) & 0x7);
                c.Kind = type == 1 ? "dados" : type == 2 ? "instrucao" : "unificado";

                int lineBytes = (int)((r[1] & 0xFFF) + 1);
                int partitions = (int)(((r[1] >> 12) & 0x3FF) + 1);
                int ways = (int)(((r[1] >> 22) & 0x3FF) + 1);
                int sets = (int)(r[2] + 1);

                c.LineBytes = lineBytes;
                c.Ways = ways;
                c.SizeKb = (int)(((long)lineBytes * partitions * ways * sets) / 1024);
                f.Caches.Add(c);
            }
        }

        private static bool Bit(uint value, int index)
        {
            return ((value >> index) & 1) != 0;
        }

        private static string RegistersToText(params uint[] registers)
        {
            byte[] bytes = new byte[registers.Length * 4];
            for (int i = 0; i < registers.Length; i++)
            {
                bytes[i * 4 + 0] = (byte)(registers[i] & 0xFF);
                bytes[i * 4 + 1] = (byte)((registers[i] >> 8) & 0xFF);
                bytes[i * 4 + 2] = (byte)((registers[i] >> 16) & 0xFF);
                bytes[i * 4 + 3] = (byte)((registers[i] >> 24) & 0xFF);
            }

            string text = Encoding.ASCII.GetString(bytes);
            int nul = text.IndexOf('\0');
            if (nul >= 0) text = text.Substring(0, nul);
            return text;
        }

        public void Dispose()
        {
            _cpuid = null;
            _tsc = null;
            _xgetbv = null;
            _burn = null;
            _streamWrite = null;
            _streamRead = null;

            if (_burnPage != null) { _burnPage.Dispose(); _burnPage = null; }
            if (_page != null) { _page.Dispose(); _page = null; }
        }
    }

    // Unidade de carga de UMA thread: buffer proprio, alinhado, para que duas
    // threads nunca disputem a mesma linha de cache (false sharing arruinaria
    // tanto a medida quanto a carga).
    public sealed class BurnUnit : IDisposable
    {
        private readonly LowLevelEngine _engine;
        private readonly int _lanes;
        private IntPtr _raw;
        private IntPtr _buffer;

        public long TotalSteps { get; private set; }
        public long ArithmeticErrors { get; private set; }
        public string FirstErrorDetail { get; private set; }

        public BurnUnit(LowLevelEngine engine)
        {
            _engine = engine;
            _lanes = engine.BurnLanes;

            int size = engine.BurnBufferBytes;
            _raw = Marshal.AllocHGlobal(size + 64);
            long aligned = (_raw.ToInt64() + 63) & ~63L;
            _buffer = new IntPtr(aligned);

            for (int i = 0; i < size / 4; i++) Marshal.WriteInt32(_buffer, i * 4, 0);

            if (engine.UsesFma)
            {
                for (int lane = 0; lane < 8; lane++)
                {
                    WriteFloat(0 + lane * 4, 1.0f);
                    WriteFloat(32 + lane * 4, lane + 1);
                }
            }
            else
            {
                for (int lane = 0; lane < 4; lane++)
                    WriteFloat(lane * 4, lane + 1);
            }
        }

        private void WriteFloat(int offset, float value)
        {
            Marshal.WriteInt32(_buffer, offset, BitConverter.ToInt32(BitConverter.GetBytes(value), 0));
        }

        private float ReadFloat(int offset)
        {
            return BitConverter.ToSingle(BitConverter.GetBytes(Marshal.ReadInt32(_buffer, offset)), 0);
        }

        // Roda um lote e confere o resultado contra o valor exato esperado.
        // Devolve o numero de operacoes de ponto flutuante executadas.
        public long RunBlock(int blocks)
        {
            if (blocks < 1) blocks = 1;
            if (blocks > LowLevelEngine.MaxBlocksPerCall) blocks = LowLevelEngine.MaxBlocksPerCall;

            _engine.BurnRoutine((ulong)blocks, _buffer);

            long steps = (long)blocks * LowLevelEngine.InnerSteps;
            TotalSteps += steps;
            Verify(steps);

            // Cada passo e uma multiplicacao e uma soma por faixa (FMA), ou
            // apenas uma soma no caminho SSE.
            long perStep = _engine.UsesFma ? 2 : 1;
            return steps * LowLevelEngine.Accumulators * _lanes * perStep;
        }

        private void Verify(long steps)
        {
            int resultBase = _engine.UsesFma ? 64 : 16;
            int stride = _engine.UsesFma ? 32 : 16;

            for (int acc = 0; acc < LowLevelEngine.Accumulators; acc++)
            {
                for (int lane = 0; lane < _lanes; lane++)
                {
                    float expected = (float)steps * (lane + 1);
                    float actual = ReadFloat(resultBase + acc * stride + lane * 4);
                    if (actual == expected) continue;

                    ArithmeticErrors++;
                    if (FirstErrorDetail == null)
                    {
                        FirstErrorDetail = "acumulador " + acc + ", faixa " + lane +
                            ": esperado " + expected.ToString("R", CultureInfo.InvariantCulture) +
                            ", obtido " + actual.ToString("R", CultureInfo.InvariantCulture);
                    }
                }
            }
        }

        public void Dispose()
        {
            if (_raw == IntPtr.Zero) return;
            Marshal.FreeHGlobal(_raw);
            _raw = IntPtr.Zero;
            _buffer = IntPtr.Zero;
        }
    }

    // Controles de sistema usados durante a carga.
    public static class ThreadControl
    {
        private const uint ES_CONTINUOUS = 0x80000000, ES_SYSTEM_REQUIRED = 0x00000001, ES_DISPLAY_REQUIRED = 0x00000002;

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll")]
        private static extern UIntPtr SetThreadAffinityMask(IntPtr thread, UIntPtr mask);

        [DllImport("kernel32.dll")]
        private static extern uint SetThreadExecutionState(uint flags);

        // Prende a thread atual a um processador logico. Sem isso o Windows
        // migra as threads entre nucleos e um nucleo defeituoso pode nunca ser
        // exercitado - ou o erro aparece sem que se saiba onde.
        public static bool PinToProcessor(int logicalIndex)
        {
            if (logicalIndex < 0 || logicalIndex >= 64) return false;
            try
            {
                UIntPtr mask = new UIntPtr(1UL << logicalIndex);
                return SetThreadAffinityMask(GetCurrentThread(), mask) != UIntPtr.Zero;
            }
            catch { return false; }
        }

        // Impede que a maquina durma no meio de um teste longo.
        public static void KeepAwake(bool keep)
        {
            try
            {
                SetThreadExecutionState(keep
                    ? ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED
                    : ES_CONTINUOUS);
            }
            catch { }
        }
    }
}
