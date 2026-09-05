using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PcDiag.Sources
{
    // ================================================================
    //  Montador x86-64 minimo.
    //
    //  Por que montar opcode a opcode em vez de escrever .asm: o Windows nao
    //  traz montador (ml64.exe so vem com o Visual Studio) e este projeto e
    //  compilado apenas com o csc.exe que ja existe na maquina. Emitir os
    //  bytes em tempo de execucao e a unica forma de usar instrucao real -
    //  CPUID, RDTSC, FMA de 256 bits - sem exigir que o tecnico instale nada
    //  no computador do cliente.
    //
    //  O codigo emitido segue a ABI x64 da Microsoft: argumentos inteiros em
    //  RCX/RDX/R8/R9, retorno em RAX, e RBX/RBP/RSI/RDI/R12-R15 e XMM6-XMM15
    //  sao responsabilidade de quem os usa preservar.
    // ================================================================
    internal sealed class X64Assembler
    {
        public const int RAX = 0, RCX = 1, RDX = 2, RBX = 3, RSP = 4, RBP = 5, RSI = 6, RDI = 7;
        public const int R8 = 8, R9 = 9, R10 = 10, R11 = 11, R12 = 12, R13 = 13, R14 = 14, R15 = 15;

        // mm seleciona a tabela de opcode (0F, 0F38); pp e o prefixo
        // obrigatorio que a instrucao herda do mundo SSE.
        private const int MM_0F = 1, MM_0F38 = 2;
        private const int PP_NONE = 0, PP_66 = 1;

        // Instrucao VEX de dois operandos nao tem terceiro registrador, e o
        // campo vvvv e RESERVADO: a CPU exige que ele venha gravado como
        // 1111. Como o campo e armazenado invertido, um registrador real N
        // vira ~N, mas o "nao usado" nao e o registrador 15 - e o literal
        // 1111. Gravar ~15 = 0000 aqui rende #UD (instrucao ilegal).
        private const int VvvvUnused = -1;

        private readonly List<byte> _code = new List<byte>(2048);
        private readonly Dictionary<string, int> _labels = new Dictionary<string, int>(StringComparer.Ordinal);
        private readonly List<string> _fixupLabel = new List<string>();
        private readonly List<int> _fixupSite = new List<int>();

        public int Position { get { return _code.Count; } }

        // ---------- primitivas ----------

        public void Emit(params byte[] bytes)
        {
            for (int i = 0; i < bytes.Length; i++) _code.Add(bytes[i]);
        }

        public void Imm32(int value)
        {
            _code.Add((byte)(value & 0xFF));
            _code.Add((byte)((value >> 8) & 0xFF));
            _code.Add((byte)((value >> 16) & 0xFF));
            _code.Add((byte)((value >> 24) & 0xFF));
        }

        private void Rex(bool w, int reg, int index, int rmBase)
        {
            int r = (reg >> 3) & 1;
            int x = (index >> 3) & 1;
            int b = (rmBase >> 3) & 1;
            if (w || r != 0 || x != 0 || b != 0)
                _code.Add((byte)(0x40 | (w ? 8 : 0) | (r << 2) | (x << 1) | b));
        }

        private void ModRmReg(int reg, int rm)
        {
            _code.Add((byte)(0xC0 | ((reg & 7) << 3) | (rm & 7)));
        }

        // Endereco [base + disp]. Trata os dois casos especiais do x86-64:
        // rm=100 (RSP/R12) exige byte SIB, e rm=101 (RBP/R13) com mod=00
        // significaria endereco relativo a RIP - por isso disp8 e forcado.
        private void ModRmMem(int reg, int baseReg, int disp)
        {
            int rm = baseReg & 7;
            int mod;
            if (disp == 0 && rm != 5) mod = 0;
            else if (disp >= -128 && disp <= 127) mod = 1;
            else mod = 2;

            _code.Add((byte)((mod << 6) | ((reg & 7) << 3) | (rm == 4 ? 4 : rm)));
            if (rm == 4) _code.Add(0x24); // SIB: base=RSP/R12, sem indice

            if (mod == 1) _code.Add((byte)(sbyte)disp);
            else if (mod == 2) Imm32(disp);
        }

        private void Vex(int mm, int pp, bool w, bool l256, int reg, int vvvv, int rmBase)
        {
            int r = (reg >> 3) & 1;
            int b = (rmBase >> 3) & 1;
            int storedVvvv = vvvv < 0 ? 0xF : (~vvvv & 0xF);
            _code.Add(0xC4);
            _code.Add((byte)((((r ^ 1) & 1) << 7) | (1 << 6) | (((b ^ 1) & 1) << 5) | (mm & 0x1F)));
            _code.Add((byte)(((w ? 1 : 0) << 7) | (storedVvvv << 3) | ((l256 ? 1 : 0) << 2) | (pp & 3)));
        }

        private void VexRR(byte op, int mm, int pp, bool l256, int reg, int vvvv, int rm)
        {
            Vex(mm, pp, false, l256, reg, vvvv, rm);
            _code.Add(op);
            ModRmReg(reg, rm);
        }

        private void VexRM(byte op, int mm, int pp, bool l256, int reg, int vvvv, int baseReg, int disp)
        {
            Vex(mm, pp, false, l256, reg, vvvv, baseReg);
            _code.Add(op);
            ModRmMem(reg, baseReg, disp);
        }

        // ---------- rotulos ----------

        public void Label(string name)
        {
            _labels[name] = _code.Count;
        }

        public void Jnz(string label)
        {
            _code.Add(0x75);
            _fixupLabel.Add(label);
            _fixupSite.Add(_code.Count);
            _code.Add(0x00);
        }

        // ---------- inteiro ----------

        public void Ret() { _code.Add(0xC3); }
        public void PushRbx() { _code.Add(0x53); }
        public void PopRbx() { _code.Add(0x5B); }
        public void Cpuid() { Emit(0x0F, 0xA2); }
        public void Rdtsc() { Emit(0x0F, 0x31); }
        public void Lfence() { Emit(0x0F, 0xAE, 0xE8); }
        public void Sfence() { Emit(0x0F, 0xAE, 0xF8); }
        public void Xgetbv() { Emit(0x0F, 0x01, 0xD0); }

        public void MovR32R32(int dst, int src)
        {
            Rex(false, dst, 0, src);
            _code.Add(0x8B);
            ModRmReg(dst, src);
        }

        public void MovR32Imm(int dst, int value)
        {
            Rex(false, 0, 0, dst);
            _code.Add((byte)(0xB8 + (dst & 7)));
            Imm32(value);
        }

        public void XorR32Self(int reg)
        {
            Rex(false, reg, 0, reg);
            _code.Add(0x33);
            ModRmReg(reg, reg);
        }

        // mov [base+disp], reg32
        public void MovMemR32(int baseReg, int disp, int src)
        {
            Rex(false, src, 0, baseReg);
            _code.Add(0x89);
            ModRmMem(src, baseReg, disp);
        }

        public void ShlR64Imm(int reg, byte bits)
        {
            Rex(true, 0, 0, reg);
            _code.Add(0xC1);
            ModRmReg(4, reg);
            _code.Add(bits);
        }

        public void OrR64(int dst, int src)
        {
            Rex(true, dst, 0, src);
            _code.Add(0x0B);
            ModRmReg(dst, src);
        }

        public void AddR64Imm(int reg, int value) { AluR64Imm(0, reg, value); }
        public void SubR64Imm(int reg, int value) { AluR64Imm(5, reg, value); }

        private void AluR64Imm(int ext, int reg, int value)
        {
            Rex(true, 0, 0, reg);
            if (value >= -128 && value <= 127)
            {
                _code.Add(0x83);
                ModRmReg(ext, reg);
                _code.Add((byte)(sbyte)value);
            }
            else
            {
                _code.Add(0x81);
                ModRmReg(ext, reg);
                Imm32(value);
            }
        }

        public void SubR32Imm(int reg, int value)
        {
            Rex(false, 0, 0, reg);
            if (value >= -128 && value <= 127)
            {
                _code.Add(0x83);
                ModRmReg(5, reg);
                _code.Add((byte)(sbyte)value);
            }
            else
            {
                _code.Add(0x81);
                ModRmReg(5, reg);
                Imm32(value);
            }
        }

        // ---------- SSE (presente em todo x64) ----------

        public void MovupsLoad(int xmm, int baseReg, int disp)
        {
            Rex(false, xmm, 0, baseReg);
            Emit(0x0F, 0x10);
            ModRmMem(xmm, baseReg, disp);
        }

        public void MovupsStore(int baseReg, int disp, int xmm)
        {
            Rex(false, xmm, 0, baseReg);
            Emit(0x0F, 0x11);
            ModRmMem(xmm, baseReg, disp);
        }

        public void Addps(int dst, int src)
        {
            Rex(false, dst, 0, src);
            Emit(0x0F, 0x58);
            ModRmReg(dst, src);
        }

        public void XorpsSelf(int xmm)
        {
            Rex(false, xmm, 0, xmm);
            Emit(0x0F, 0x57);
            ModRmReg(xmm, xmm);
        }

        // ---------- AVX / AVX2 / FMA ----------

        public void VmovupsLoad(int ymm, int baseReg, int disp)
        {
            VexRM(0x10, MM_0F, PP_NONE, true, ymm, VvvvUnused, baseReg, disp);
        }

        public void VmovupsStore(int baseReg, int disp, int ymm)
        {
            VexRM(0x11, MM_0F, PP_NONE, true, ymm, VvvvUnused, baseReg, disp);
        }

        public void VmovdqaLoad(int ymm, int baseReg, int disp)
        {
            VexRM(0x6F, MM_0F, PP_66, true, ymm, VvvvUnused, baseReg, disp);
        }

        public void Vmovntdq(int baseReg, int disp, int ymm)
        {
            VexRM(0xE7, MM_0F, PP_66, true, ymm, VvvvUnused, baseReg, disp);
        }

        public void VxorpsSelf(int ymm)
        {
            VexRR(0x57, MM_0F, PP_NONE, true, ymm, ymm, ymm);
        }

        // dst = src1 * src2 + dst
        public void Vfmadd231ps(int dst, int src1, int src2)
        {
            VexRR(0xB8, MM_0F38, PP_66, true, dst, src1, src2);
        }

        public void Vzeroupper() { Emit(0xC5, 0xF8, 0x77); }

        // ---------- finalizacao ----------

        public byte[] ToArray()
        {
            for (int i = 0; i < _fixupSite.Count; i++)
            {
                int target;
                if (!_labels.TryGetValue(_fixupLabel[i], out target))
                    throw new InvalidOperationException("Rotulo nao definido: " + _fixupLabel[i]);

                int rel = target - (_fixupSite[i] + 1);
                if (rel < -128 || rel > 127)
                    throw new InvalidOperationException("Salto curto fora de alcance (" + rel + " bytes) para " + _fixupLabel[i] + ".");

                _code[_fixupSite[i]] = (byte)(sbyte)rel;
            }
            return _code.ToArray();
        }
    }

    // ================================================================
    //  Pagina de codigo executavel.
    //
    //  Alocada como leitura/escrita, preenchida, e so entao promovida a
    //  leitura/execucao (W^X). Uma pagina gravavel E executavel ao mesmo
    //  tempo e assinatura classica de malware: varios antivirus e a politica
    //  Arbitrary Code Guard bloqueiam. Separar as fases faz o codigo passar
    //  onde RWX seria barrado.
    // ================================================================
    internal sealed class ExecutableCode : IDisposable
    {
        private const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_RELEASE = 0x8000;
        private const uint PAGE_READWRITE = 0x04, PAGE_EXECUTE_READ = 0x20;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocationType, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualProtect(IntPtr address, UIntPtr size, uint newProtect, out uint oldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualFree(IntPtr address, UIntPtr size, uint freeType);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FlushInstructionCache(IntPtr process, IntPtr baseAddress, UIntPtr size);

        private IntPtr _block;
        private readonly int _size;
        private int _used;

        public ExecutableCode(int size)
        {
            _size = size;
            _block = VirtualAlloc(IntPtr.Zero, new UIntPtr((uint)size), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (_block == IntPtr.Zero)
                throw new InvalidOperationException("VirtualAlloc falhou (erro " + Marshal.GetLastWin32Error() + ").");
        }

        public IntPtr Add(byte[] code)
        {
            // Cada rotina comeca em endereco multiplo de 16: alinhar a entrada
            // evita que a busca de instrucao atravesse linha de cache no meio
            // do laco quente.
            int offset = (_used + 15) & ~15;
            if (offset + code.Length > _size)
                throw new InvalidOperationException("Pagina de codigo cheia.");

            IntPtr address = new IntPtr(_block.ToInt64() + offset);
            Marshal.Copy(code, 0, address, code.Length);
            _used = offset + code.Length;
            return address;
        }

        public void MakeExecutable()
        {
            uint previous;
            if (!VirtualProtect(_block, new UIntPtr((uint)_size), PAGE_EXECUTE_READ, out previous))
                throw new InvalidOperationException("VirtualProtect para executavel falhou (erro " +
                    Marshal.GetLastWin32Error() + "); politica de seguranca pode estar bloqueando codigo dinamico.");

            FlushInstructionCache(GetCurrentProcess(), _block, new UIntPtr((uint)_size));
        }

        public void Dispose()
        {
            if (_block == IntPtr.Zero) return;
            VirtualFree(_block, UIntPtr.Zero, MEM_RELEASE);
            _block = IntPtr.Zero;
        }
    }
}
