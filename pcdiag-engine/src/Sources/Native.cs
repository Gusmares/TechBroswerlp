using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PcDiag.Sources
{
    // Dispositivo enumerado direto pela SetupAPI/CfgMgr32.
    //
    // Por que nao usar so Win32_PnPEntity: a WMI lista apenas dispositivos
    // PRESENTES. Dispositivo oculto/fantasma (aquele que aparece no
    // Gerenciador de Dispositivos com "Mostrar dispositivos ocultos") nao
    // aparece na WMI - e e exatamente onde moram restos de driver de hardware
    // trocado, que explicam conflito de recurso e Code 12.
    public sealed class NativeDevice
    {
        public string InstanceId { get; set; }
        public string Description { get; set; }
        public string FriendlyName { get; set; }
        public string Class { get; set; }
        public string Manufacturer { get; set; }
        public string Service { get; set; }
        public string HardwareIds { get; set; }
        public string CompatibleIds { get; set; }
        public string LocationInfo { get; set; }
        public string Enumerator { get; set; }
        public uint Status { get; set; }
        public uint ProblemCode { get; set; }
        public bool HasProblem { get; set; }
        public bool IsPresent { get; set; }

        // Uma fracao relevante dos dispositivos enumerados com
        // DIGCF_ALLCLASSES tem CM_Get_DevNode_Status devolvendo um erro
        // diferente de sucesso (tipicamente CR_NO_SUCH_DEVINST) mesmo com o
        // dispositivo estando PRESENTE segundo SetupDiEnumDeviceInfo -
        // "consulta de status falhou" e "sem problema nenhum" ficariam
        // indistinguiveis (os dois cairiam em ProblemCode=0), entao o
        // dispositivo pareceria silenciosamente "sem problema" quando na
        // verdade a ferramenta nao sabe o estado real. Esta flag deixa essa
        // diferenca visivel para quem consumir NativeDevice.
        public bool StatusQueried { get; set; }
    }

    public static class Native
    {
        // ---------- Seguranca do carregamento de DLL ----------
        // "cfgmgr32.dll" NAO esta na lista KnownDLLs do Windows (verificado
        // no registro: HKLM\SYSTEM\CurrentControlSet\Control\Session
        // Manager\KnownDLLs tem setupapi e kernel32, mas nao cfgmgr32). Um
        // [DllImport("cfgmgr32.dll")] comum e resolvido primeiro pela pasta
        // do executavel, o que abre espaco para uma DLL indevida ser
        // carregada dentro de um processo elevado.
        //
        // Pre-carregar a DLL certa por caminho absoluto antes do primeiro
        // [DllImport] nao basta: o resolvedor de P/Invoke do .NET Framework
        // para um DllImport por nome curto nao reaproveita de forma
        // confiavel um modulo ja presente no processo - nenhuma variante de
        // "carregar a DLL certa antes" impede o CLR de pesquisar a pasta do
        // executavel por conta propria quando o DllImport usa nome curto.
        //
        // O QUE REALMENTE FUNCIONA: nunca deixar o CLR resolver o nome. A
        // DLL e carregada explicitamente por CAMINHO ABSOLUTO
        // (%SystemRoot%\System32\cfgmgr32.dll, sem nenhuma pesquisa
        // envolvida) e a funcao e chamada por PONTEIRO (GetProcAddress +
        // delegate), nunca por um [DllImport("cfgmgr32.dll")] que o CLR
        // possa re-resolver do jeito errado. Ver CmGetDevNodeStatus() e o
        // uso em vez de um DllImport direto.
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibraryEx(string lpLibFileName, IntPtr hFile, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetDefaultDllDirectories(uint DirectoryFlags);

        private const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;

        // Chamado uma unica vez, o mais cedo possivel em Main. Mantido como
        // defesa em profundidade (fecha a hipotese para qualquer DllImport
        // futuro que use LoadLibraryEx com flags padrao), mesmo nao sendo
        // suficiente sozinho para o caso do cfgmgr32.dll de hoje.
        public static void HardenDllSearchPath()
        {
            try { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32); }
            catch { /* API ausente em Windows anterior ao 8 (KB2533623) - degrada sem quebrar a ferramenta */ }
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate int CMGetDevNodeStatusDelegate(out uint pulStatus, out uint pulProblemNumber, uint dnDevInst, uint ulFlags);

        private static CMGetDevNodeStatusDelegate _cmGetDevNodeStatus;
        private static bool _cmGetDevNodeStatusResolved;

        // Chamado sob demanda (nao em HardenDllSearchPath) porque so
        // DeviceCollector precisa desta funcao - as demais 40+ chamadas do
        // projeto continuam DllImport comum, protegidas por serem todas
        // contra DLLs em KnownDLLs (kernel32, ntdll) ou pela mitigacao geral
        // acima (setupapi).
        private static CMGetDevNodeStatusDelegate ResolveCmGetDevNodeStatus()
        {
            if (_cmGetDevNodeStatusResolved) return _cmGetDevNodeStatus;
            _cmGetDevNodeStatusResolved = true;
            try
            {
                string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string fullPath = Path.Combine(system32, "cfgmgr32.dll");
                IntPtr module = LoadLibraryEx(fullPath, IntPtr.Zero, 0);
                if (module == IntPtr.Zero) return null;

                IntPtr proc = GetProcAddress(module, "CM_Get_DevNode_Status");
                if (proc == IntPtr.Zero) return null;

                _cmGetDevNodeStatus = (CMGetDevNodeStatusDelegate)Marshal.GetDelegateForFunctionPointer(proc, typeof(CMGetDevNodeStatusDelegate));
            }
            catch { /* fica null - o chamador trata como CR_FAILURE, igual a uma excecao de DllImport de antes */ }
            return _cmGetDevNodeStatus;
        }

        // Substitui o antigo "[DllImport("cfgmgr32.dll")] CM_Get_DevNode_Status"
        // direto - ver a nota longa acima sobre por que o DllImport direto
        // nao e seguro para esta DLL especifica.
        private static int CmGetDevNodeStatus(out uint pulStatus, out uint pulProblemNumber, uint dnDevInst, uint ulFlags)
        {
            CMGetDevNodeStatusDelegate fn = ResolveCmGetDevNodeStatus();
            if (fn == null)
            {
                pulStatus = 0;
                pulProblemNumber = 0;
                throw new EntryPointNotFoundException("CM_Get_DevNode_Status indisponivel em cfgmgr32.dll.");
            }
            return fn(out pulStatus, out pulProblemNumber, dnDevInst, ulFlags);
        }

        // ---------- Firmware (UEFI x Legacy) ----------
        // Fonte autoritativa. O coletor antigo fazia parsing da SAIDA DE TEXTO
        // do bcdedit, que depende do idioma do Windows e de privilegio.

        public enum FirmwareType
        {
            Unknown = 0,
            Bios = 1,
            Uefi = 2,
            Max = 3
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFirmwareType(out uint FirmwareType);

        public static FirmwareType? GetFirmware()
        {
            try
            {
                uint t;
                if (!GetFirmwareType(out t)) return null;
                if (t > 3) return FirmwareType.Unknown;
                return (FirmwareType)t;
            }
            catch (EntryPointNotFoundException) { return null; }
            catch (DllNotFoundException) { return null; }
        }

        // ---------- Versao real do Windows ----------
        //
        // Environment.OSVersion (e GetVersionEx) MENTEM: sem manifesto de
        // compatibilidade o Windows devolve 6.2 (Windows 8) para qualquer
        // sistema mais novo. Isso foi detectado rodando a propria ferramenta:
        // um Windows 10 build 19044 era reportado como "anterior ao Windows 10"
        // e a execucao abortava.
        //
        // RtlGetVersion e a unica API que devolve a versao verdadeira sem
        // depender de manifesto.

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RTL_OSVERSIONINFOW
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
        }

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        private static extern int RtlGetVersion(ref RTL_OSVERSIONINFOW versionInformation);

        public static Version GetRealOsVersion()
        {
            try
            {
                RTL_OSVERSIONINFOW info = new RTL_OSVERSIONINFOW();
                info.dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(RTL_OSVERSIONINFOW));

                if (RtlGetVersion(ref info) != 0) return null;
                if (info.dwMajorVersion == 0) return null;

                return new Version((int)info.dwMajorVersion, (int)info.dwMinorVersion, (int)info.dwBuildNumber, 0);
            }
            catch
            {
                return null;
            }
        }

        // ---------- Memoria ----------

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        public sealed class MemoryStatus
        {
            public uint LoadPercent { get; set; }
            public ulong TotalPhysicalBytes { get; set; }
            public ulong AvailablePhysicalBytes { get; set; }
            public ulong TotalCommitBytes { get; set; }
            public ulong AvailableCommitBytes { get; set; }
        }

        public static MemoryStatus GetMemoryStatus()
        {
            try
            {
                MEMORYSTATUSEX m = new MEMORYSTATUSEX();
                m.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
                if (!GlobalMemoryStatusEx(ref m)) return null;

                MemoryStatus s = new MemoryStatus();
                s.LoadPercent = m.dwMemoryLoad;
                s.TotalPhysicalBytes = m.ullTotalPhys;
                s.AvailablePhysicalBytes = m.ullAvailPhys;
                s.TotalCommitBytes = m.ullTotalPageFile;
                s.AvailableCommitBytes = m.ullAvailPageFile;
                return s;
            }
            catch { return null; }
        }

        // Memoria FISICAMENTE INSTALADA, lida do SMBIOS pelo kernel. E a
        // contraparte independente para o "utilizavel" do GlobalMemoryStatusEx:
        // a diferenca entre os dois e a memoria reservada para hardware, que o
        // briefing pede que seja explicada com contexto (item 7).
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetPhysicallyInstalledSystemMemory(out long TotalMemoryInKilobytes);

        public static ulong? GetInstalledMemoryBytes()
        {
            try
            {
                long kb;
                if (!GetPhysicallyInstalledSystemMemory(out kb)) return null;
                if (kb <= 0) return null;
                return (ulong)kb * 1024UL;
            }
            catch (EntryPointNotFoundException) { return null; }
            catch { return null; }
        }

        // ---------- Processador ----------

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_INFO
        {
            public ushort wProcessorArchitecture;
            public ushort wReserved;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public IntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort wProcessorLevel;
            public ushort wProcessorRevision;
        }

        [DllImport("kernel32.dll")]
        private static extern void GetNativeSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        public sealed class SystemInfoLite
        {
            public string Architecture { get; set; }
            public int LogicalProcessors { get; set; }
            public int ProcessorLevel { get; set; }
            public int ProcessorRevision { get; set; }
        }

        public static SystemInfoLite GetSystemInfoNative()
        {
            try
            {
                SYSTEM_INFO si = new SYSTEM_INFO();
                GetNativeSystemInfo(ref si);

                SystemInfoLite r = new SystemInfoLite();
                switch (si.wProcessorArchitecture)
                {
                    case 9: r.Architecture = "x64"; break;
                    case 5: r.Architecture = "ARM"; break;
                    case 12: r.Architecture = "ARM64"; break;
                    case 6: r.Architecture = "IA64"; break;
                    case 0: r.Architecture = "x86"; break;
                    default: r.Architecture = "Desconhecida(" + si.wProcessorArchitecture + ")"; break;
                }
                r.LogicalProcessors = (int)si.dwNumberOfProcessors;
                r.ProcessorLevel = si.wProcessorLevel;
                r.ProcessorRevision = si.wProcessorRevision;
                return r;
            }
            catch { return null; }
        }

        // ---------- SetupAPI / CfgMgr32: arvore de dispositivos ----------

        private const uint DIGCF_PRESENT = 0x00000002;
        private const uint DIGCF_ALLCLASSES = 0x00000004;

        private const uint SPDRP_DEVICEDESC = 0x00000000;
        private const uint SPDRP_HARDWAREID = 0x00000001;
        private const uint SPDRP_COMPATIBLEIDS = 0x00000002;
        private const uint SPDRP_SERVICE = 0x00000004;
        private const uint SPDRP_CLASS = 0x00000007;
        private const uint SPDRP_MFG = 0x0000000B;
        private const uint SPDRP_FRIENDLYNAME = 0x0000000C;
        private const uint SPDRP_LOCATION_INFORMATION = 0x0000000D;
        private const uint SPDRP_ENUMERATOR_NAME = 0x00000016;

        private const uint DN_HAS_PROBLEM = 0x00000400;

        private const int CR_SUCCESS = 0;
        private const int ERROR_NO_MORE_ITEMS = 259;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        // Limites de seguranca para o laco de SetupDiEnumDeviceInfo, que
        // depende de uma unica condicao de parada (ERROR_NO_MORE_ITEMS=259).
        // Se o provedor nunca devolver 259 (driver
        // de classe corrompido, bug de terceiro no provedor, ACL negada em
        // todo indice), o "continue" avanca para o proximo indice e o laco
        // varre ate uint.MaxValue sem nunca sair - trava a ferramenta
        // indefinidamente na maquina do cliente, sem timeout e sem log (nao
        // ha watchdog nenhum sobre este laco). Um teto absoluto de iteracoes
        // E um contador de falhas consecutivas (erro diferente de 259) cobrem
        // os dois jeitos de nunca terminar.
        private const uint MaxEnumerateIterations = 100000;
        private const int MaxConsecutiveNonExpectedFailures = 50;

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public uint cbSize;
            public Guid ClassGuid;
            public uint DevInst;
            public IntPtr Reserved;
        }

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevsW(IntPtr ClassGuid, string Enumerator, IntPtr hwndParent, uint Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiEnumDeviceInfo(IntPtr DeviceInfoSet, uint MemberIndex, ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiGetDeviceRegistryPropertyW(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            uint Property,
            out uint PropertyRegDataType,
            byte[] PropertyBuffer,
            uint PropertyBufferSize,
            out uint RequiredSize);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiGetDeviceInstanceIdW(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            StringBuilder DeviceInstanceId,
            uint DeviceInstanceIdSize,
            out uint RequiredSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        public static IList<NativeDevice> EnumerateDevices(bool includeNonPresent)
        {
            List<NativeDevice> devices = new List<NativeDevice>();

            uint flags = DIGCF_ALLCLASSES;
            if (!includeNonPresent) flags |= DIGCF_PRESENT;

            IntPtr set = SetupDiGetClassDevsW(IntPtr.Zero, null, IntPtr.Zero, flags);
            if (set == IntPtr.Zero || set == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetupDiGetClassDevs falhou.");

            try
            {
                SP_DEVINFO_DATA data = new SP_DEVINFO_DATA();
                data.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));

                int consecutiveFailures = 0;
                for (uint i = 0; i < MaxEnumerateIterations; i++)
                {
                    if (!SetupDiEnumDeviceInfo(set, i, ref data))
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == ERROR_NO_MORE_ITEMS) break;

                        // Uma entrada ruim isolada
                        // nao pode abortar a enumeracao inteira, mas uma
                        // sequencia longa de falhas que nunca chega a 259 e
                        // sinal de que o provedor nao vai se recuperar -
                        // aborta e registra em vez de rodar ate o teto de
                        // iteracoes em silencio.
                        consecutiveFailures++;
                        if (consecutiveFailures >= MaxConsecutiveNonExpectedFailures) break;
                        continue;
                    }
                    consecutiveFailures = 0;

                    NativeDevice d = new NativeDevice();
                    d.InstanceId = GetInstanceId(set, ref data);
                    d.Description = GetStringProperty(set, ref data, SPDRP_DEVICEDESC);
                    d.FriendlyName = GetStringProperty(set, ref data, SPDRP_FRIENDLYNAME);
                    d.Class = GetStringProperty(set, ref data, SPDRP_CLASS);
                    d.Manufacturer = GetStringProperty(set, ref data, SPDRP_MFG);
                    d.Service = GetStringProperty(set, ref data, SPDRP_SERVICE);
                    d.HardwareIds = GetStringProperty(set, ref data, SPDRP_HARDWAREID);
                    d.CompatibleIds = GetStringProperty(set, ref data, SPDRP_COMPATIBLEIDS);
                    d.LocationInfo = GetStringProperty(set, ref data, SPDRP_LOCATION_INFORMATION);
                    d.Enumerator = GetStringProperty(set, ref data, SPDRP_ENUMERATOR_NAME);

                    uint status, problem;
                    int cr = CmGetDevNodeStatus(out status, out problem, data.DevInst, 0);
                    if (cr == CR_SUCCESS)
                    {
                        d.Status = status;
                        d.ProblemCode = problem;
                        d.HasProblem = (status & DN_HAS_PROBLEM) != 0;
                        d.IsPresent = true;
                        d.StatusQueried = true;
                    }
                    else
                    {
                        // CR_NO_SUCH_DEVINST (0x0D) = dispositivo fantasma:
                        // esta registrado mas nao esta conectado agora.
                        // StatusQueried=false aqui
                        // - ProblemCode=0 nao pode significar "sem problema"
                        // quando a propria consulta de status falhou.
                        d.IsPresent = false;
                        d.ProblemCode = 0;
                        d.StatusQueried = false;
                    }

                    devices.Add(d);
                }
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(set);
            }

            return devices;
        }

        private static string GetInstanceId(IntPtr set, ref SP_DEVINFO_DATA data)
        {
            try
            {
                StringBuilder sb = new StringBuilder(1024);
                uint required;
                if (SetupDiGetDeviceInstanceIdW(set, ref data, sb, (uint)sb.Capacity, out required))
                    return sb.ToString();
            }
            catch { }
            return null;
        }

        private static string GetStringProperty(IntPtr set, ref SP_DEVINFO_DATA data, uint property)
        {
            try
            {
                byte[] buffer = new byte[2048];
                uint regType, required;
                if (!SetupDiGetDeviceRegistryPropertyW(set, ref data, property, out regType, buffer, (uint)buffer.Length, out required))
                {
                    // Uma propriedade maior que os
                    // 2048 bytes do buffer fixo (HardwareIds/CompatibleIds
                    // com muitas entradas passam disso com facilidade) fazia
                    // a chamada devolver false por buffer pequeno, e o valor
                    // inteiro virava null - silenciosamente, sem diferenciar
                    // de "propriedade ausente". HardwareIds/CompatibleIds
                    // truncados assim perdem o identificador usado para casar
                    // com o inventario WMI e para achar drivers compativeis.
                    // ERROR_INSUFFICIENT_BUFFER (122) e o sinal de que so
                    // falta espaco - realoca com o tamanho que a propria
                    // chamada informou (RequiredSize) e tenta mais uma vez.
                    if (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER && required > (uint)buffer.Length)
                    {
                        buffer = new byte[required];
                        if (!SetupDiGetDeviceRegistryPropertyW(set, ref data, property, out regType, buffer, (uint)buffer.Length, out required))
                            return null;
                    }
                    else
                    {
                        return null;
                    }
                }

                if (required == 0) return null;
                int byteCount = (int)Math.Min(required, (uint)buffer.Length);

                string raw = Encoding.Unicode.GetString(buffer, 0, byteCount);
                // REG_MULTI_SZ (7) vem com strings separadas por NUL.
                if (regType == 7)
                {
                    string[] parts = raw.Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
                    return parts.Length == 0 ? null : string.Join(" | ", parts);
                }

                int nul = raw.IndexOf('\0');
                if (nul >= 0) raw = raw.Substring(0, nul);
                raw = raw.Trim();
                return raw.Length == 0 ? null : raw;
            }
            catch { return null; }
        }

        // Traducao dos codigos do Gerenciador de Dispositivos (item 16).
        // Fonte: documentacao oficial de "Device Manager Error Messages".
        public static string ProblemCodeMeaning(uint code)
        {
            switch (code)
            {
                case 0: return "Sem problema";
                case 1: return "Code 1: dispositivo nao configurado corretamente (driver ausente ou INF incompleto)";
                case 3: return "Code 3: driver pode estar corrompido, ou o sistema esta sem memoria/recursos";
                case 9: return "Code 9: informacao do dispositivo no registro esta invalida";
                case 10: return "Code 10: o dispositivo nao pode iniciar (falha do driver ou do proprio hardware)";
                case 12: return "Code 12: nao ha recursos livres suficientes (conflito de IRQ/memoria/IO)";
                case 14: return "Code 14: exige reinicializacao do computador para funcionar";
                case 16: return "Code 16: o Windows nao conseguiu identificar todos os recursos que o dispositivo usa";
                case 18: return "Code 18: e necessario reinstalar os drivers do dispositivo";
                case 19: return "Code 19: configuracao do registro corrompida ou duplicada";
                case 21: return "Code 21: o Windows esta removendo o dispositivo";
                case 22: return "Code 22: dispositivo DESATIVADO (pelo usuario ou por politica) - nao e defeito";
                case 24: return "Code 24: dispositivo ausente, funcionando mal, ou com driver incompleto (tipico de hardware removido)";
                case 28: return "Code 28: drivers nao instalados para este dispositivo";
                case 29: return "Code 29: desativado porque o firmware nao lhe deu os recursos necessarios (ver BIOS/UEFI)";
                case 31: return "Code 31: o dispositivo nao funciona porque o Windows nao carrega os drivers dele";
                case 32: return "Code 32: o driver foi desabilitado (tipo de inicializacao do servico em Disabled)";
                case 33: return "Code 33: nao foi possivel determinar quais recursos o dispositivo precisa (falha de hardware)";
                case 34: return "Code 34: exige configuracao manual de recursos (jumper/BIOS)";
                case 35: return "Code 35: o firmware nao tem informacao suficiente para configurar o dispositivo (atualizar BIOS)";
                case 36: return "Code 36: o dispositivo esta pedindo uma interrupcao PCI mas esta configurado para ISA (ou o oposto)";
                case 37: return "Code 37: o driver retornou falha ao inicializar o dispositivo";
                case 38: return "Code 38: uma instancia anterior do driver ainda esta na memoria (exige reinicializacao)";
                case 39: return "Code 39: driver corrompido ou ausente";
                case 40: return "Code 40: a chave do servico no registro esta invalida";
                case 41: return "Code 41: o driver carregou, mas o Windows nao encontrou o dispositivo (tipico em hardware nao PnP)";
                case 42: return "Code 42: driver duplicado (o dispositivo ja tem uma instancia rodando)";
                case 43: return "Code 43: o Windows PAROU este dispositivo porque ele reportou um problema (falha de hardware ou de driver)";
                case 44: return "Code 44: um aplicativo ou servico parou o dispositivo";
                case 45: return "Code 45: dispositivo nao esta conectado no momento (registro historico)";
                case 46: return "Code 46: indisponivel porque o sistema esta desligando";
                case 47: return "Code 47: o dispositivo foi preparado para remocao segura mas nao foi removido fisicamente";
                case 48: return "Code 48: o software deste dispositivo foi bloqueado por ter problema conhecido de compatibilidade";
                case 49: return "Code 49: o hive do sistema excedeu o tamanho maximo";
                case 52: return "Code 52: o Windows nao consegue verificar a ASSINATURA DIGITAL do driver";
                case 53: return "Code 53: o dispositivo foi reservado para uso pelo depurador do kernel";
                case 54: return "Code 54: o dispositivo falhou e esta em reinicializacao";
                default: return "Code " + code + ": codigo de problema nao catalogado";
            }
        }

        // Severidade padronizada por codigo. Code 22 (desativado) e decisao
        // administrativa, nao defeito - tratar como problema seria falso
        // positivo.
        public static bool IsCodeAdministrativeChoice(uint code)
        {
            return code == 22 || code == 32 || code == 47;
        }

        public static bool IsCodeHardwareSuspect(uint code)
        {
            return code == 10 || code == 43 || code == 33 || code == 37 || code == 54 || code == 12;
        }

        // ---------- Carga de CPU do sistema ----------
        //
        // Medir a carga de CPU enumerando processos individualmente (tempo
        // de CPU por processo dividido pelo intervalo pedido) e fragil: o
        // custo da propria enumeracao pode dominar o intervalo medido, o
        // denominador correto e o tempo de parede REALMENTE decorrido (nao o
        // intervalo pedido), e processos sem privilegio suficiente distorcem
        // o numerador.
        //
        // GetSystemTimes e a API correta para isto: uma unica chamada de
        // kernel (sem enumerar processo nenhum, sem depender de privilegio)
        // devolve idle/kernel/user do SISTEMA INTEIRO. kernel JA INCLUI
        // idle no Windows, entao ocupado = (kernel+user) - idle.
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetSystemTimes(
            out System.Runtime.InteropServices.ComTypes.FILETIME lpIdleTime,
            out System.Runtime.InteropServices.ComTypes.FILETIME lpKernelTime,
            out System.Runtime.InteropServices.ComTypes.FILETIME lpUserTime);

        private static ulong ToUInt64(System.Runtime.InteropServices.ComTypes.FILETIME ft)
        {
            return ((ulong)(uint)ft.dwHighDateTime << 32) | (uint)ft.dwLowDateTime;
        }

        // Devolve null quando a amostra nao e confiavel (chamada falhou, ou
        // o resultado saiu fora da faixa fisicamente possivel [0,100] -
        // nesse caso e sintoma de erro de medicao, nao deve ser
        // silenciosamente cortado para 100 como antes).
        public static double? SampleSystemCpuLoad(int intervalMs)
        {
            System.Runtime.InteropServices.ComTypes.FILETIME idle1, kernel1, user1;
            if (!GetSystemTimes(out idle1, out kernel1, out user1)) return null;

            System.Threading.Thread.Sleep(intervalMs);

            System.Runtime.InteropServices.ComTypes.FILETIME idle2, kernel2, user2;
            if (!GetSystemTimes(out idle2, out kernel2, out user2)) return null;

            ulong idleDelta = ToUInt64(idle2) - ToUInt64(idle1);
            ulong kernelDelta = ToUInt64(kernel2) - ToUInt64(kernel1);
            ulong userDelta = ToUInt64(user2) - ToUInt64(user1);
            ulong totalDelta = kernelDelta + userDelta; // kernel ja inclui idle

            if (totalDelta == 0) return null;
            if (idleDelta > totalDelta) return null; // impossivel fisicamente - amostra invalida

            double busy = totalDelta - idleDelta;
            double pct = busy / totalDelta * 100.0;

            if (pct < 0 || pct > 100) return null; // sintoma de erro de medicao, nunca cortar em silencio
            return Math.Round(pct, 1);
        }
    }
}
