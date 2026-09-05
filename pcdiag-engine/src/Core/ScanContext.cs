using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Principal;

namespace PcDiag.Core
{
    // Opcoes de execucao, vindas da linha de comando.
    public sealed class ScanOptions
    {
        public ScanOptions()
        {
            Mode = ScanMode.Diagnostic;
            ModuleTimeoutMs = 30000;
            StressSeconds = 20;
            MemoryTestMegabytes = 512;
            DiskTestMegabytes = 256;
            OpenReport = true;
            TechnicianReport = true;
            Formats = new List<string>();
        }

        public ScanMode Mode { get; set; }
        public bool PrivacySafe { get; set; }
        public bool AllowStress { get; set; }
        public bool AllowDiskWriteBenchmark { get; set; }
        public bool AllowMemoryTest { get; set; }
        public bool AllowGpuStress { get; set; }
        public int StressSeconds { get; set; }
        public int MemoryTestMegabytes { get; set; }
        public int DiskTestMegabytes { get; set; }
        public int ModuleTimeoutMs { get; set; }
        public bool OpenReport { get; set; }
        public bool TechnicianReport { get; set; }
        public bool Verbose { get; set; }
        public string OutputDirectory { get; set; }
        public string BaselinePath { get; set; }
        public List<string> Formats { get; set; }

        public int CpuWarnC { get; set; }
        public int CpuCritC { get; set; }

        // Limiares proprios para leitura em REPOUSO (usados quando --stress
        // nao e passado, o modo padrao no balcao): os limiares de CARGA
        // (85/95 C) nao fazem sentido para uma maquina ociosa, entao o
        // repouso usa valores mais baixos, condizentes com o que um
        // processador saudavel realmente mostra parado.
        public int CpuIdleWarnC { get; set; }
        public int CpuIdleCritC { get; set; }

        public int GpuWarnC { get; set; }
        public int GpuCritC { get; set; }
        public int BoardWarnC { get; set; }

        public static ScanOptions Defaults()
        {
            ScanOptions o = new ScanOptions();
            o.CpuWarnC = 85;
            o.CpuCritC = 95;
            o.CpuIdleWarnC = 60;
            o.CpuIdleCritC = 75;
            o.GpuWarnC = 85;
            o.GpuCritC = 92;
            o.BoardWarnC = 65;
            o.Formats.Add("html");
            o.Formats.Add("json");
            return o;
        }
    }

    // Metadados de reprodutibilidade (item 60) + estado de privilegio.
    public sealed class ScanContext
    {
        public const string ToolVersion = "2.0.0";
        public const int SchemaVersion = 2;
        public const string RulesVersion = "v2";

        public ScanContext(ScanOptions options, Logger logger)
        {
            Options = options;
            Log = logger;
            ScanId = Guid.NewGuid().ToString("N").Substring(0, 16);
            StartedAt = DateTime.Now;
            IsElevated = DetectElevation();

            // IntPtr.Size so revela a BITNESS DO PROCESSO (sempre 8 num
            // binario /platform:anycpu rodando em qualquer Windows moderno,
            // inclusive sob emulacao ARM64EC/WOW64), nao a arquitetura real
            // da maquina. GetNativeSystemInfo devolve a arquitetura fisica
            // do processador, nao a do processo, e por isso e usado aqui -
            // a distincao importa porque LibreHardwareMonitorLib (a unica
            // fonte de temperatura/sensores) nao funciona em ARM64.
            Sources.Native.SystemInfoLite sysInfo = Sources.Native.GetSystemInfoNative();
            ProcessArchitecture = sysInfo != null && !string.IsNullOrEmpty(sysInfo.Architecture)
                ? sysInfo.Architecture
                : (IntPtr.Size == 8 ? "x64" : "x86");

            // Versao verdadeira via RtlGetVersion; Environment.OSVersion so e
            // usado como ultimo recurso porque mente sem manifesto.
            Version real = Sources.Native.GetRealOsVersion();
            if (real == null) real = Environment.OSVersion.Version;
            OsVersionRaw = real.ToString();

            MachineNameRaw = SafeMachineName();

            string reason;
            Support = ClassifySupport(real, Environment.Is64BitOperatingSystem, ProcessArchitecture, out reason);
            SupportReason = reason;
            ModuleOutcomes = new List<ModuleOutcome>();
            Inconsistencies = new List<Inconsistency>();
        }

        public string ScanId { get; private set; }
        public DateTime StartedAt { get; private set; }
        public bool IsElevated { get; private set; }
        public string ProcessArchitecture { get; private set; }
        public string OsVersionRaw { get; private set; }
        public string MachineNameRaw { get; private set; }
        public SupportLevel Support { get; private set; }
        public string SupportReason { get; private set; }

        public ScanOptions Options { get; private set; }
        public Logger Log { get; private set; }
        public List<ModuleOutcome> ModuleOutcomes { get; private set; }
        public List<Inconsistency> Inconsistencies { get; private set; }

        public bool SensorsAvailable { get; set; }

        // Usado apenas pela suite de testes, para exercitar os caminhos com e
        // sem elevacao sem precisar reexecutar o processo elevado. Nao ha
        // chamada a este metodo no codigo de producao.
        public void OverrideElevationForTesting(bool elevated)
        {
            IsElevated = elevated;
        }

        // List<T>.Add nao e thread-safe, e este
        // metodo pode ser chamado por uma thread de modulo ABANDONADA por
        // timeout (ModuleRunner deixa a thread orfa rodando em background)
        // ao mesmo tempo em que o serializador do relatorio percorre a MESMA
        // lista com foreach (Json.cs/HtmlReport.cs, via Engine.cs). Um Add
        // simultaneo a um foreach em andamento pode corromper o estado
        // interno da List ou derrubar o foreach com
        // InvalidOperationException. O lock aqui elimina a corrupcao entre
        // Adds concorrentes (o cenario mais provavel, com varios modulos
        // reportando divergencia ao mesmo tempo); ele nao cobre o foreach do
        // lado do serializador, que vive em Reporting/Json.cs e
        // Reporting/HtmlReport.cs - fora do escopo deste arquivo.
        private readonly object _inconsistencyLock = new object();

        public void AddInconsistency(string subject, string explanation, Severity severity, params Evidence[] readings)
        {
            Inconsistency inc = new Inconsistency();
            inc.Subject = subject;
            inc.Explanation = explanation;
            inc.Severity = severity;
            if (readings != null) inc.Readings.AddRange(readings);
            lock (_inconsistencyLock)
            {
                Inconsistencies.Add(inc);
            }
            Log.Write(LogLevel.Warn, LogChannel.Diagnostic, "CrossCheck", "Divergencia em " + subject + ": " + explanation);
        }

        private static bool DetectElevation()
        {
            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal p = new WindowsPrincipal(id);
                    return p.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        private static string SafeMachineName()
        {
            try { return Environment.MachineName; }
            catch { return "(desconhecido)"; }
        }

        // Sobrecarga antiga, mantida por compatibilidade com os chamadores
        // existentes (tests/CoreTests.cs) que nao tem a arquitetura real
        // disponivel - assume x64, que e o comportamento que ja tinham.
        public static SupportLevel ClassifySupport(Version version, bool is64Bit, out string reason)
        {
            return ClassifySupport(version, is64Bit, "x64", out reason);
        }

        // Declara suporte explicitamente (item 67) em vez de fingir que roda
        // em qualquer lugar. Separado do construtor para poder ser testado com
        // versoes sinteticas, sem depender do sistema onde a suite roda.
        //
        // Recebe a arquitetura real (nao so a bitness do processo) para nao
        // declarar ARM64 como "Supported x64". Uma checagem de edicao
        // (Windows Server) exigiria ProductType via OSVERSIONINFOEXW/WMI,
        // que nao esta disponivel nas fontes nativas hoje expostas a este
        // arquivo - fica registrado como limitacao conhecida.
        public static SupportLevel ClassifySupport(Version version, bool is64Bit, string architecture, out string reason)
        {
            if (version == null)
            {
                reason = "Nao foi possivel determinar a versao do Windows; a coleta segue, mas sem garantia de cobertura.";
                return SupportLevel.PartiallySupported;
            }

            if (version.Major < 10)
            {
                reason = "Windows " + version.Major + "." + version.Minor +
                         " e anterior ao Windows 10 e nao e suportado por esta ferramenta.";
                return SupportLevel.Unsupported;
            }

            if (string.Equals(architecture, "ARM64", StringComparison.OrdinalIgnoreCase))
            {
                reason = "ARM64: a coleta funciona via P/Invoke, mas LibreHardwareMonitorLib nao suporta esta arquitetura - sensores e temperatura de hardware ficam indisponiveis.";
                return SupportLevel.PartiallySupported;
            }

            if (string.Equals(architecture, "ARM", StringComparison.OrdinalIgnoreCase))
            {
                reason = "ARM de 32 bits nao e suportado por esta ferramenta.";
                return SupportLevel.Unsupported;
            }

            if (!is64Bit)
            {
                // LibreHardwareMonitorLib (x64-only) e a fonte de
                // CPUID/RDTSC, do teste de carga e do benchmark de
                // memoria/disco, alem dos sensores - por isso a razao lista
                // todos esses itens, nao so "sensores".
                reason = "Windows 32 bits: alem dos sensores de hardware (temperatura), o teste de carga, o benchmark de memoria/disco e a leitura de CPUID via LibreHardwareMonitorLib (x64-only) tambem ficam indisponiveis.";
                return SupportLevel.PartiallySupported;
            }

            if (version.Build > 0 && version.Build < 17763)
            {
                reason = "Build " + version.Build + " e anterior ao Windows 10 1809; alguns contadores podem nao existir.";
                return SupportLevel.PartiallySupported;
            }

            reason = "Windows " + (version.Build >= 22000 ? "11" : "10") + " build " + version.Build + " " + architecture + ".";
            return SupportLevel.Supported;
        }

        public string FormatDuration()
        {
            TimeSpan d = DateTime.Now - StartedAt;
            return d.TotalSeconds.ToString("F1", CultureInfo.InvariantCulture) + "s";
        }
    }
}
