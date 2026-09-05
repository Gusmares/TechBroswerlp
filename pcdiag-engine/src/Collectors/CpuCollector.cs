using System;
using System.Collections.Generic;
using System.Globalization;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    public sealed class CpuCollector : ICollector
    {
        public string Name { get { return "Cpu"; } }

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            CpuInfo c = inv.Cpu;

            // DataExecutionPrevention_Available e propriedade de
            // Win32_OperatingSystem, nao existe em Win32_Processor -
            // incluir esse campo na projecao faz o WQL inteiro ser
            // rejeitado ("Consulta invalida"), e NENHUM campo de CPU e
            // preenchido (nucleos, sockets, clocks, WmiStatus). Por isso
            // fica de fora da projecao abaixo; o campo correspondente no
            // modelo nao e lido a partir daqui.
            IList<DataRow> rows = Try.Get(ctx, Name, "Win32_Processor", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT Name, Manufacturer, Architecture, Family, Description, SocketDesignation, " +
                    "NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, CurrentClockSpeed, " +
                    "L2CacheSize, L3CacheSize, VirtualizationFirmwareEnabled, SecondLevelAddressTranslationExtensions, " +
                    "LoadPercentage, Status FROM Win32_Processor");
            });

            if (rows != null && rows.Count > 0)
            {
                // Soma todos os sockets. O coletor antigo pegava so o primeiro
                // e subnotificava nucleos/threads em maquina de 2 sockets.
                c.SocketCount = rows.Count;

                int cores = 0, threads = 0;
                bool anyCores = false, anyThreads = false;
                double loadSum = 0; int loadCount = 0;
                // Em maquina multi-socket, o status agregado precisa ser o
                // PIOR entre as linhas, nao apenas o da primeira - senao um
                // socket degradado passa despercebido enquanto outro esta OK.
                string worstStatus = null;

                foreach (DataRow r in rows)
                {
                    // NumberOfCores/NumberOfLogicalProcessors iguais a 0 nao
                    // sao um fato ("CPU com 0 nucleos") - normalmente indicam
                    // um provedor WMI que nao preencheu o campo direito
                    // (costuma aparecer junto com MaxClockSpeed=0 na mesma
                    // linha). Aceitar HasValue sem checar > 0 gravaria
                    // PhysicalCores/LogicalProcessors = 0 no Inventory, e como
                    // esses campos ficariam com valor (mesmo que zero),
                    // CrossCheckWithNativeApi nunca entraria para preencher
                    // com GetNativeSystemInfo - o fallback nativo so roda
                    // quando o campo esta null.
                    int? nc = r.Int("NumberOfCores");
                    if (nc.HasValue && nc.Value > 0) { cores += nc.Value; anyCores = true; }

                    int? nl = r.Int("NumberOfLogicalProcessors");
                    if (nl.HasValue && nl.Value > 0) { threads += nl.Value; anyThreads = true; }

                    int? load = r.Int("LoadPercentage");
                    if (load.HasValue) { loadSum += load.Value; loadCount++; }

                    string status = r.Str("Status");
                    if (status != null && (worstStatus == null || string.Equals(worstStatus, "OK", StringComparison.OrdinalIgnoreCase)))
                        worstStatus = status;
                }

                if (anyCores) c.PhysicalCores = cores;
                if (anyThreads) c.LogicalProcessors = threads;
                if (loadCount > 0) c.LoadPercent = Math.Round(loadSum / loadCount, 1);

                DataRow first = rows[0];
                c.Name = first.Str("Name");
                c.Manufacturer = first.Str("Manufacturer");
                c.Socket = first.Str("SocketDesignation");
                c.Family = first.Int("Family");

                // Mesma logica para os clocks - 0 MHz nao e um clock, e
                // gravar isso como fato impede o fallback do registro
                // (~MHz, em CrossCheckWithRegistry) de entrar, ja que esse
                // fallback so roda quando MaxClockMhz ainda esta null.
                int? maxClock = first.Int("MaxClockSpeed");
                c.MaxClockMhz = (maxClock.HasValue && maxClock.Value > 0) ? maxClock : null;

                int? curClock = first.Int("CurrentClockSpeed");
                c.CurrentClockMhz = (curClock.HasValue && curClock.Value > 0) ? curClock : null;
                c.L2CacheKb = first.Int("L2CacheSize");
                c.L3CacheKb = first.Int("L3CacheSize");
                c.VirtualizationEnabled = first.Bool("VirtualizationFirmwareEnabled");
                c.SecondLevelAddressTranslation = first.Bool("SecondLevelAddressTranslationExtensions");
                c.DataExecutionPrevention = first.Bool("DataExecutionPrevention_Available");
                c.WmiStatus = worstStatus;
                c.Architecture = ArchitectureName(first.Int("Architecture"));

                ParseFamilyModelStepping(first.Str("Description"), c);
            }

            CrossCheckWithRegistry(ctx, src, c);
            CrossCheckWithNativeApi(ctx, c);
        }

        // Segunda fonte independente: HKLM\HARDWARE\DESCRIPTION vem direto do
        // que o kernel enumerou no boot, sem passar pelo provedor WMI.
        private void CrossCheckWithRegistry(ScanContext ctx, SourceSet src, CpuInfo c)
        {
            const string key = @"HARDWARE\DESCRIPTION\System\CentralProcessor\0";

            string regName = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", key, "ProcessorNameString"));
            string identifier = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", key, "Identifier"));
            object mhz = RegistryWalk.ValueSafe(src.Registry, "HKLM", key, "~MHz");

            if (c.Name == null && regName != null) c.Name = regName;

            if (c.Name != null && regName != null)
            {
                string a = Normalize(c.Name);
                string b = Normalize(regName);
                if (a != b)
                {
                    ctx.AddInconsistency("Modelo da CPU",
                        "WMI e registro do kernel reportam nomes diferentes para o mesmo processador.",
                        Severity.Low,
                        Evidence.Of("WMI", "Win32_Processor.Name", c.Name),
                        Evidence.Of("Registry", key + "\\ProcessorNameString", regName));
                }
                else
                {
                    // So aqui existe prova real de que a segunda fonte
                    // (registro do kernel) concordou com a WMI - CPU-001 le
                    // esta flag antes de conceder AgreeingSource().
                    c.NameConfirmedByRegistry = true;
                }
            }

            if (!c.MaxClockMhz.HasValue && mhz != null)
            {
                try { c.MaxClockMhz = Convert.ToInt32(mhz, CultureInfo.InvariantCulture); }
                catch { }
            }

            if (identifier != null && (!c.Family.HasValue || !c.Stepping.HasValue))
                ParseFamilyModelStepping(identifier, c);
        }

        private void CrossCheckWithNativeApi(ScanContext ctx, CpuInfo c)
        {
            Native.SystemInfoLite si = Native.GetSystemInfoNative();
            if (si == null) return;

            if (!c.LogicalProcessors.HasValue) c.LogicalProcessors = si.LogicalProcessors;
            else if (si.LogicalProcessors > 0 && si.LogicalProcessors == c.LogicalProcessors.Value)
            {
                // Prova real de que a API nativa (fonte independente da
                // WMI) confirmou o mesmo numero.
                c.LogicalProcessorsConfirmedByNativeApi = true;
            }
            else if (si.LogicalProcessors > 0 && si.LogicalProcessors != c.LogicalProcessors.Value)
            {
                // GetNativeSystemInfo so enxerga o grupo de processadores atual;
                // acima de 64 threads o Windows divide em grupos, e a divergencia
                // e esperada, nao defeito.
                if (c.LogicalProcessors.Value <= 64)
                {
                    ctx.AddInconsistency("Quantidade de processadores logicos",
                        "WMI e API nativa discordam sobre o numero de threads.",
                        Severity.Low,
                        Evidence.Of("WMI", "Win32_Processor.NumberOfLogicalProcessors", c.LogicalProcessors),
                        Evidence.Of("Native", "GetNativeSystemInfo.dwNumberOfProcessors", si.LogicalProcessors));
                }
            }

            if (c.Architecture == null) c.Architecture = si.Architecture;
        }

        // "Intel64 Family 6 Model 158 Stepping 10"
        public static void ParseFamilyModelStepping(string description, CpuInfo c)
        {
            if (string.IsNullOrEmpty(description) || c == null) return;

            string[] tokens = description.Split(new char[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < tokens.Length - 1; i++)
            {
                int v;
                if (!int.TryParse(tokens[i + 1], NumberStyles.Integer, CultureInfo.InvariantCulture, out v)) continue;

                if (string.Equals(tokens[i], "Family", StringComparison.OrdinalIgnoreCase) && !c.Family.HasValue) c.Family = v;
                else if (string.Equals(tokens[i], "Model", StringComparison.OrdinalIgnoreCase) && !c.ModelId.HasValue) c.ModelId = v;
                else if (string.Equals(tokens[i], "Stepping", StringComparison.OrdinalIgnoreCase) && !c.Stepping.HasValue) c.Stepping = v;
            }
        }

        public static string ArchitectureName(int? arch)
        {
            if (!arch.HasValue) return null;
            switch (arch.Value)
            {
                case 0: return "x86";
                case 1: return "MIPS";
                case 2: return "Alpha";
                case 3: return "PowerPC";
                case 5: return "ARM";
                case 6: return "Itanium";
                case 9: return "x64";
                case 12: return "ARM64";
                default: return "Arquitetura " + arch.Value;
            }
        }

        private static string Normalize(string s)
        {
            if (s == null) return null;
            string r = s.Replace("(R)", "").Replace("(TM)", "").Replace("(r)", "").Replace("(tm)", "");
            while (r.IndexOf("  ", StringComparison.Ordinal) >= 0) r = r.Replace("  ", " ");
            return r.Trim().ToLowerInvariant();
        }

        private static string AsString(object v)
        {
            if (v == null) return null;
            string s = Convert.ToString(v, CultureInfo.InvariantCulture);
            if (s == null) return null;
            s = s.Trim();
            return s.Length == 0 ? null : s;
        }
    }
}
