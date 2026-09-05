using System;
using System.Collections.Generic;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    public sealed class MemoryCollector : ICollector
    {
        public string Name { get { return "Memory"; } }

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            MemoryInfo m = inv.Memory;

            CollectRuntimeStatus(ctx, m);
            CollectModules(ctx, src, m);
            CollectArray(ctx, src, m);
            CollectPageFile(ctx, src, m);
            CollectComputerSystemTotal(ctx, src, m);
            CrossCheckTotals(ctx, m);
        }

        // Terceira fonte independente de RAM total, complementando as duas
        // coletadas em CollectModules/CollectRuntimeStatus. Consulta propria
        // e minima - nao acopla este coletor ao SystemCollector, que ja
        // consulta Win32_ComputerSystem para outros campos, mas roda
        // separado e isolado por timeout proprio.
        private void CollectComputerSystemTotal(ScanContext ctx, SourceSet src, MemoryInfo m)
        {
            DataRow row = Helpers.FirstRow(Try.Get(ctx, Name, "Win32_ComputerSystem.TotalPhysicalMemory", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2, "SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
            }));
            if (row != null) m.ComputerSystemTotalBytes = row.ULong("TotalPhysicalMemory");
        }

        private void CollectRuntimeStatus(ScanContext ctx, MemoryInfo m)
        {
            // Instalado (SMBIOS, via kernel) x utilizavel (o que o SO enxerga).
            // A diferenca e a memoria reservada para hardware - dado que o
            // briefing pede que seja EXPLICADO, nao so alertado.
            m.InstalledBytes = Native.GetInstalledMemoryBytes();

            Native.MemoryStatus s = Native.GetMemoryStatus();
            if (s != null)
            {
                m.UsableBytes = s.TotalPhysicalBytes;
                m.AvailableBytes = s.AvailablePhysicalBytes;
                m.UsagePercent = s.LoadPercent;
                m.CommitTotalBytes = s.TotalCommitBytes;
                m.CommitAvailableBytes = s.AvailableCommitBytes;
            }

            if (m.InstalledBytes.HasValue && m.UsableBytes.HasValue && m.InstalledBytes.Value >= m.UsableBytes.Value)
                m.ReservedBytes = m.InstalledBytes.Value - m.UsableBytes.Value;
        }

        private void CollectModules(ScanContext ctx, SourceSet src, MemoryInfo m)
        {
            IList<DataRow> rows = Try.Get(ctx, Name, "Win32_PhysicalMemory", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT DeviceLocator, BankLabel, Capacity, Speed, ConfiguredClockSpeed, ConfiguredVoltage, " +
                    "SMBIOSMemoryType, FormFactor, Manufacturer, PartNumber, SerialNumber FROM Win32_PhysicalMemory");
            });

            if (rows == null) return;

            ulong sum = 0;
            bool anyCapacity = false;
            int validSlots = 0;

            foreach (DataRow r in rows)
            {
                // Uma linha de Win32_PhysicalMemory com Capacity ausente ou
                // <= 0 nao e um pente de memoria - e um registro SMBIOS tipo
                // 17 de slot vazio ou malformado que algumas placas publicam
                // mesmo assim. Contar essa linha como slot ocupado infla
                // "SlotsUsed" e, mesmo a capacidade zero nao alterando a
                // soma, o modulo apareceria na lista como se fosse um pente
                // real de 0 bytes, o que pode derrubar
                // ChannelConfiguration/CrossCheckTotals por engano - por isso
                // a linha e ignorada por completo antes de virar
                // MemoryModule.
                ulong? capacity = r.ULong("Capacity");
                if (!capacity.HasValue || capacity.Value == 0) continue;

                MemoryModule mod = new MemoryModule();
                mod.Slot = r.Str("DeviceLocator");
                mod.Bank = r.Str("BankLabel");
                mod.CapacityBytes = capacity;
                mod.SpeedMhz = r.Int("Speed");
                mod.ConfiguredSpeedMhz = r.Int("ConfiguredClockSpeed");
                mod.ConfiguredVoltageMv = r.Int("ConfiguredVoltage");
                mod.MemoryType = MemoryTypeName(r.Int("SMBIOSMemoryType"));
                mod.FormFactor = FormFactorName(r.Int("FormFactor"));
                mod.Manufacturer = SystemCollector.IsPlaceholder(r.Str("Manufacturer")) ? null : r.Str("Manufacturer");
                mod.PartNumber = SystemCollector.IsPlaceholder(r.Str("PartNumber")) ? null : r.Str("PartNumber");
                mod.SerialNumber = SystemCollector.IsPlaceholder(r.Str("SerialNumber")) ? null : r.Str("SerialNumber");

                sum += mod.CapacityBytes.Value;
                anyCapacity = true;
                validSlots++;
                m.Modules.Add(mod);
            }

            // Quando a WMI devolve zero linhas (falha silenciosa do provedor,
            // nao "zero memoria instalada"), afirmar SlotsUsed = 0 viraria um
            // fato errado no laudo ("0 de 4 slots ocupados, ate 4 livres para
            // upgrade"), quando na verdade e "nao sabemos quantos estao
            // ocupados". Por isso so afirma SlotsUsed quando pelo menos um
            // modulo valido foi de fato enumerado; caso contrario o valor
            // fica null e o teste MEM-003 deve tratar isso como Unknown.
            if (validSlots > 0) m.SlotsUsed = validSlots;
            if (anyCapacity) m.ModulesSumBytes = sum;

            m.ChannelConfiguration = InferChannelConfiguration(m.Modules);
        }

        // Inferencia conservadora: so afirma o modo de canal quando os
        // rotulos de slot do firmware seguem o padrao ChannelA/ChannelB. Em
        // qualquer outro caso devolve null (desconhecido) em vez de chutar.
        public static string InferChannelConfiguration(List<MemoryModule> modules)
        {
            if (modules == null || modules.Count == 0) return null;
            if (modules.Count == 1) return "Single-channel (1 modulo instalado)";

            List<string> channels = new List<string>();
            foreach (MemoryModule mod in modules)
            {
                string label = Helpers.FirstNonEmpty(mod.Slot, mod.Bank);
                if (label == null) return null;

                string ch = ExtractChannelToken(label);
                if (ch == null) return null;
                if (!channels.Contains(ch)) channels.Add(ch);
            }

            if (channels.Count <= 1) return null;
            if (channels.Count == 2) return "Dual-channel (" + modules.Count + " modulos em 2 canais)";
            if (channels.Count == 4) return "Quad-channel (" + modules.Count + " modulos em 4 canais)";
            return channels.Count + " canais detectados (" + modules.Count + " modulos)";
        }

        private static string ExtractChannelToken(string label)
        {
            if (label == null) return null;
            string u = label.ToUpperInvariant();

            int idx = u.IndexOf("CHANNEL", StringComparison.Ordinal);
            if (idx >= 0 && idx + 7 < u.Length)
            {
                char c = u[idx + 7];
                if (char.IsLetterOrDigit(c)) return "CH" + c;
            }

            // Padroes "DIMM_A1"/"DIMM_B2" tambem identificam canal.
            idx = u.IndexOf("DIMM", StringComparison.Ordinal);
            if (idx >= 0)
            {
                for (int i = idx + 4; i < u.Length; i++)
                {
                    if (u[i] >= 'A' && u[i] <= 'H') return "CH" + u[i];
                    if (char.IsDigit(u[i])) break;
                }
            }

            return null;
        }

        private void CollectArray(ScanContext ctx, SourceSet src, MemoryInfo m)
        {
            IList<DataRow> arrays = Try.Get(ctx, Name, "Win32_PhysicalMemoryArray", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT MemoryDevices, MaxCapacity, MaxCapacityEx, Manufacturer, SerialNumber FROM Win32_PhysicalMemoryArray");
            });

            if (arrays == null || arrays.Count == 0) return;

            int total = 0;
            bool any = false;
            foreach (DataRow r in arrays)
            {
                int? devices = r.Int("MemoryDevices");
                if (devices.HasValue && devices.Value > 0) { total += devices.Value; any = true; }
            }

            if (!any) return;
            m.SlotsTotalReportedByFirmware = total;

            // MaxCapacity sozinho nao e sinal confiavel de matriz "template
            // de fabrica": 64 GB e uma capacidade maxima real e comum em
            // placa recente, e uma matriz sem fabricante/serial preenchido
            // tambem e normal em muita placa que reporta esses campos
            // honestamente vazios. O unico sinal objetivo, que independe do
            // valor de MaxCapacity, e o abaixo: o firmware afirmar menos
            // slots do que a quantidade de pentes fisicamente detectados e
            // impossivel, entao o numero declarado esta errado.
            if (m.SlotsUsed.HasValue && total < m.SlotsUsed.Value)
            {
                m.SlotsTotalLooksTemplated = true;
                ctx.AddInconsistency("Total de slots de memoria",
                    "O firmware declara menos slots do que a quantidade de modulos realmente detectados.",
                    Severity.Medium,
                    Evidence.Of("WMI", "Win32_PhysicalMemoryArray.MemoryDevices", total),
                    Evidence.Of("WMI", "Win32_PhysicalMemory (contagem de instancias)", m.SlotsUsed.Value));
            }
        }

        private void CollectPageFile(ScanContext ctx, SourceSet src, MemoryInfo m)
        {
            IList<DataRow> rows = Try.Get(ctx, Name, "Win32_PageFileUsage", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2, "SELECT Name, AllocatedBaseSize, CurrentUsage FROM Win32_PageFileUsage");
            });

            if (rows == null || rows.Count == 0) return;

            ulong totalMb = 0;
            List<string> locations = new List<string>();
            foreach (DataRow r in rows)
            {
                ulong? mb = r.ULong("AllocatedBaseSize");
                if (mb.HasValue) totalMb += mb.Value;
                string n = r.Str("Name");
                if (n != null) locations.Add(n);
            }

            if (totalMb > 0) m.PageFileSizeBytes = totalMb * 1024UL * 1024UL;
            if (locations.Count > 0) m.PageFileLocation = string.Join("; ", locations.ToArray());
        }

        // A soma dos pentes detectados, o total instalado lido do kernel e o
        // total que a WMI reporta para o computador sao tres fontes
        // independentes de total de RAM. Divergencia real (acima de 64 MB de
        // folga) contra QUALQUER uma delas significa modulo que uma das
        // camadas nao esta enxergando - o tipo de achado que justifica abrir
        // a maquina.
        private void CrossCheckTotals(ScanContext ctx, MemoryInfo m)
        {
            if (!m.ModulesSumBytes.HasValue || !m.InstalledBytes.HasValue) return;

            long diff = (long)m.ModulesSumBytes.Value - (long)m.InstalledBytes.Value;
            if (Math.Abs(diff) > 64L * 1024L * 1024L)
            {
                ctx.AddInconsistency("Total de memoria RAM",
                    "A soma dos modulos detectados nao bate com a memoria instalada reportada pelo kernel.",
                    Severity.High,
                    Evidence.Of("WMI", "SUM(Win32_PhysicalMemory.Capacity)", m.ModulesSumBytes.Value),
                    Evidence.Of("Native", "GetPhysicallyInstalledSystemMemory", m.InstalledBytes.Value));
            }

            if (m.ComputerSystemTotalBytes.HasValue)
            {
                long diffCs = (long)m.ModulesSumBytes.Value - (long)m.ComputerSystemTotalBytes.Value;
                if (Math.Abs(diffCs) > 64L * 1024L * 1024L)
                {
                    ctx.AddInconsistency("Total de memoria RAM (Win32_ComputerSystem)",
                        "A soma dos modulos detectados nao bate com o total que a WMI reporta para o computador.",
                        Severity.Medium,
                        Evidence.Of("WMI", "SUM(Win32_PhysicalMemory.Capacity)", m.ModulesSumBytes.Value),
                        Evidence.Of("WMI", "Win32_ComputerSystem.TotalPhysicalMemory", m.ComputerSystemTotalBytes.Value));
                }
            }
        }

        public static string MemoryTypeName(int? code)
        {
            if (!code.HasValue || code.Value == 0) return null;   // 0 = desconhecido, nao "tipo 0"
            switch (code.Value)
            {
                case 2: return "DRAM";
                case 3: return "SDRAM";
                case 17: return "SDRAM";
                case 18: return "EDO";
                case 20: return "DDR";
                case 21: return "DDR2";
                case 22: return "DDR2 FB-DIMM";
                case 24: return "DDR3";
                case 25: return "FBD2";
                case 26: return "DDR4";
                case 27: return "LPDDR";
                case 28: return "LPDDR2";
                case 29: return "LPDDR3";
                case 30: return "LPDDR4";
                case 34: return "DDR5";
                case 35: return "LPDDR5";
                default: return "Tipo SMBIOS " + code.Value;
            }
        }

        public static string FormFactorName(int? code)
        {
            if (!code.HasValue) return null;
            switch (code.Value)
            {
                case 8: return "DIMM";
                case 12: return "SODIMM";
                case 13: return "SRIMM";
                case 0: return null;
                default: return "FormFactor " + code.Value;
            }
        }
    }
}
