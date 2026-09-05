using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    public sealed class GpuCollector : ICollector
    {
        public string Name { get { return "Gpu"; } }

        private const string DisplayClassKey = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            IList<DataRow> rows = Try.Get(ctx, Name, "Win32_VideoController", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT Name, PNPDeviceID, AdapterRAM, AdapterCompatibility, DriverVersion, DriverDate, " +
                    "Status, ConfigManagerErrorCode, CurrentHorizontalResolution, CurrentVerticalResolution, " +
                    "CurrentRefreshRate, VideoProcessor FROM Win32_VideoController");
            });

            if (rows == null) return;

            List<RegistryAdapter> regAdapters = ReadRegistryAdapters(ctx, src);

            foreach (DataRow r in rows)
            {
                string pnp = r.Str("PNPDeviceID");

                // PNPDeviceID de GPU fisica comeca com "PCI\", mas
                // VM/Hyper-V/sessao RDP reportam video com PNPDeviceID
                // "VMBUS\...", "ROOT\..." - a UNICA GPU que esse tipo de
                // maquina tem. Descartar todo adaptador nao-PCI em silencio
                // deixaria essas maquinas sem nenhuma GPU no laudo. Esses
                // adaptadores entram na lista como Kind "Virtual/Sintetico",
                // sem tentar casamento de registro PCI nem resolucao de VRAM
                // (nenhum dos dois se aplica).
                if (pnp == null || !pnp.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase))
                {
                    GpuInfo virt = new GpuInfo();
                    virt.Name = r.Str("Name");
                    virt.PnpDeviceId = pnp;
                    virt.Status = r.Str("Status");
                    virt.DriverVersion = r.Str("DriverVersion");
                    virt.DriverDate = r.Date("DriverDate");
                    virt.DriverAgeYears = Helpers.YearsSince(virt.DriverDate);
                    virt.CurrentHorizontalResolution = r.Int("CurrentHorizontalResolution");
                    virt.CurrentVerticalResolution = r.Int("CurrentVerticalResolution");
                    virt.CurrentRefreshRate = r.Int("CurrentRefreshRate");
                    virt.VramSource = "Nao aplicavel: adaptador nao-PCI (virtual/sintetico)";
                    virt.Kind = "Virtual/Sintetico";
                    virt.KindSource = pnp == null
                        ? "PNPDeviceID ausente"
                        : "PNPDeviceID nao-PCI (" + pnp.Split('\\')[0] + ")";
                    inv.Gpus.Add(virt);
                    continue;
                }

                GpuInfo g = new GpuInfo();
                g.Name = r.Str("Name");
                g.PnpDeviceId = pnp;
                g.Status = r.Str("Status");

                int? cm = r.Int("ConfigManagerErrorCode");
                if (cm.HasValue && cm.Value != 0) g.ConfigManagerErrorCode = (uint)cm.Value;

                g.CurrentHorizontalResolution = r.Int("CurrentHorizontalResolution");
                g.CurrentVerticalResolution = r.Int("CurrentVerticalResolution");
                g.CurrentRefreshRate = r.Int("CurrentRefreshRate");
                g.DriverVersion = r.Str("DriverVersion");
                g.DriverDate = r.Date("DriverDate");
                g.DriverAgeYears = Helpers.YearsSince(g.DriverDate);

                Helpers.PciIds ids = Helpers.ParsePciIds(pnp);
                if (ids != null)
                {
                    g.PciVendorId = ids.VendorId;
                    g.PciDeviceId = ids.DeviceId;
                    g.SubsystemId = ids.SubsystemId;
                }

                g.Manufacturer = Helpers.FirstNonEmpty(
                    Helpers.PciVendorName(g.PciVendorId),
                    r.Str("AdapterCompatibility"));

                RegistryAdapter match = MatchRegistryAdapter(regAdapters, g);
                ResolveVram(ctx, g, r, match);

                if (match != null)
                {
                    g.DriverProvider = match.ProviderName;
                    if (g.DriverVersion == null) g.DriverVersion = match.DriverVersion;
                }

                g.IsGenericMicrosoftDriver = IsGenericDriver(g);
                Classify(g, match);

                inv.Gpus.Add(g);
            }
        }

        private sealed class RegistryAdapter
        {
            public string SubKey { get; set; }
            public string DriverDesc { get; set; }
            public string MatchingDeviceId { get; set; }
            public string ProviderName { get; set; }
            public string DriverVersion { get; set; }
            public ulong? QwMemorySize { get; set; }
            public string LocationInformation { get; set; }
        }

        private List<RegistryAdapter> ReadRegistryAdapters(ScanContext ctx, SourceSet src)
        {
            List<RegistryAdapter> list = new List<RegistryAdapter>();

            // CurrentControlSet, nao ControlSet001: numa maquina que bootou por
            // Last Known Good, ControlSet001 nao e o conjunto ativo e os dados
            // lidos seriam de um driver que nao esta em uso.
            foreach (string sub in RegistryWalk.SubKeysSafe(src.Registry, "HKLM", DisplayClassKey))
            {
                // So subchaves numericas ("0000", "0001") sao adaptadores.
                bool numeric = sub.Length == 4;
                for (int i = 0; i < sub.Length && numeric; i++) if (!char.IsDigit(sub[i])) numeric = false;
                if (!numeric) continue;

                string path = DisplayClassKey + "\\" + sub;
                RegistryAdapter a = new RegistryAdapter();
                a.SubKey = sub;
                a.DriverDesc = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", path, "DriverDesc"));
                a.MatchingDeviceId = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", path, "MatchingDeviceId"));
                a.ProviderName = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", path, "ProviderName"));
                a.DriverVersion = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", path, "DriverVersion"));
                a.LocationInformation = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", path, "LocationInformation"));

                // Alguns drivers (comum em NVIDIA/AMD mais recente) publicam
                // este valor como REG_BINARY em vez de REG_QWORD/REG_DWORD,
                // entao o dado chega como byte[] e precisa ser convertido
                // explicitamente (ver ReadUInt64RegistryValue) -
                // Convert.ToUInt64 direto sobre um byte[] lanca
                // InvalidCastException. HardwareInformation.MemorySize (nome
                // alternativo que alguns drivers usam) tambem e lido como
                // fallback quando qwMemorySize nao existir.
                ulong? qwValue = ReadUInt64RegistryValue(
                    RegistryWalk.ValueSafe(src.Registry, "HKLM", path, "HardwareInformation.qwMemorySize"));
                if (!qwValue.HasValue)
                    qwValue = ReadUInt64RegistryValue(
                        RegistryWalk.ValueSafe(src.Registry, "HKLM", path, "HardwareInformation.MemorySize"));
                if (qwValue.HasValue && qwValue.Value > 0) a.QwMemorySize = qwValue.Value;

                if (a.DriverDesc != null || a.MatchingDeviceId != null) list.Add(a);
            }

            return list;
        }

        // Le um valor de registro numerico que pode chegar como qualquer
        // tipo REG_* (DWORD, QWORD ou REG_BINARY como byte[] de 4 ou 8
        // bytes em little-endian, o formato que o CfgMgr32/inf do driver de
        // video costuma gravar).
        private static ulong? ReadUInt64RegistryValue(object raw)
        {
            if (raw == null) return null;

            byte[] bytes = raw as byte[];
            if (bytes != null)
            {
                if (bytes.Length >= 8) return BitConverter.ToUInt64(bytes, 0);
                if (bytes.Length == 4) return BitConverter.ToUInt32(bytes, 0);
                return null;
            }

            try { return Convert.ToUInt64(raw, CultureInfo.InvariantCulture); }
            catch { return null; }
        }

        // Casamento por VEN_/DEV_ (identificador estavel do hardware) em vez de
        // igualdade exata de nome comercial. Com duas GPUs identicas, o nome
        // nao distingue - o coletor antigo atribuia a mesma VRAM as duas.
        private RegistryAdapter MatchRegistryAdapter(List<RegistryAdapter> adapters, GpuInfo g)
        {
            if (adapters == null || adapters.Count == 0) return null;

            if (g.PciVendorId != null && g.PciDeviceId != null)
            {
                string needle = "VEN_" + g.PciVendorId + "&DEV_" + g.PciDeviceId;
                List<RegistryAdapter> byId = new List<RegistryAdapter>();
                foreach (RegistryAdapter a in adapters)
                {
                    if (a.MatchingDeviceId == null) continue;
                    if (a.MatchingDeviceId.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) byId.Add(a);
                }

                if (byId.Count == 1) return byId[0];

                // Com duas GPUs identicas (mesmo VEN_/DEV_), o desempate por
                // nome comercial nao resolve nada - as duas tem o mesmo
                // DriverDesc. Desempata primeiro pelo caminho PCI real:
                // compara o device/function extraidos do PNPDeviceID (fonte
                // WMI) com o device/function que a string LocationInformation
                // do registro publica (ja lida acima). So quando isso resolve
                // para exatamente um adaptador e que a atribuicao e feita.
                if (byId.Count > 1)
                {
                    int wmiDevice, wmiFunction;
                    if (TryParsePciDeviceFunction(g.PnpDeviceId, out wmiDevice, out wmiFunction))
                    {
                        List<RegistryAdapter> byLocation = new List<RegistryAdapter>();
                        foreach (RegistryAdapter a in byId)
                        {
                            int regDevice, regFunction;
                            if (TryParsePciDeviceFunction(a.LocationInformation, out regDevice, out regFunction) &&
                                regDevice == wmiDevice && regFunction == wmiFunction)
                            {
                                byLocation.Add(a);
                            }
                        }
                        if (byLocation.Count == 1) return byLocation[0];
                    }

                    // Sem desempate seguro por localizacao (registro nao
                    // publicou LocationInformation utilizavel, ou mais de um
                    // adaptador colidiu tambem no device/function), nao
                    // atribui nada - errado e melhor do que trocado.
                    return null;
                }
            }

            foreach (RegistryAdapter a in adapters)
            {
                if (a.DriverDesc != null && string.Equals(a.DriverDesc, g.Name, StringComparison.OrdinalIgnoreCase)) return a;
            }

            return null;
        }

        private void ResolveVram(ScanContext ctx, GpuInfo g, DataRow wmiRow, RegistryAdapter match)
        {
            // Win32_VideoController.AdapterRAM e um DWORD de 32 bits: satura em
            // ~4 GB e e simplesmente errado em qualquer GPU moderna. O valor
            // correto de 64 bits esta no registro.
            ulong? fromRegistry = (match != null) ? match.QwMemorySize : null;

            uint? adapterRam = null;
            object raw = wmiRow.Raw("AdapterRAM");
            if (raw != null)
            {
                try { adapterRam = Convert.ToUInt32(raw, CultureInfo.InvariantCulture); }
                catch { }
            }

            if (fromRegistry.HasValue)
            {
                g.VramBytes = fromRegistry.Value;
                g.VramSource = "Registro (HardwareInformation.qwMemorySize, 64 bits)";

                if (adapterRam.HasValue && adapterRam.Value > 0)
                {
                    // O guarda de saturacao e so sobre adapterRam (o DWORD
                    // de 32 bits que de fato satura): so ignora a comparacao
                    // quando o proprio AdapterRAM estiver saturado (perto do
                    // teto de um uint32), e compara normalmente em qualquer
                    // outro caso, mesmo com VRAM real acima de 4 GB -
                    // comparar fromRegistry (o valor de 64 bits) contra o
                    // limite de 4 GB desligaria o cross-check justamente no
                    // hardware onde ele mais importa.
                    bool adapterRamSaturated = adapterRam.Value >= 0xFFFF0000U;
                    if (!adapterRamSaturated)
                    {
                        ulong diff = fromRegistry.Value > adapterRam.Value
                            ? fromRegistry.Value - adapterRam.Value
                            : adapterRam.Value - fromRegistry.Value;

                        if (diff > 64UL * 1024UL * 1024UL)
                        {
                            ctx.AddInconsistency("VRAM de " + (g.Name == null ? "GPU" : g.Name),
                                "Registro e WMI reportam quantidades diferentes de memoria de video.",
                                Severity.Low,
                                Evidence.Of("Registry", "HardwareInformation.qwMemorySize", fromRegistry.Value),
                                Evidence.Of("WMI", "Win32_VideoController.AdapterRAM", adapterRam.Value));
                        }
                    }
                }
                return;
            }

            if (adapterRam.HasValue && adapterRam.Value > 0)
            {
                if (adapterRam.Value >= 4293918720U)
                {
                    // Saturou o DWORD: o numero nao significa nada. Reportar
                    // ausencia com motivo e melhor do que reportar "4 GB" falso.
                    g.VramBytes = null;
                    g.VramSource = "Indisponivel: WMI saturou em 32 bits e o registro nao informou o valor real";
                }
                else
                {
                    g.VramBytes = adapterRam.Value;
                    g.VramSource = "WMI (AdapterRAM, 32 bits - confiavel apenas abaixo de 4 GB)";
                }
                return;
            }

            g.VramSource = "Nao informado por nenhuma fonte";
        }

        private static bool IsGenericDriver(GpuInfo g)
        {
            string provider = g.DriverProvider == null ? "" : g.DriverProvider;
            string name = g.Name == null ? "" : g.Name;

            if (name.IndexOf("Microsoft Basic Display", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            if (name.IndexOf("Standard VGA", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            if (provider.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        // Classificacao integrada x dedicada.
        //
        // O identificador de fabricante (VEN_) e estavel; o nome comercial nao.
        // Onde o VEN_ resolve sozinho, KindSource = "VendorId". Onde nao
        // resolve (AMD, que usa o mesmo VEN_1002 para APU e placa dedicada),
        // usa-se o barramento PCI e depois o nome - e isso fica REGISTRADO na
        // saida, para o tecnico saber quanto confiar.
        public static void Classify(GpuInfo g, object registryMatch)
        {
            string name = g.Name == null ? "" : g.Name;
            string vendor = g.PciVendorId == null ? "" : g.PciVendorId.ToUpperInvariant();

            if (vendor == "10DE")
            {
                g.Kind = "Dedicada";
                g.KindSource = "PCI VendorId (NVIDIA)";
                return;
            }

            if (vendor == "8086")
            {
                // A unica linha dedicada da Intel e a Arc.
                bool arc = name.IndexOf("Arc", StringComparison.OrdinalIgnoreCase) >= 0;
                g.Kind = arc ? "Dedicada" : "Integrada";
                g.KindSource = arc ? "PCI VendorId + linha Arc" : "PCI VendorId (Intel, nao Arc)";
                return;
            }

            if (vendor == "1002" || vendor == "1022")
            {
                // AMD usa o mesmo VendorId para APU e placa dedicada.
                bool discreteName =
                    name.IndexOf(" RX ", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    name.IndexOf("Radeon Pro", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    name.IndexOf("FirePro", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    name.IndexOf("Radeon VII", StringComparison.OrdinalIgnoreCase) >= 0;

                bool integratedName =
                    name.IndexOf("Vega", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    name.IndexOf("Graphics", StringComparison.OrdinalIgnoreCase) >= 0;
                if (name.IndexOf("(TM) Graphics", StringComparison.OrdinalIgnoreCase) >= 0) integratedName = true;

                if (discreteName && !integratedName)
                {
                    g.Kind = "Dedicada";
                    g.KindSource = "Heuristica de nome (AMD)";
                }
                else if (integratedName)
                {
                    g.Kind = "Integrada";
                    g.KindSource = "Heuristica de nome (AMD APU)";
                }
                else
                {
                    g.Kind = "Indeterminado";
                    g.KindSource = "AMD sem sinal conclusivo - confirmar visualmente";
                }
                return;
            }

            if (vendor == "15AD" || vendor == "80EE" || vendor == "1414" || vendor == "1AF4")
            {
                g.Kind = "Virtual";
                g.KindSource = "PCI VendorId (adaptador de maquina virtual)";
                return;
            }

            g.Kind = "Indeterminado";
            g.KindSource = "Fabricante nao catalogado";
        }

        // Extrai (device, function) do caminho PCI real, de duas formas de
        // texto diferentes:
        //  - LocationInformation do registro, tipicamente "PCI bus N, device
        //    N, function N";
        //  - PNPDeviceID da WMI, cujo ultimo segmento de instancia codifica
        //    device/function num par hex de 4 digitos (convencao do Windows
        //    para PDO de PCI: valor = (device << 3) | function).
        private static readonly Regex LocationDeviceFunctionRegex =
            new Regex(@"device\s+(?<dev>\d+)\D+function\s+(?<func>\d+)", RegexOptions.IgnoreCase);

        public static bool TryParsePciDeviceFunction(string text, out int device, out int function)
        {
            device = -1;
            function = -1;
            if (string.IsNullOrEmpty(text)) return false;

            Match m = LocationDeviceFunctionRegex.Match(text);
            if (m.Success)
            {
                return int.TryParse(m.Groups["dev"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out device) &&
                       int.TryParse(m.Groups["func"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out function);
            }

            // Formato PNPDeviceID: "...\<algo>&<algo>&<algo>&FFFF" onde FFFF
            // e o ultimo segmento, hexadecimal de 4 digitos.
            int lastSlash = text.LastIndexOf('\\');
            string instance = lastSlash >= 0 && lastSlash < text.Length - 1 ? text.Substring(lastSlash + 1) : text;
            string[] parts = instance.Split('&');
            string tail = parts[parts.Length - 1];
            if (tail.Length != 4) return false;

            int devFunc;
            if (!int.TryParse(tail, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out devFunc)) return false;

            device = devFunc >> 3;
            function = devFunc & 0x7;
            return true;
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
