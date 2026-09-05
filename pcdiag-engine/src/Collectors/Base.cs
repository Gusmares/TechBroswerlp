using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    // Conjunto de fontes injetado nos collectors. Trocar por fakes nos testes
    // e o que permite testar coleta e diagnostico sem hardware real.
    public sealed class SourceSet
    {
        public IWmiSource Wmi { get; set; }
        public IRegistrySource Registry { get; set; }
        public IEventLogSource EventLog { get; set; }
        public IProcessRunner Processes { get; set; }
        public SensorSource Sensors { get; set; }
    }

    // Um collector so COLETA e NORMALIZA. Nunca decide se algo esta bom ou
    // ruim - isso e responsabilidade exclusiva da camada de Tests.
    public interface ICollector
    {
        string Name { get; }
        void Collect(ScanContext ctx, SourceSet src, Inventory inv);
    }

    public static class Helpers
    {
        public static double? YearsSince(DateTime? date)
        {
            if (!date.HasValue) return null;
            double years = (DateTime.Now - date.Value).TotalDays / 365.25;
            if (years < 0) return null;         // data no futuro = dado invalido
            if (years > 60) return null;        // 1601/1980 default de firmware
            return Math.Round(years, 1);
        }

        public static bool IsPlausibleTemperature(double? c)
        {
            return c.HasValue && c.Value > 0 && c.Value < 130;
        }

        // Extrai VEN_/DEV_/SUBSYS_ de um PNPDeviceID ou HardwareID.
        // Ex: "PCI\VEN_10DE&DEV_2504&SUBSYS_40BD1458&REV_A1\4&..."
        private static readonly Regex PciRegex = new Regex(
            @"VEN_(?<ven>[0-9A-Fa-f]{4})(&DEV_(?<dev>[0-9A-Fa-f]{4}))?(&SUBSYS_(?<sub>[0-9A-Fa-f]{8}))?",
            RegexOptions.Compiled);

        public sealed class PciIds
        {
            public string VendorId { get; set; }
            public string DeviceId { get; set; }
            public string SubsystemId { get; set; }
        }

        public static PciIds ParsePciIds(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;
            Match m = PciRegex.Match(id);
            if (!m.Success) return null;

            PciIds r = new PciIds();
            r.VendorId = m.Groups["ven"].Success ? m.Groups["ven"].Value.ToUpperInvariant() : null;
            r.DeviceId = m.Groups["dev"].Success ? m.Groups["dev"].Value.ToUpperInvariant() : null;
            r.SubsystemId = m.Groups["sub"].Success ? m.Groups["sub"].Value.ToUpperInvariant() : null;
            return r;
        }

        // Extrai o codigo de classe PCI (campo CC_) de uma lista de
        // HardwareID separada por " | " (formato gravado em
        // DeviceInfo.HardwareIds - ver Native.GetStringProperty, que junta o
        // REG_MULTI_SZ do SPDRP_HARDWAREID com esse separador).
        //
        // Para um dispositivo PCI o Windows gera a lista de HardwareID da
        // mais especifica para a mais generica, e as duas ultimas entradas
        // SEMPRE trazem o codigo de classe: "VEN_v&DEV_d&CC_ccssp" (classe +
        // subclasse + prog-if, 6 digitos) e "VEN_v&DEV_d&CC_ccss" (classe +
        // subclasse, 4 digitos) - documentado pela Microsoft em "PCI Devices"
        // (formato de Hardware IDs). E assim que ChipsetCollector acha a
        // ponte ISA/LPC (classe 0601) ou o controlador USB XHCI (classe
        // 0C03) sem precisar presumir bus/device/function.
        private static readonly Regex PciClassRegex = new Regex(
            @"CC_(?<cc>[0-9A-Fa-f]{4,6})", RegexOptions.Compiled);

        public static bool HasPciClassCode(string hardwareIds, string classCode)
        {
            if (string.IsNullOrEmpty(hardwareIds) || string.IsNullOrEmpty(classCode)) return false;

            foreach (Match m in PciClassRegex.Matches(hardwareIds))
            {
                string cc = m.Groups["cc"].Value;
                if (cc.StartsWith(classCode, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        public static string PciVendorName(string vendorId)
        {
            if (string.IsNullOrEmpty(vendorId)) return null;
            switch (vendorId.ToUpperInvariant())
            {
                case "8086": return "Intel";
                case "10DE": return "NVIDIA";
                case "1002": return "AMD/ATI";
                case "1022": return "AMD";
                case "1414": return "Microsoft";
                case "15AD": return "VMware";
                case "80EE": return "Oracle VirtualBox";
                case "1AF4": return "Red Hat / VirtIO";
                case "5333": return "S3 Graphics";
                case "102B": return "Matrox";
                default: return null;
            }
        }

        // Caminhos de onde executavel de servico legitimo normalmente NAO roda.
        // Usado como indicador heuristico - nunca como acusacao de malware.
        //
        // ProgramData NAO entra nesta lista, apesar de parecer um bom candidato:
        // o proprio Windows Defender instala seus binarios em
        // C:\ProgramData\Microsoft\Windows Defender\Platform\<versao>\ porque se
        // atualiza fora do Windows Update. Incluir ProgramData fazia a
        // ferramenta acusar o Defender de suspeito - um falso positivo que, no
        // limite, levaria um tecnico a desativar a protecao da maquina.
        // (Confirmado rodando a ferramenta nesta maquina.)
        public static bool IsUnusualExecutableLocation(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string p = path.ToLowerInvariant().Replace('/', '\\');
            p = p.Trim('"', ' ');

            string[] suspicious = new string[]
            {
                @"\appdata\local\temp\",
                @"\appdata\roaming\",
                @"\appdata\local\packages\",
                @"\windows\temp\",
                @"\users\public\",
                @"\$recycle.bin\",
                @"\downloads\",
                @"\temp\",
                @"\tmp\"
            };

            foreach (string s in suspicious)
            {
                if (p.IndexOf(s, StringComparison.Ordinal) >= 0) return true;
            }
            return false;
        }

        // Enumeradores que nao representam hardware fisico. HTREE e a raiz da
        // arvore de dispositivos (HTREE\ROOT\0 existe em toda maquina), e
        // SW/SWD sao dispositivos puramente logicos. Nenhum deles tem driver
        // ou classe, entao a heuristica de "dispositivo desconhecido" precisa
        // ignora-los - senao acusa um falso positivo em 100% das maquinas.
        public static bool IsPseudoEnumerator(string enumerator, string instanceId)
        {
            string source = Helpers.FirstNonEmpty(enumerator, instanceId);
            if (source == null) return false;

            string s = source.ToUpperInvariant();
            return s.StartsWith("HTREE", StringComparison.Ordinal)
                || s.StartsWith("SW\\", StringComparison.Ordinal)
                || s.Equals("SW", StringComparison.Ordinal)
                || s.StartsWith("SWD", StringComparison.Ordinal)
                || s.StartsWith("UMB", StringComparison.Ordinal);
        }

        // Extrai o caminho do executavel de uma linha de comando de servico,
        // que pode vir com aspas e argumentos.
        public static string ExtractExecutablePath(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine)) return null;
            string s = commandLine.Trim();

            if (s.StartsWith("\"", StringComparison.Ordinal))
            {
                int end = s.IndexOf('"', 1);
                if (end > 1) return s.Substring(1, end - 1);
                return s.Trim('"');
            }

            int ext = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (ext > 0) return s.Substring(0, ext + 4);

            int space = s.IndexOf(' ');
            return space > 0 ? s.Substring(0, space) : s;
        }

        public static string NormalizeDriveLetter(string s)
        {
            if (string.IsNullOrEmpty(s)) return null;
            s = s.Trim();
            if (s.Length >= 2 && s[1] == ':') return s.Substring(0, 2).ToUpperInvariant();
            if (s.Length == 1 && char.IsLetter(s[0])) return char.ToUpperInvariant(s[0]) + ":";
            return null;
        }

        public static int? ParseIntSafe(string s)
        {
            if (string.IsNullOrEmpty(s)) return null;
            int v;
            if (int.TryParse(s.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out v)) return v;
            return null;
        }

        public static string FirstNonEmpty(params string[] values)
        {
            if (values == null) return null;
            foreach (string v in values)
            {
                if (!string.IsNullOrEmpty(v) && v.Trim().Length > 0) return v.Trim();
            }
            return null;
        }

        public static DataRow FirstRow(IList<DataRow> rows)
        {
            return (rows != null && rows.Count > 0) ? rows[0] : null;
        }
    }
}
