using System;
using System.Collections.Generic;
using System.Globalization;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    public sealed class SystemCollector : ICollector
    {
        public string Name { get { return "System"; } }

        private static readonly int[] PortableChassis = new int[] { 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32 };

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            CollectMachine(ctx, src, inv);
            CollectOs(ctx, src, inv);
            CollectFirmware(ctx, src, inv);
        }

        private void CollectMachine(ScanContext ctx, SourceSet src, Inventory inv)
        {
            MachineInfo m = inv.Machine;

            DataRow cs = Helpers.FirstRow(Try.Get(ctx, Name, "Win32_ComputerSystem",
                delegate { return src.Wmi.Query(WmiSource.CimV2, "SELECT Manufacturer, Model, SystemFamily, Name, UserName, Domain, PartOfDomain, HypervisorPresent FROM Win32_ComputerSystem"); }));

            if (cs != null)
            {
                m.Manufacturer = cs.Str("Manufacturer");
                m.Model = cs.Str("Model");
                m.SystemFamily = cs.Str("SystemFamily");
                m.Hostname = cs.Str("Name");
                m.LoggedUser = cs.Str("UserName");
                m.Domain = cs.Str("Domain");
                m.PartOfDomain = cs.Bool("PartOfDomain");
            }
            if (m.Hostname == null) m.Hostname = ctx.MachineNameRaw;

            DataRow enc = Helpers.FirstRow(Try.Get(ctx, Name, "Win32_SystemEnclosure",
                delegate { return src.Wmi.Query(WmiSource.CimV2, "SELECT ChassisTypes, SerialNumber FROM Win32_SystemEnclosure"); }));

            if (enc != null)
            {
                object types = enc.Raw("ChassisTypes");
                int? first = null;
                ushort[] us = types as ushort[];
                if (us != null && us.Length > 0) first = us[0];
                else
                {
                    int[] ints = types as int[];
                    if (ints != null && ints.Length > 0) first = ints[0];
                }
                m.ChassisType = first;
                if (first.HasValue)
                {
                    m.IsPortable = Array.IndexOf(PortableChassis, first.Value) >= 0;
                    m.FormFactor = ChassisName(first.Value);
                }
                m.SerialNumber = enc.Str("SerialNumber");
            }

            DataRow board = Helpers.FirstRow(Try.Get(ctx, Name, "Win32_BaseBoard",
                delegate { return src.Wmi.Query(WmiSource.CimV2, "SELECT Manufacturer, Product, Version, SerialNumber FROM Win32_BaseBoard"); }));

            if (board != null)
            {
                m.BoardManufacturer = board.Str("Manufacturer");
                m.BoardProduct = board.Str("Product");
                m.BoardVersion = board.Str("Version");
                m.BoardSerialNumber = board.Str("SerialNumber");
            }

            // Serial: preferir o do chassi; cair para o da BIOS. Alguns OEM
            // preenchem so um dos dois, e valores de template ("To be filled
            // by O.E.M.", "Default string") sao descartados em vez de virarem
            // um numero de serie falso no laudo.
            DataRow bios = Helpers.FirstRow(Try.Get(ctx, Name, "Win32_BIOS",
                delegate { return src.Wmi.Query(WmiSource.CimV2, "SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SerialNumber FROM Win32_BIOS"); }));

            if (bios != null && IsPlaceholder(m.SerialNumber)) m.SerialNumber = bios.Str("SerialNumber");
            if (IsPlaceholder(m.SerialNumber)) m.SerialNumber = null;
            if (IsPlaceholder(m.BoardSerialNumber)) m.BoardSerialNumber = null;
            if (IsPlaceholder(m.Model)) m.Model = null;
            if (IsPlaceholder(m.Manufacturer)) m.Manufacturer = null;

            DetectVirtualMachine(ctx, src, inv, cs);

            if (bios != null)
            {
                inv.Firmware.Manufacturer = bios.Str("Manufacturer");
                inv.Firmware.Version = bios.Str("SMBIOSBIOSVersion");
                inv.Firmware.ReleaseDate = bios.Date("ReleaseDate");
                inv.Firmware.AgeYears = Helpers.YearsSince(inv.Firmware.ReleaseDate);
            }
        }

        // Valores de template que fabricantes deixam no SMBIOS. Apresentar
        // isso como numero de serie real e desinformar o tecnico.
        public static bool IsPlaceholder(string s)
        {
            if (string.IsNullOrEmpty(s)) return true;
            string v = s.Trim().ToLowerInvariant();
            if (v.Length == 0) return true;

            string[] known = new string[]
            {
                "to be filled by o.e.m.", "to be filled by oem", "default string",
                "system serial number", "none", "n/a", "na",
                "not specified", "not applicable", "0123456789", "chassis serial number",
                "base board serial number", "invalid", "unknown", "x.x.x",
                "oem", "o.e.m.", "system manufacturer", "system product name"
            };

            foreach (string k in known)
            {
                if (v == k) return true;
            }

            // Sequencias degeneradas: "0000000", ".....", "        "
            bool allSame = true;
            for (int i = 1; i < v.Length; i++)
            {
                if (v[i] != v[0]) { allSame = false; break; }
            }
            return allSame;
        }

        private void DetectVirtualMachine(ScanContext ctx, SourceSet src, Inventory inv, DataRow cs)
        {
            MachineInfo m = inv.Machine;
            string hay = ((m.Manufacturer == null ? "" : m.Manufacturer) + " " +
                          (m.Model == null ? "" : m.Model) + " " +
                          (m.BoardProduct == null ? "" : m.BoardProduct)).ToLowerInvariant();

            string[][] hints = new string[][]
            {
                new string[] { "vmware", "VMware" },
                new string[] { "virtualbox", "VirtualBox" },
                new string[] { "kvm", "KVM" },
                new string[] { "qemu", "QEMU" },
                new string[] { "xen", "Xen" },
                new string[] { "parallels", "Parallels" },
                new string[] { "virtual machine", "Hyper-V" },
                new string[] { "bochs", "Bochs" }
            };

            foreach (string[] h in hints)
            {
                if (hay.IndexOf(h[0], StringComparison.Ordinal) >= 0)
                {
                    m.IsVirtualMachine = true;
                    m.VirtualizationHint = h[1];
                    return;
                }
            }

            m.IsVirtualMachine = false;
        }

        private void CollectOs(ScanContext ctx, SourceSet src, Inventory inv)
        {
            OsInfo os = inv.Os;

            DataRow r = Helpers.FirstRow(Try.Get(ctx, Name, "Win32_OperatingSystem",
                delegate
                {
                    return src.Wmi.Query(WmiSource.CimV2,
                        "SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, Locale, OSLanguage FROM Win32_OperatingSystem");
                }));

            if (r != null)
            {
                os.Caption = r.Str("Caption");
                os.Version = r.Str("Version");
                os.BuildNumber = Helpers.ParseIntSafe(r.Str("BuildNumber"));
                os.Architecture = r.Str("OSArchitecture");
                os.InstallDate = r.Date("InstallDate");
                os.LastBootTime = r.Date("LastBootUpTime");
                if (os.LastBootTime.HasValue)
                {
                    double h = (DateTime.Now - os.LastBootTime.Value).TotalHours;
                    if (h >= 0 && h < 24 * 365 * 5) os.UptimeHours = Math.Round(h, 1);
                }
                os.Locale = r.Str("Locale");
            }

            if (os.Architecture == null) os.Architecture = Environment.Is64BitOperatingSystem ? "64 bits" : "32 bits";

            // DisplayVersion (22H2, 23H2...) e UBR so existem no registro.
            const string cv = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
            os.DisplayVersion = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", cv, "DisplayVersion"));
            if (os.DisplayVersion == null) os.DisplayVersion = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", cv, "ReleaseId"));
            os.Ubr = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", cv, "UBR"));
            os.Edition = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", cv, "EditionID"));

            try { os.TimeZone = TimeZoneInfo.Local.StandardName; }
            catch { }

            CollectActivation(ctx, src, os);
            CollectUpdates(ctx, src, os);
        }

        private void CollectActivation(ScanContext ctx, SourceSet src, OsInfo os)
        {
            IList<DataRow> lic = Try.Get(ctx, Name, "SoftwareLicensingProduct", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT LicenseStatus, Description, PartialProductKey, GracePeriodRemaining FROM SoftwareLicensingProduct " +
                    "WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL");
            });

            if (lic == null || lic.Count == 0)
            {
                os.ActivationStatus = "Nao determinado";
                return;
            }

            DataRow row = lic[0];
            int? status = row.Int("LicenseStatus");
            os.ActivationStatus = LicenseStatusName(status);
            os.IsActivated = status.HasValue && status.Value == 1;

            string desc = row.Str("Description");
            if (desc != null)
            {
                if (desc.IndexOf("OEM", StringComparison.OrdinalIgnoreCase) >= 0) os.LicenseChannel = "OEM";
                else if (desc.IndexOf("VOLUME", StringComparison.OrdinalIgnoreCase) >= 0) os.LicenseChannel = "Volume";
                else if (desc.IndexOf("RETAIL", StringComparison.OrdinalIgnoreCase) >= 0) os.LicenseChannel = "Retail";
                else os.LicenseChannel = "Outro";
            }
        }

        public static string LicenseStatusName(int? status)
        {
            if (!status.HasValue) return "Nao determinado";
            switch (status.Value)
            {
                case 0: return "Nao licenciado";
                case 1: return "Ativado";
                case 2: return "Periodo de carencia inicial (OOB)";
                case 3: return "Periodo de carencia (OOT)";
                case 4: return "Nao genuino";
                case 5: return "Notificacao (nao ativado)";
                case 6: return "Carencia estendida";
                default: return "Status desconhecido (" + status.Value + ")";
            }
        }

        private void CollectUpdates(ScanContext ctx, SourceSet src, OsInfo os)
        {
            IList<DataRow> qfe = Try.Get(ctx, Name, "Win32_QuickFixEngineering", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2, "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering");
            });

            if (qfe == null) return;

            os.UpdatesInstalledCount = qfe.Count;
            DateTime? newest = null;
            string newestId = null;

            foreach (DataRow row in qfe)
            {
                DateTime? d = row.Date("InstalledOn");
                if (!d.HasValue) continue;
                if (!newest.HasValue || d.Value > newest.Value)
                {
                    newest = d;
                    newestId = row.Str("HotFixID");
                }
            }

            os.LastUpdateInstalled = newest;
            os.LastUpdateId = newestId;
        }

        private void CollectFirmware(ScanContext ctx, SourceSet src, Inventory inv)
        {
            FirmwareInfo f = inv.Firmware;

            // Fonte autoritativa: API nativa. Nao depende de idioma nem de
            // privilegio, ao contrario do parsing de bcdedit.
            Native.FirmwareType? ft = Native.GetFirmware();
            if (ft.HasValue)
            {
                f.FirmwareType = ft.Value == Native.FirmwareType.Uefi ? "UEFI"
                    : ft.Value == Native.FirmwareType.Bios ? "Legacy BIOS" : "Desconhecido";
                f.FirmwareTypeSource = "GetFirmwareType (API nativa)";
            }

            // Cross-check independente: a chave SecureBoot\State so existe em
            // maquina UEFI.
            bool secureBootKeyExists = false;
            // Uma ACL endurecida em SYSTEM\CurrentControlSet\Control (politica
            // corporativa, hive parcialmente corrompida) pode fazer KeyExists
            // lancar excecao. Sem guardar o resultado da leitura em separado,
            // secureBootKeyExists ficaria false do mesmo jeito que ficaria se
            // a chave genuinamente nao existisse - os dois casos seriam
            // indistinguiveis e o laudo afirmaria "Secure Boot NaoSuportado"
            // mesmo quando a leitura simplesmente falhou.
            bool secureBootReadOk = Try.Do(ctx, Name, "SecureBoot\\State", delegate
            {
                secureBootKeyExists = src.Registry.KeyExists("HKLM", @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            });

            if (f.FirmwareType == null)
            {
                f.FirmwareType = secureBootReadOk && secureBootKeyExists ? "UEFI" : "Desconhecido";
                f.FirmwareTypeSource = secureBootReadOk && secureBootKeyExists ? "Registro (SecureBoot\\State existe)" : "Indeterminado";
            }
            else if (secureBootReadOk && secureBootKeyExists && f.FirmwareType == "Legacy BIOS")
            {
                ctx.AddInconsistency("Modo de firmware",
                    "GetFirmwareType() reportou Legacy BIOS, mas a chave SecureBoot\\State (que so existe em UEFI) esta presente.",
                    Severity.Medium,
                    Evidence.Of("Native", "GetFirmwareType()", "Bios"),
                    Evidence.Of("Registry", @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "existe"));
            }

            // Secure Boot: separar DESATIVADO de NAO SUPORTADO de LEITURA
            // FALHOU/SEM ACESSO - tres estados, nao dois.
            if (!secureBootReadOk)
            {
                f.SecureBootState = ctx.IsElevated ? "Desconhecido (falha ao ler o registro)" : "RequerAdministrador";
            }
            else if (!secureBootKeyExists)
            {
                f.SecureBootState = f.FirmwareType == "Legacy BIOS" ? "NaoSuportado (modo Legacy)" : "NaoSuportado";
            }
            else
            {
                object v = RegistryWalk.ValueSafe(src.Registry, "HKLM", @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
                if (v == null) f.SecureBootState = ctx.IsElevated ? "Desconhecido" : "RequerAdministrador";
                else f.SecureBootState = Convert.ToInt32(v, CultureInfo.InvariantCulture) == 1 ? "Ativado" : "Desativado";
            }

            CollectTpm(ctx, src, f);
        }

        private void CollectTpm(ScanContext ctx, SourceSet src, FirmwareInfo f)
        {
            // root\CIMV2\Security\MicrosoftTpm exige elevacao - sem admin
            // a consulta sempre falha, mas so
            // depois de pagar o custo total do handshake WMI/DCOM com o
            // namespace de seguranca. Medido em execucao real sem elevacao:
            // so o modulo System consumiu 5,86s dos 15,0s do orcamento
            // padrao do scan por causa desta chamada, que a propria
            // ferramenta ja sabe de antemao que vai falhar. Evita tocar na
            // WMI quando nao elevado.
            if (!ctx.IsElevated)
            {
                f.TpmPresent = null;
                f.TpmVersion = "RequerAdministrador";
                return;
            }

            IList<DataRow> tpm = Try.Get(ctx, Name, "Win32_Tpm", delegate
            {
                return src.Wmi.Query(@"root\CIMV2\Security\MicrosoftTpm",
                    "SELECT IsEnabled_InitialValue, IsActivated_InitialValue, SpecVersion, ManufacturerVersion FROM Win32_Tpm");
            });

            if (tpm == null)
            {
                // Elevado mas a consulta falhou por outro motivo (namespace
                // ausente nesta edicao do Windows, por exemplo).
                f.TpmPresent = null;
                return;
            }

            if (tpm.Count == 0)
            {
                f.TpmPresent = false;
                return;
            }

            f.TpmPresent = true;
            f.TpmEnabled = tpm[0].Bool("IsEnabled_InitialValue");
            f.TpmActivated = tpm[0].Bool("IsActivated_InitialValue");

            string spec = tpm[0].Str("SpecVersion");
            if (spec != null)
            {
                string[] parts = spec.Split(',');
                f.TpmVersion = parts.Length > 0 ? parts[0].Trim() : spec;
            }
        }

        private static string AsString(object v)
        {
            if (v == null) return null;
            string s = Convert.ToString(v, CultureInfo.InvariantCulture);
            if (s == null) return null;
            s = s.Trim();
            return s.Length == 0 ? null : s;
        }

        public static string ChassisName(int type)
        {
            switch (type)
            {
                case 3: return "Desktop";
                case 4: return "Low Profile Desktop";
                case 5: return "Pizza Box";
                case 6: return "Mini Tower";
                case 7: return "Tower";
                case 8: return "Portatil";
                case 9: return "Notebook";
                case 10: return "Sub Notebook";
                case 11: return "Hand Held";
                case 12: return "Docking Station";
                case 13: return "All in One";
                case 14: return "Sub Notebook";
                case 15: return "Space-saving";
                case 16: return "Lunch Box";
                case 17: return "Main System Chassis";
                case 18: return "Expansion Chassis";
                case 21: return "Peripheral Chassis";
                case 23: return "Rack Mount Chassis";
                case 24: return "Sealed-case PC";
                case 30: return "Tablet";
                case 31: return "Conversivel";
                case 32: return "Destacavel";
                default: return "Tipo " + type;
            }
        }
    }
}
