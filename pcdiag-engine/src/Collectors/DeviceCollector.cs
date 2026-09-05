using System;
using System.Collections.Generic;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    // Levantamento de dispositivos e drivers.
    //
    // Duas fontes independentes, de proposito:
    //  - SetupAPI/CfgMgr32 (nativo): enxerga TODOS os dispositivos, inclusive
    //    os ocultos/fantasma que a WMI nao lista. E onde ficam restos de driver
    //    de hardware ja trocado, que explicam conflito de recurso (Code 12).
    //  - Win32_PnPEntity (WMI): confirma o codigo de erro por outro caminho.
    //
    // Quando as duas discordam sobre um dispositivo, isso vira inconsistencia
    // registrada, nao um lado escolhido silenciosamente.
    public sealed class DeviceCollector : ICollector
    {
        public string Name { get { return "Devices"; } }

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            Dictionary<string, DeviceInfo> byId = new Dictionary<string, DeviceInfo>(StringComparer.OrdinalIgnoreCase);

            CollectNative(ctx, inv, byId);
            CollectWmi(ctx, src, inv, byId);
            CollectDrivers(ctx, src, inv);
        }

        private void CollectNative(ScanContext ctx, Inventory inv, Dictionary<string, DeviceInfo> byId)
        {
            IList<NativeDevice> native = Try.Get(ctx, Name, "SetupAPI EnumerateDevices", delegate
            {
                return Native.EnumerateDevices(true);
            });

            // Este flag indica se a fonte nativa (SetupAPI/CfgMgr32)
            // respondeu. Quando falha (ex.: cfgmgr32.dll sequestrada, ou
            // qualquer excecao), o inventario de dispositivos fica
            // preenchido apenas pela WMI (CollectWmi roda em seguida), e o
            // flag deixa isso explicito no inventario. DEV-001 usa este
            // flag para nao citar "SetupAPI" como evidencia nem reivindicar
            // confianca de duas fontes concordando quando so uma rodou.
            inv.DevicesNativeSourceAvailable = native != null;
            if (native == null)
            {
                inv.DevicesNativeSourceUnavailableReason = "Consulta nativa SetupAPI/CfgMgr32 falhou (ver errors.log) - inventario de dispositivos vem so da WMI, sem cross-check.";
                return;
            }

            foreach (NativeDevice n in native)
            {
                if (n.InstanceId == null) continue;

                DeviceInfo d = new DeviceInfo();
                d.InstanceId = n.InstanceId;
                d.Name = Helpers.FirstNonEmpty(n.FriendlyName, n.Description, n.InstanceId);
                d.Class = n.Class;
                d.Manufacturer = SystemCollector.IsPlaceholder(n.Manufacturer) ? null : n.Manufacturer;
                d.Service = n.Service;
                d.HardwareIds = n.HardwareIds;
                d.LocationInfo = n.LocationInfo;
                d.Enumerator = n.Enumerator;
                d.IsPresent = n.IsPresent;
                d.IsHidden = !n.IsPresent;
                d.Source = "SetupAPI";

                if (n.HasProblem && n.ProblemCode != 0)
                {
                    d.ProblemCode = n.ProblemCode;
                    d.ProblemMeaning = Native.ProblemCodeMeaning(n.ProblemCode);
                    d.IsAdministrativeChoice = Native.IsCodeAdministrativeChoice(n.ProblemCode);
                    d.IsHardwareSuspect = Native.IsCodeHardwareSuspect(n.ProblemCode);
                }

                inv.Devices.Add(d);
                byId[d.InstanceId] = d;
            }
        }

        private void CollectWmi(ScanContext ctx, SourceSet src, Inventory inv, Dictionary<string, DeviceInfo> byId)
        {
            IList<DataRow> rows = Try.Get(ctx, Name, "Win32_PnPEntity", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT DeviceID, Name, PNPClass, Manufacturer, Service, Status, ConfigManagerErrorCode FROM Win32_PnPEntity");
            });

            if (rows == null)
            {
                // WMI indisponivel nao pode virar "nenhum dispositivo com
                // problema". O modulo registra a falha e a camada de testes
                // reporta confianca reduzida.
                ctx.Log.Warn(Name, "Win32_PnPEntity indisponivel - deteccao de dispositivos ficou apoiada apenas na SetupAPI.");
                return;
            }

            foreach (DataRow r in rows)
            {
                string id = r.Str("DeviceID");
                if (id == null) continue;

                int? cmCode = r.Int("ConfigManagerErrorCode");
                uint problem = (cmCode.HasValue && cmCode.Value > 0) ? (uint)cmCode.Value : 0;

                DeviceInfo existing;
                if (byId.TryGetValue(id, out existing))
                {
                    existing.Source = "SetupAPI + WMI";
                    if (existing.Name == null) existing.Name = r.Str("Name");
                    if (existing.Class == null) existing.Class = r.Str("PNPClass");
                    if (existing.Manufacturer == null && !SystemCollector.IsPlaceholder(r.Str("Manufacturer")))
                        existing.Manufacturer = r.Str("Manufacturer");

                    uint nativeProblem = existing.ProblemCode.HasValue ? existing.ProblemCode.Value : 0;
                    if (nativeProblem != problem)
                    {
                        ctx.AddInconsistency("Codigo de problema de '" + existing.Name + "'",
                            "SetupAPI e WMI reportam codigos diferentes para o mesmo dispositivo.",
                            Severity.Low,
                            Evidence.Of("Native", "CM_Get_DevNode_Status", nativeProblem),
                            Evidence.Of("WMI", "Win32_PnPEntity.ConfigManagerErrorCode", problem));

                        // Na duvida, prevalece o codigo diferente de zero: e
                        // pior deixar de reportar um problema real do que
                        // reportar um a mais com a divergencia registrada.
                        if (problem != 0 && nativeProblem == 0)
                        {
                            existing.ProblemCode = problem;
                            existing.ProblemMeaning = Native.ProblemCodeMeaning(problem);
                            existing.IsAdministrativeChoice = Native.IsCodeAdministrativeChoice(problem);
                            existing.IsHardwareSuspect = Native.IsCodeHardwareSuspect(problem);
                        }
                    }
                    continue;
                }

                DeviceInfo d = new DeviceInfo();
                d.InstanceId = id;
                d.Name = r.Str("Name");
                d.Class = r.Str("PNPClass");
                d.Manufacturer = SystemCollector.IsPlaceholder(r.Str("Manufacturer")) ? null : r.Str("Manufacturer");
                d.Service = r.Str("Service");
                d.IsPresent = true;
                d.Source = "WMI";

                if (problem != 0)
                {
                    d.ProblemCode = problem;
                    d.ProblemMeaning = Native.ProblemCodeMeaning(problem);
                    d.IsAdministrativeChoice = Native.IsCodeAdministrativeChoice(problem);
                    d.IsHardwareSuspect = Native.IsCodeHardwareSuspect(problem);
                }

                inv.Devices.Add(d);
                byId[id] = d;
            }
        }

        private void CollectDrivers(ScanContext ctx, SourceSet src, Inventory inv)
        {
            // Win32_PnPSignedDriver e notoriamente lenta (dezenas de segundos
            // em algumas maquinas). Roda dentro do timeout do modulo; se
            // estourar, o restante do inventario ja coletado permanece valido.
            IList<DataRow> rows = Try.Get(ctx, Name, "Win32_PnPSignedDriver", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT DeviceName, DeviceClass, DriverProviderName, DriverVersion, DriverDate, InfName, IsSigned FROM Win32_PnPSignedDriver");
            });

            if (rows == null) return;

            foreach (DataRow r in rows)
            {
                string deviceName = r.Str("DeviceName");
                if (deviceName == null) continue;

                DriverInfo d = new DriverInfo();
                d.DeviceName = deviceName;
                d.DeviceClass = r.Str("DeviceClass");
                d.Provider = r.Str("DriverProviderName");
                d.Version = r.Str("DriverVersion");
                d.Date = r.Date("DriverDate");
                d.AgeYears = Helpers.YearsSince(d.Date);
                d.InfName = r.Str("InfName");
                d.IsSigned = r.Bool("IsSigned");

                // Driver "generico da Microsoft": funciona, mas normalmente sem
                // os recursos especificos do fabricante. E um achado de
                // configuracao, nao um defeito - a classificacao acontece na
                // camada de testes.
                d.IsMicrosoftGeneric = d.Provider != null &&
                    d.Provider.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;

                inv.Drivers.Add(d);
            }
        }
    }
}
