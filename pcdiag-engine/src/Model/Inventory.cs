using System;
using System.Collections.Generic;
using System.Reflection;
using PcDiag.Core;

namespace PcDiag.Model
{
    // Regra do modelo: todo campo mensuravel e ANULAVEL (int?, double?, bool?).
    //
    // null significa exatamente "nao foi possivel obter" e nunca zero, nunca
    // string de aviso. Quem consome decide como apresentar a ausencia, e o
    // relatorio nunca pode transformar ausencia em afirmacao de saude.
    // Nenhum campo aqui guarda texto formatado para exibicao ("32 GB", "45%") -
    // formatacao e responsabilidade exclusiva da camada de relatorio.

    public sealed class Inventory
    {
        public Inventory()
        {
            Machine = new MachineInfo();
            Os = new OsInfo();
            Firmware = new FirmwareInfo();
            Cpu = new CpuInfo();
            Memory = new MemoryInfo();
            Gpus = new List<GpuInfo>();
            Disks = new List<DiskInfo>();
            Volumes = new List<VolumeInfo>();
            Devices = new List<DeviceInfo>();
            Drivers = new List<DriverInfo>();
            Network = new NetworkInfo();
            Security = new SecurityInfo();
            Events = new EventsInfo();
            Services = new List<ServiceInfo>();
            Startup = new List<StartupItem>();
            Software = new List<SoftwareInfo>();
            Sensors = new SensorsInfo();
            Performance = new PerformanceInfo();
        }

        public MachineInfo Machine { get; set; }
        public OsInfo Os { get; set; }
        public FirmwareInfo Firmware { get; set; }
        public CpuInfo Cpu { get; set; }
        public MemoryInfo Memory { get; set; }
        public List<GpuInfo> Gpus { get; set; }
        public List<DiskInfo> Disks { get; set; }
        public List<VolumeInfo> Volumes { get; set; }
        public List<DeviceInfo> Devices { get; set; }
        public List<DriverInfo> Drivers { get; set; }

        // Quando a fonte nativa (SetupAPI/CfgMgr32) falha mas a WMI
        // responde, inv.Devices continua nao-vazio (so com dispositivos
        // vindos da WMI) - sem este par, DEV-001 nao tem como distinguir
        // esse caso de "a fonte autoritativa rodou e nao achou nada".
        public bool DevicesNativeSourceAvailable { get; set; }
        public string DevicesNativeSourceUnavailableReason { get; set; }

        // Identificacao de chipset. Ver ChipsetInfo mais abaixo para a
        // explicacao completa da fonte.
        // Mutuamente exclusivos: depois de ChipsetCollector rodar, exatamente
        // um dos dois e nao-nulo (mesmo par que DevicesNativeSourceAvailable/
        // DevicesNativeSourceUnavailableReason acima) - Chipset != null
        // significa "achei o dispositivo PCI", mesmo que Chipset.Name fique
        // null por ID nao catalogado; ChipsetUnavailableReason != null
        // significa que nem o dispositivo foi encontrado.
        public ChipsetInfo Chipset { get; set; }
        public string ChipsetUnavailableReason { get; set; }
        public NetworkInfo Network { get; set; }
        public SecurityInfo Security { get; set; }
        public BatteryInfo Battery { get; set; }
        public EventsInfo Events { get; set; }
        public List<ServiceInfo> Services { get; set; }
        public List<StartupItem> Startup { get; set; }
        public List<SoftwareInfo> Software { get; set; }
        public SensorsInfo Sensors { get; set; }
        public PerformanceInfo Performance { get; set; }
        public StressResults Stress { get; set; }

        // Fotografia estavel para a fase de analise. So as LISTAS sao
        // copiadas - sao elas que um coletor
        // abandonado por timeout continua mutando em segundo plano. Os
        // demais campos escalares (Cpu, Memory, etc.) continuam
        // compartilhados por referencia - o pior caso ali e um valor lido
        // um instante desatualizado, nunca uma excecao, e alguns coletores
        // (ex.: StressCollector) dependem de enriquecer o MESMO objeto que
        // outro coletor ja populou (inv.Cpu.TemperatureC).
        //
        // TENTATIVA ANTERIOR (registrada aqui porque um harness provou que
        // estava errada, e a licao vale para quem mexer nisso de novo):
        // "new List<T>(source)" e "source.ToArray()" PARECEM copias seguras,
        // mas List<T> le o campo interno _size DUAS VEZES em pontos
        // diferentes (uma vez em Count, outra dentro de CopyTo/Array.Copy).
        // Se um coletor abandonado continuar dando .Add() nesse intervalo, a
        // segunda leitura ve um _size maior que o array de destino alocado
        // para a primeira - ArgumentException ("matriz de destino nao era
        // longa o suficiente"), reproduzido de fato com harness de 2M
        // iteracoes. Ou seja: a troca do foreach (que lanca por causa do
        // contador de versao) pelo construtor de List<T> so trocou uma
        // excecao por outra.
        //
        // O QUE REALMENTE FUNCIONA: os coletores so fazem .Add() (nenhum
        // Remove/Clear/Insert/Sort nas listas do Inventory - conferido por
        // grep em todo Collectors/). Uma lista so cresce, nunca encolhe nem
        // reordena, e List<T> preserva os elementos ja existentes quando
        // realoca o array interno para crescer. Isso significa que ler
        // Count UMA VEZ e depois indexar 0..Count-1 pelo indexador e
        // garantidamente seguro, mesmo com .Add() concorrente: cada indice
        // dentro do Count capturado ja existia e permanece valido para
        // sempre, e o indexador nunca falha por causa de a lista ter
        // crescido AINDA MAIS depois. SafeSnapshot implementa exatamente
        // isso, sem lock nenhum.
        public Inventory SnapshotForAnalysis()
        {
            Inventory copy = (Inventory)MemberwiseClone();
            copy.Gpus = SafeSnapshot(Gpus);
            copy.Disks = SafeSnapshot(Disks);
            copy.Volumes = SafeSnapshot(Volumes);
            copy.Devices = SafeSnapshot(Devices);
            copy.Drivers = SafeSnapshot(Drivers);
            copy.Services = SafeSnapshot(Services);
            copy.Startup = SafeSnapshot(Startup);
            copy.Software = SafeSnapshot(Software);

            if (Network != null)
            {
                copy.Network = ShallowClone(Network);
                copy.Network.Adapters = SafeSnapshot(Network.Adapters);
            }
            if (Security != null)
            {
                copy.Security = ShallowClone(Security);
                copy.Security.AntivirusProducts = SafeSnapshot(Security.AntivirusProducts);
            }
            if (Events != null)
            {
                copy.Events = ShallowClone(Events);
                copy.Events.Buckets = SafeSnapshot(Events.Buckets);
                copy.Events.TopEvents = SafeSnapshot(Events.TopEvents);
                copy.Events.BugChecks = SafeSnapshot(Events.BugChecks);
                copy.Events.WheaEvents = SafeSnapshot(Events.WheaEvents);
                copy.Events.DiskEvents = SafeSnapshot(Events.DiskEvents);
            }
            if (Sensors != null)
            {
                copy.Sensors = ShallowClone(Sensors);
                copy.Sensors.Fans = SafeSnapshot(Sensors.Fans);
                copy.Sensors.Temperatures = SafeSnapshot(Sensors.Temperatures);
            }

            return copy;
        }

        private static List<T> SafeSnapshot<T>(List<T> source)
        {
            int count = source.Count;
            List<T> copy = new List<T>(count);
            for (int i = 0; i < count; i++) copy.Add(source[i]);
            return copy;
        }

        private static T ShallowClone<T>(T source) where T : class
        {
            MethodInfo clone = typeof(T).GetMethod("MemberwiseClone", BindingFlags.Instance | BindingFlags.NonPublic);
            return (T)clone.Invoke(source, null);
        }
    }

    public sealed class MachineInfo
    {
        public string Manufacturer { get; set; }
        public string Model { get; set; }
        public string SystemFamily { get; set; }
        public string FormFactor { get; set; }
        public int? ChassisType { get; set; }
        public bool? IsPortable { get; set; }
        public bool? IsVirtualMachine { get; set; }
        public string VirtualizationHint { get; set; }
        public string BoardManufacturer { get; set; }
        public string BoardProduct { get; set; }
        public string BoardVersion { get; set; }

        [Sensitive(DataClass.SensitiveSystem)]
        public string SerialNumber { get; set; }

        [Sensitive(DataClass.SensitiveSystem)]
        public string BoardSerialNumber { get; set; }

        [Sensitive(DataClass.SensitiveSystem)]
        public string Hostname { get; set; }

        [Sensitive(DataClass.Personal)]
        public string LoggedUser { get; set; }

        // Domain identifica a rede especifica da maquina e por isso e
        // sensivel, mascarado por --privacy-safe (igual a hostname e
        // loggedUser). PartOfDomain (booleano) continua Public - so
        // indica se a maquina esta em dominio, sem identificar qual.
        [Sensitive(DataClass.SensitiveSystem)]
        public string Domain { get; set; }
        public bool? PartOfDomain { get; set; }
    }

    public sealed class OsInfo
    {
        public string Caption { get; set; }
        public string Edition { get; set; }
        public string Version { get; set; }
        public int? BuildNumber { get; set; }
        public string DisplayVersion { get; set; }
        public string Ubr { get; set; }
        public string Architecture { get; set; }
        public DateTime? InstallDate { get; set; }
        public DateTime? LastBootTime { get; set; }
        public double? UptimeHours { get; set; }
        public string Locale { get; set; }
        public string TimeZone { get; set; }
        public string ActivationStatus { get; set; }
        public string LicenseChannel { get; set; }
        public bool? IsActivated { get; set; }
        public DateTime? LastUpdateInstalled { get; set; }
        public int? UpdatesInstalledCount { get; set; }
        public string LastUpdateId { get; set; }
    }

    public sealed class FirmwareInfo
    {
        public string Manufacturer { get; set; }
        public string Version { get; set; }
        public DateTime? ReleaseDate { get; set; }
        public double? AgeYears { get; set; }
        public string FirmwareType { get; set; }   // Uefi | Bios | Unknown
        public string FirmwareTypeSource { get; set; }
        public string SecureBootState { get; set; } // Enabled|Disabled|NotSupported|Unknown|RequiresAdmin
        public bool? TpmPresent { get; set; }
        public string TpmVersion { get; set; }
        public bool? TpmEnabled { get; set; }
        public bool? TpmActivated { get; set; }
        public bool? VirtualizationFirmwareEnabled { get; set; }
    }

    public sealed class CpuInfo
    {
        public string Name { get; set; }
        public string Manufacturer { get; set; }
        public string Architecture { get; set; }
        public int? Family { get; set; }
        public int? ModelId { get; set; }
        public int? Stepping { get; set; }
        public string Socket { get; set; }
        public int? PhysicalCores { get; set; }
        public int? LogicalProcessors { get; set; }
        public int? SocketCount { get; set; }
        public int? MaxClockMhz { get; set; }
        public int? CurrentClockMhz { get; set; }
        public int? L2CacheKb { get; set; }
        public int? L3CacheKb { get; set; }
        public bool? VirtualizationEnabled { get; set; }
        public bool? SecondLevelAddressTranslation { get; set; }
        public bool? DataExecutionPrevention { get; set; }
        public double? LoadPercent { get; set; }
        public double? TemperatureC { get; set; }
        public string TemperatureSource { get; set; }
        public string WmiStatus { get; set; }
        public CpuLowLevelInfo LowLevel { get; set; }

        // Gravados pelo proprio CpuCollector quando a segunda fonte
        // (registro do kernel / API nativa) de fato concorda com a WMI -
        // CPU-001 so pode reivindicar AgreeingSource() quando um destes
        // for true, nunca incondicionalmente.
        public bool NameConfirmedByRegistry { get; set; }
        public bool LogicalProcessorsConfirmedByNativeApi { get; set; }
    }

    public sealed class MemoryModule
    {
        public string Slot { get; set; }
        public string Bank { get; set; }
        public ulong? CapacityBytes { get; set; }
        public int? SpeedMhz { get; set; }
        public int? ConfiguredSpeedMhz { get; set; }
        public string MemoryType { get; set; }
        public string FormFactor { get; set; }
        public string Manufacturer { get; set; }
        public string PartNumber { get; set; }

        [Sensitive(DataClass.SensitiveSystem)]
        public string SerialNumber { get; set; }

        public int? ConfiguredVoltageMv { get; set; }
    }

    public sealed class MemoryInfo
    {
        public MemoryInfo()
        {
            Modules = new List<MemoryModule>();
        }

        // Instalado fisicamente (SMBIOS via kernel) x utilizavel pelo SO.
        // A diferenca e a memoria reservada para hardware - o caso
        // "32 GB instalados / 29,7 GB utilizaveis" do briefing.
        public ulong? InstalledBytes { get; set; }
        public ulong? UsableBytes { get; set; }
        public ulong? ReservedBytes { get; set; }
        public ulong? AvailableBytes { get; set; }
        public double? UsagePercent { get; set; }
        public ulong? ModulesSumBytes { get; set; }

        // Terceira fonte independente para RAM total
        // (Win32_ComputerSystem.TotalPhysicalMemory), complementando
        // ModulesSumBytes (soma dos modulos) e InstalledBytes/UsableBytes
        // (via GetPhysicallyInstalledSystemMemory/GetMemoryStatus).
        public ulong? ComputerSystemTotalBytes { get; set; }

        public ulong? CommitTotalBytes { get; set; }
        public ulong? CommitAvailableBytes { get; set; }
        public ulong? PageFileSizeBytes { get; set; }
        public string PageFileLocation { get; set; }

        public int? SlotsUsed { get; set; }
        public int? SlotsTotalReportedByFirmware { get; set; }
        public bool SlotsTotalLooksTemplated { get; set; }
        public string ChannelConfiguration { get; set; }
        public bool? EccSupported { get; set; }

        public List<MemoryModule> Modules { get; set; }
    }

    public sealed class GpuInfo
    {
        public string Name { get; set; }
        public string Manufacturer { get; set; }
        public string PnpDeviceId { get; set; }
        public string PciVendorId { get; set; }
        public string PciDeviceId { get; set; }
        public string SubsystemId { get; set; }
        public string Kind { get; set; }        // Integrated | Discrete | Unknown
        public string KindSource { get; set; }  // VendorId | NameHeuristic
        public ulong? VramBytes { get; set; }
        public string VramSource { get; set; }
        public ulong? SharedMemoryBytes { get; set; }
        public string DriverVersion { get; set; }
        public DateTime? DriverDate { get; set; }
        public double? DriverAgeYears { get; set; }
        public string DriverProvider { get; set; }
        public bool? IsGenericMicrosoftDriver { get; set; }
        public int? CurrentHorizontalResolution { get; set; }
        public int? CurrentVerticalResolution { get; set; }
        public int? CurrentRefreshRate { get; set; }
        public string Status { get; set; }
        public uint? ConfigManagerErrorCode { get; set; }
        public double? TemperatureC { get; set; }
        public double? LoadPercent { get; set; }
    }

    public sealed class DiskInfo
    {
        public DiskInfo()
        {
            VolumeLetters = new List<string>();
        }

        public int? Index { get; set; }
        public string Model { get; set; }

        [Sensitive(DataClass.SensitiveSystem)]
        public string SerialNumber { get; set; }

        public string FirmwareVersion { get; set; }
        public ulong? SizeBytes { get; set; }
        public string MediaType { get; set; }    // SSD | HDD | SCM | Unspecified
        public string MediaTypeSource { get; set; }
        public string BusType { get; set; }      // NVMe | SATA | USB | RAID ...
        public string HealthStatus { get; set; }
        public string OperationalStatus { get; set; }
        public int? WearPercent { get; set; }
        public double? TemperatureC { get; set; }
        public string TemperatureSource { get; set; }
        public ulong? PowerOnHours { get; set; }
        public ulong? ReadErrorsUncorrected { get; set; }
        public ulong? WriteErrorsUncorrected { get; set; }
        public bool? SmartPredictFailure { get; set; }
        public string SmartSource { get; set; }

        // Identificador estavel para casar
        // MSStorageDriver_FailurePredictStatus.InstanceName com o disco
        // certo - o sufixo numerico do InstanceName e por CONTROLADOR, nao
        // global, entao um NVMe (DeviceId 0) e um SATA (DeviceId 1) podem
        // ambos ter InstanceName terminado em "_0" (cada um e o LUN 0 do seu
        // proprio controlador). PnpDeviceId (de Win32_DiskDrive) evita essa
        // colisao porque e um prefixo real do InstanceName.
        public string PnpDeviceId { get; set; }

        // Gravado por StorageCollector.CrossCheckLegacy so quando
        // Win32_DiskDrive.Status de fato concorda com
        // MSFT_PhysicalDisk.HealthStatus - STO-001 le esta flag antes de
        // conceder AgreeingSource(), nunca incondicionalmente.
        public bool HealthConfirmedByLegacyStatus { get; set; }
        public bool? IsBootDisk { get; set; }
        public bool? IsSystemDisk { get; set; }
        public List<string> VolumeLetters { get; set; }
        public double? WriteMbPerSec { get; set; }
        public double? ReadMbPerSec { get; set; }
    }

    public sealed class VolumeInfo
    {
        public string DriveLetter { get; set; }

        // Rotulo de volume frequentemente carrega nome de pessoa ou
        // empresa (ex.: "BACKUP-JOAO") e por isso e sensivel, mascarado
        // em --privacy-safe. DriveLetter, tamanho e espaco livre
        // continuam Public - nao identificam ninguem.
        [Sensitive(DataClass.Personal)]
        public string Label { get; set; }
        public string FileSystem { get; set; }
        public ulong? SizeBytes { get; set; }
        public ulong? FreeBytes { get; set; }
        public double? FreePercent { get; set; }
        public bool? IsBootVolume { get; set; }
        public bool? IsSystemVolume { get; set; }
        public bool? HasPageFile { get; set; }
        public string BitLockerStatus { get; set; }
        public string BitLockerSource { get; set; }
        public bool? DirtyBit { get; set; }
        public int? PhysicalDiskIndex { get; set; }
        public bool? Compressed { get; set; }
    }

    public sealed class DeviceInfo
    {
        public string InstanceId { get; set; }
        public string Name { get; set; }
        public string Class { get; set; }
        public string Manufacturer { get; set; }
        public string Service { get; set; }
        public string HardwareIds { get; set; }
        public string LocationInfo { get; set; }
        public string Enumerator { get; set; }
        public uint? ProblemCode { get; set; }
        public string ProblemMeaning { get; set; }
        public bool IsPresent { get; set; }
        public bool IsHidden { get; set; }
        public bool IsAdministrativeChoice { get; set; }
        public bool IsHardwareSuspect { get; set; }
        public string Source { get; set; } // SetupAPI | WMI | Both
    }

    // Identificacao de chipset (Intel PCH / AMD FCH) a partir do PCI
    // Vendor/Device ID da ponte ISA/LPC (Intel, classe PCI 0601) ou da FCH
    // (AMD, mesma classe 0601 para a ponte LPC e classe 0C03 para o
    // controlador USB XHCI) - o mesmo sinal que CPU-Z/AIDA64 usam para isso,
    // sem SMBIOS e sem P/Invoke novo: DeviceCollector ja enumera esses
    // dispositivos via SetupAPI (Inventory.Devices/DeviceInfo.HardwareIds).
    // Ver ChipsetCollector (Collectors/ChipsetCollector.cs).
    //
    // VendorId/DeviceId/Vendor sao FATOS MEDIDOS (o dispositivo PCI existe e
    // tem esse ID exato). Name e uma TRADUCAO desse ID via tabela curada
    // embutida no binario (ChipsetDatabase) - fica null quando o ID nao esta
    // catalogado, nunca um palpite. Mesmo principio de
    // Native.ProblemCodeMeaning ("codigo nao catalogado" em vez de inventar
    // um significado): Chipset != null com Name == null significa "achei o
    // dispositivo, mas nao esta na tabela" - diferente de Chipset == null
    // (inv.ChipsetUnavailableReason), que significa "nem achei o
    // dispositivo".
    public sealed class ChipsetInfo
    {
        public string VendorId { get; set; }     // "8086" (Intel) ou "1022" (AMD)
        public string DeviceId { get; set; }      // ex.: "A305"
        public string Vendor { get; set; }        // "Intel" ou "AMD"
        public string Name { get; set; }          // ex.: "Intel Z390" - null se ID nao catalogado
        public string SourceDevice { get; set; }  // qual dispositivo PCI (e classe) foi usado como fonte
    }

    public sealed class DriverInfo
    {
        public string DeviceName { get; set; }
        public string DeviceClass { get; set; }
        public string Provider { get; set; }
        public string Version { get; set; }
        public DateTime? Date { get; set; }
        public double? AgeYears { get; set; }
        public string InfName { get; set; }
        public bool? IsSigned { get; set; }
        public bool IsMicrosoftGeneric { get; set; }
    }

    public sealed class NetworkAdapterInfo
    {
        public NetworkAdapterInfo()
        {
            IPv4Addresses = new List<string>();
            IPv6Addresses = new List<string>();
            DnsServers = new List<string>();
            Gateways = new List<string>();
        }

        public string Name { get; set; }
        public string Description { get; set; }
        public string Manufacturer { get; set; }
        public string InterfaceType { get; set; }  // Ethernet | WiFi | Bluetooth | Virtual | Loopback | Other
        public bool IsVirtual { get; set; }
        public string VirtualKind { get; set; }
        public string Status { get; set; }
        public bool? IsUp { get; set; }
        public long? LinkSpeedBitsPerSecond { get; set; }

        [Sensitive(DataClass.SensitiveSystem)]
        public string MacAddress { get; set; }

        [Sensitive(DataClass.SensitiveSystem)]
        public List<string> IPv4Addresses { get; set; }

        [Sensitive(DataClass.SensitiveSystem)]
        public List<string> IPv6Addresses { get; set; }

        [Sensitive(DataClass.SensitiveSystem)]
        public List<string> Gateways { get; set; }

        [Sensitive(DataClass.SensitiveSystem)]
        public List<string> DnsServers { get; set; }

        public bool? DhcpEnabled { get; set; }
        public string DriverVersion { get; set; }
        public uint? ConfigManagerErrorCode { get; set; }
    }

    public sealed class NetworkInfo
    {
        public NetworkInfo()
        {
            Adapters = new List<NetworkAdapterInfo>();
        }

        public List<NetworkAdapterInfo> Adapters { get; set; }
        public int? AdaptersUp { get; set; }
        public bool? HasDefaultGateway { get; set; }
        public bool? HasDnsConfigured { get; set; }

        // Conectividade em camadas, para separar "sem internet" de
        // "DNS quebrado" de "gateway inacessivel" (item 19).
        public string GatewayReachable { get; set; }   // Yes | No | NotTested
        public string DnsResolves { get; set; }
        public string InternetReachable { get; set; }
        public string HttpsReachable { get; set; }
        public double? GatewayLatencyMs { get; set; }
        public string ConnectivityNote { get; set; }
    }

    public sealed class SecurityInfo
    {
        public SecurityInfo()
        {
            AntivirusProducts = new List<AntivirusProduct>();
        }

        public string DefenderRealtimeProtection { get; set; }  // Enabled|Disabled|NotAvailable|RequiresAdmin|Error
        public string DefenderRealtimeReason { get; set; }      // User|Policy|ThirdPartyAv|Unknown
        public string DefenderCloudProtection { get; set; }
        public string DefenderTamperProtection { get; set; }
        public string DefenderAntispyware { get; set; }
        public DateTime? DefenderSignatureDate { get; set; }
        public double? DefenderSignatureAgeDays { get; set; }
        public string DefenderServiceState { get; set; }
        public DateTime? DefenderLastQuickScan { get; set; }
        public DateTime? DefenderLastFullScan { get; set; }

        // Segunda fonte de verdade para o estado do Defender,
        // independente da WMI - o Service Control Manager, via
        // ServiceController("WinDefend"). SEC-001 so pode reivindicar
        // AgreeingSource() quando as duas fontes realmente concordarem
        // (DefenderRealtimeConfirmedByScm), nunca so por ter consultado a
        // WMI.
        public string DefenderScmStatus { get; set; }
        public bool DefenderRealtimeConfirmedByScm { get; set; }

        public string FirewallDomain { get; set; }
        public string FirewallPrivate { get; set; }
        public string FirewallPublic { get; set; }

        public string SmartScreenState { get; set; }
        public string UacState { get; set; }
        public int? UacConsentPromptLevel { get; set; }
        public string BitLockerSystemDrive { get; set; }

        public List<AntivirusProduct> AntivirusProducts { get; set; }

        public int? LocalAdminAccounts { get; set; }
        public int? LocalAccountsEnabled { get; set; }
        public int? LocalAccountsDisabled { get; set; }
        public bool? GuestAccountEnabled { get; set; }
        public bool? BuiltinAdminEnabled { get; set; }
        public bool? BuiltinAdminBlankPassword { get; set; }
    }

    public sealed class AntivirusProduct
    {
        public string Name { get; set; }
        public string State { get; set; }
        public bool? IsEnabled { get; set; }
        public bool? IsUpToDate { get; set; }
    }

    public sealed class BatteryInfo
    {
        public string Name { get; set; }
        public string Manufacturer { get; set; }
        public string Chemistry { get; set; }
        public int? ChargePercent { get; set; }
        public string Status { get; set; }
        public int? DesignCapacityMwh { get; set; }
        public int? FullChargeCapacityMwh { get; set; }
        public double? HealthPercent { get; set; }
        public int? CycleCount { get; set; }
        public int? VoltageMv { get; set; }
        public int? BatteryCount { get; set; }
        public string HealthSource { get; set; }
    }

    public sealed class EventBucket
    {
        public string LogName { get; set; }
        public int Critical { get; set; }
        public int Error { get; set; }
        public int Warning { get; set; }

        // Os contadores acima saturam no teto da consulta (ex.: 400) sem
        // marcar por si sos que o total real pode ser maior - um log de
        // System muito ativo pode aparentar "poucos avisos" quando a
        // consulta simplesmente nao contou o resto. Os campos abaixo dao
        // ao coletor (EventsCollector/EventLogSource) onde registrar que
        // um nivel bateu no teto e qual era o teto, para
        // HtmlReport/JsonReport poderem avisar o tecnico.
        public bool Truncated { get; set; }
        public int QueryCap { get; set; }
    }

    public sealed class EventSummaryItem
    {
        public DateTime? Time { get; set; }
        public string Provider { get; set; }
        public int Id { get; set; }
        public string Level { get; set; }
        public string Message { get; set; }
    }

    public sealed class BugCheckEvent
    {
        public DateTime? Time { get; set; }
        public string StopCode { get; set; }
        public string Detail { get; set; }
        public string DumpFile { get; set; }
    }

    public sealed class EventsInfo
    {
        public EventsInfo()
        {
            Buckets = new List<EventBucket>();
            TopEvents = new List<EventSummaryItem>();
            BugChecks = new List<BugCheckEvent>();
            WheaEvents = new List<EventSummaryItem>();
            DiskEvents = new List<EventSummaryItem>();
        }

        public int WindowDays { get; set; }
        public bool Accessible { get; set; }
        public string InaccessibleReason { get; set; }
        public List<EventBucket> Buckets { get; set; }
        public List<EventSummaryItem> TopEvents { get; set; }

        // O teto de 400 eventos do log System e aplicado em ordem
        // decrescente de data - se atingido, os eventos MAIS ANTIGOS da
        // janela pedida (WindowDays) simplesmente nao sao lidos. Estes
        // campos permitem distinguir esse caso de "janela inteira sem
        // ocorrencia".
        public bool SystemLogTruncated { get; set; }
        public DateTime? SystemLogOldestCoveredUtc { get; set; }

        public int? UnexpectedShutdowns { get; set; }
        public List<BugCheckEvent> BugChecks { get; set; }

        // Accessible vira true logo apos o log System responder, ANTES de
        // CollectBugChecks rodar. Se o modulo for abandonado por timeout
        // entre os dois pontos, BugChecks fica vazio (nunca coletado) e
        // indistinguivel de "coletado e realmente zero" - exceto por esta
        // flag, setada so ao final de CollectBugChecks.
        public bool BugChecksCollected { get; set; }
        public int? MinidumpCount { get; set; }
        public DateTime? LastMinidump { get; set; }

        // WHEA separado por severidade real: erro CORRIGIDO e rotina, erro
        // NAO corrigido e defeito. O coletor antigo somava os dois.
        public int? WheaCorrectedCount { get; set; }
        public int? WheaUncorrectedCount { get; set; }
        public List<EventSummaryItem> WheaEvents { get; set; }
        public List<EventSummaryItem> DiskEvents { get; set; }
        public int? DiskControllerErrors { get; set; }
        public int? ServiceFailures { get; set; }
        public int? AppCrashes { get; set; }
    }

    public sealed class ServiceInfo
    {
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string State { get; set; }
        public string StartMode { get; set; }
        public string Account { get; set; }
        public string ExecutablePath { get; set; }
        public bool? BinaryExists { get; set; }
        public bool IsInUnusualLocation { get; set; }
        public int? ProcessId { get; set; }
    }

    public sealed class StartupItem
    {
        public string Name { get; set; }
        public string Command { get; set; }
        public string Location { get; set; }   // Run | RunOnce | StartupFolder | ...
        public string Scope { get; set; }      // Machine | User
        public bool? TargetExists { get; set; }
        public bool IsInUnusualLocation { get; set; }
    }

    public sealed class SoftwareInfo
    {
        public string Name { get; set; }
        public string Publisher { get; set; }
        public string Version { get; set; }
        public DateTime? InstallDate { get; set; }
        public string InstallLocation { get; set; }
        public string Architecture { get; set; }
        public string Source { get; set; }   // Uninstall64 | Uninstall32 | UninstallUser
        public string Category { get; set; } // Runtime | Browser | Security | RemoteAccess | Vpn | Virtualization | Office | Other
    }

    public sealed class SensorsInfo
    {
        public SensorsInfo()
        {
            Fans = new List<FanReading>();
            Temperatures = new List<NamedReading>();
        }

        public bool Available { get; set; }
        public string UnavailableReason { get; set; }
        public double? CpuTemperatureC { get; set; }
        public double? GpuTemperatureC { get; set; }
        public double? MotherboardTemperatureC { get; set; }
        public List<FanReading> Fans { get; set; }
        public List<NamedReading> Temperatures { get; set; }
    }

    public sealed class FanReading
    {
        public string Hardware { get; set; }
        public string Name { get; set; }
        public double Rpm { get; set; }
    }

    public sealed class NamedReading
    {
        public string Hardware { get; set; }
        public string Name { get; set; }
        public double Value { get; set; }
    }

    public sealed class PerformanceInfo
    {
        public double? CpuLoadPercent { get; set; }
        public double? MemoryLoadPercent { get; set; }
        public double? DiskQueueLength { get; set; }
        public double? DiskTimePercent { get; set; }
        public int? ProcessCount { get; set; }
        public int? ThreadCount { get; set; }
        public int? HandleCount { get; set; }
        public string SamplingNote { get; set; }
    }

    public sealed class StressResults
    {
        public StressResults()
        {
            DiskBenchmarks = new List<DiskBenchmark>();
            Timeline = new List<TelemetrySample>();
            PhasesExecuted = new List<string>();
        }

        public bool Executed { get; set; }
        public string SkipReason { get; set; }
        public int DurationSeconds { get; set; }
        public double? CpuMaxLoadPercent { get; set; }
        public double? CpuIdleTempC { get; set; }
        public double? CpuMaxTempC { get; set; }
        public double? CpuThroughputMops { get; set; }
        public double? MemoryBandwidthMbPerSec { get; set; }
        public List<DiskBenchmark> DiskBenchmarks { get; set; }

        // Motor de carga efetivamente usado, e o motivo caso o caminho de
        // codigo nativo tenha sido barrado.
        public string Engine { get; set; }
        public string EngineFallbackReason { get; set; }

        public CpuStressResult Cpu { get; set; }
        public ThermalProfile Thermal { get; set; }
        public MemoryStressResult Memory { get; set; }
        public GpuStressResult Gpu { get; set; }

        // Uma amostra por segundo do inicio ao fim da carga. E o que permite
        // distinguir "esquentou e estabilizou" de "esquentou ate o limite e
        // comecou a perder desempenho".
        public List<TelemetrySample> Timeline { get; set; }
        public List<string> PhasesExecuted { get; set; }
        public string GpuNote { get; set; }
    }

    public sealed class TelemetrySample
    {
        public double AtSecond { get; set; }
        public string Phase { get; set; }
        public double? CpuTempC { get; set; }
        public double? CpuPackageWatts { get; set; }
        public double? CpuClockMhz { get; set; }
        public double? CpuLoadPercent { get; set; }
        public double? GpuTempC { get; set; }
        public double? GpuLoadPercent { get; set; }
        public double? BoardTempC { get; set; }
        public double? StorageMaxTempC { get; set; }
        public double? MaxFanRpm { get; set; }
        public double? ThroughputGflops { get; set; }
        public double? GpuFramesPerSecond { get; set; }
    }

    public sealed class CpuStressResult
    {
        public CpuStressResult()
        {
            FaultyProcessors = new List<int>();
        }

        public int ThreadCount { get; set; }
        public bool ThreadsPinned { get; set; }
        public int DurationSeconds { get; set; }
        public double? PeakGflops { get; set; }

        // Vazao no primeiro e no ultimo terco da carga. A queda entre as duas
        // e a medida direta de throttling termico: nao depende de MSR nem de
        // driver, so do desempenho realmente entregue.
        public double? FirstWindowGflops { get; set; }
        public double? LastWindowGflops { get; set; }
        public double? SustainPercent { get; set; }

        public long TotalOperations { get; set; }
        public long ArithmeticErrors { get; set; }
        public List<int> FaultyProcessors { get; set; }
        public string FirstErrorDetail { get; set; }
        public double? MaxLoadPercent { get; set; }

        // Protecao termica: a carga e interrompida antes do prazo pedido
        // se a temperatura atingir o limiar critico. Nulo = a carga
        // terminou pelo tempo, sem intervencao de seguranca.
        public double? AbortedAtTempC { get; set; }
        public bool ThermalProtectionActive { get; set; }
    }

    // Resultado da fase opcional de carga 3D real (--gpu-stress). Ao
    // contrario do restante do teste de GPU (so leitura passiva de sensor),
    // aqui uma carga grafica de verdade foi aplicada via GpuLoadEngine.
    public sealed class GpuStressResult
    {
        public bool Executed { get; set; }
        public string SkipReason { get; set; }

        // Preenchido quando o motor de carga (janela/contexto OpenGL) nao
        // pode ser criado - sessao sem GPU/RDP basico, driver ausente,
        // pixel format indisponivel. Mesmo principio do EngineFallbackReason
        // da CPU: a fase nunca vira "aprovada" por causa disso, vira "nao
        // executada" com o motivo explicito.
        public string EngineFallbackReason { get; set; }
        public int DurationSeconds { get; set; }

        public string RenderVendor { get; set; }
        public string RenderDevice { get; set; }

        // Falso quando o contexto obtido e o renderizador de SOFTWARE da
        // Microsoft (GPU hibrida mal configurada, sessao remota sem 3D) -
        // nesse caso a carga rodou, mas nao tocou hardware de video nenhum,
        // e nenhum teste pode tratar isso como GPU testada.
        public bool? HardwareAccelerated { get; set; }

        public long FramesRendered { get; set; }
        public double? AverageFps { get; set; }

        // Fps do primeiro e do ultimo terco da carga - queda entre os dois
        // e a medida direta de throttling termico da GPU, mesmo principio
        // do FirstWindowGflops/LastWindowGflops da CPU.
        public double? FirstWindowFps { get; set; }
        public double? LastWindowFps { get; set; }
        public double? SustainPercent { get; set; }

        public double? MaxLoadPercent { get; set; }

        // Corte de seguranca por temperatura, mesmo mecanismo do
        // CpuStressResult.AbortedAtTempC.
        public double? AbortedAtTempC { get; set; }
    }

    public sealed class ThermalProfile
    {
        public double? IdleTempC { get; set; }
        public double? MaxTempC { get; set; }
        public double? AverageUnderLoadC { get; set; }
        public double? RampRateCPerMinute { get; set; }
        public double? SecondsToPeak { get; set; }
        public double? MaxPackageWatts { get; set; }
        public double? MinClockUnderLoadMhz { get; set; }
        public double? MaxClockUnderLoadMhz { get; set; }
        public double? IdleFanRpm { get; set; }
        public double? MaxFanRpm { get; set; }
        public double? MaxGpuTempC { get; set; }
        public double? MaxBoardTempC { get; set; }
        public double? MaxStorageTempC { get; set; }

        // Resfriamento apos o fim da carga. Um dissipador entupido esquenta
        // rapido E esfria devagar - o par de taxas separa "projeto apertado"
        // de "precisa de limpeza".
        public double? RecoveryTempC { get; set; }
        public double? RecoverySeconds { get; set; }
        public double? CooldownRateCPerMinute { get; set; }

        // Utilizacao maxima de GPU observada durante a fase de carga 3D
        // real (--gpu-stress). So calculada dentro dessa fase - fora dela
        // nao ha carga aplicada, entao o numero nao significaria nada.
        public double? MaxGpuLoadPercent { get; set; }
    }

    public sealed class MemoryStressResult
    {
        public MemoryStressResult()
        {
            PatternsRun = new List<string>();
        }

        public bool Executed { get; set; }
        public string SkipReason { get; set; }
        public long BytesTested { get; set; }
        public int Passes { get; set; }
        public long ErrorCount { get; set; }
        public string FirstErrorDetail { get; set; }
        public List<string> PatternsRun { get; set; }

        public double? WriteBandwidthMbPerSec { get; set; }
        public double? ReadBandwidthMbPerSec { get; set; }
        public string BandwidthMethod { get; set; }
        public double? RandomAccessLatencyNs { get; set; }
    }

    public sealed class DiskBenchmark
    {
        public string DriveLetter { get; set; }
        public int? PhysicalDiskIndex { get; set; }
        public string MediaType { get; set; }
        public double? WriteMbPerSec { get; set; }
        public double? ReadMbPerSec { get; set; }
        public string Note { get; set; }

        // Escrita sustentada: os SSDs baratos escrevem rapido enquanto o cache
        // SLC aguenta e despencam depois. Comparar o primeiro com o ultimo
        // quarto do arquivo revela isso; uma medida unica esconde.
        public double? SustainedWriteMbPerSec { get; set; }
        public double? WriteDropPercent { get; set; }

        public double? Random4kReadIops { get; set; }
        public double? Random4kWriteIops { get; set; }

        // Releitura conferida byte a byte contra o que foi gravado.
        public bool? IntegrityChecked { get; set; }
        public long IntegrityErrors { get; set; }

        public double? TempBeforeC { get; set; }
        public double? TempAfterC { get; set; }
    }

    // Identidade e capacidades lidas pela instrucao CPUID - direto do
    // silicio, sem WMI, sem registro, sem driver no meio.
    public sealed class CpuLowLevelInfo
    {
        public CpuLowLevelInfo()
        {
            Caches = new List<string>();
        }

        public string Source { get; set; }
        public string Vendor { get; set; }
        public string BrandString { get; set; }
        public int? Family { get; set; }
        public int? ModelId { get; set; }
        public int? Stepping { get; set; }
        public string Features { get; set; }
        public bool? Avx2 { get; set; }
        public bool? Fma { get; set; }
        public bool? Avx512 { get; set; }
        public bool? InvariantTsc { get; set; }
        public bool? TurboBoost { get; set; }
        public bool? DigitalThermalSensor { get; set; }
        public bool? HypervisorPresent { get; set; }
        public string HypervisorVendor { get; set; }
        public double? TscMhz { get; set; }
        public List<string> Caches { get; set; }
    }
}
