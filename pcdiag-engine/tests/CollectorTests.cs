using System;
using System.Collections.Generic;
using PcDiag.Analysis;
using PcDiag.Collectors;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Testing
{
    // Cobre o caminho feliz (DataRow -> campo do Inventory) dos coletores
    // de CPU, disco, bateria e rede, usando FakeWmi.On(...) com linhas
    // realistas e assertando campos concretos.
    //
    // Tambem cobre o estagio CrossCheck (Sources -> Collectors -> Inventory
    // -> CrossCheck -> Tests, conforme ARQUITETURA.md), que existe em varios
    // pontos via ctx.AddInconsistency. Os testes de divergencia abaixo
    // cobrem os tres cross-checks que sao deterministicos em qualquer
    // maquina (nao dependem de API nativa nem de servico do SO, que variam
    // por ambiente): nome de CPU via registro, saude de disco via
    // Win32_DiskDrive, e RAM total via Win32_ComputerSystem - os mesmos que
    // usam o mecanismo de AgreeingSource() condicional.
    public static class CollectorTests
    {
        public static void Run(TestRunner t)
        {
            CpuHappyPath(t);
            StorageHappyPath(t);
            BatteryHappyPath(t);
            NetworkHappyPath(t);
            CpuNameCrossCheck(t);
            StorageHealthCrossCheck(t);
            MemoryTotalCrossCheck(t);
            SmartMatchByPnpDeviceId(t);
        }

        // MSStorageDriver_FailurePredictStatus.InstanceName termina num LUN
        // que e por CONTROLADOR, nao global - um NVMe (LUN 0 do seu proprio
        // controlador) e um SATA (tambem LUN 0 do controlador dele) podem os
        // dois terminar em "_0". Por isso o casamento do SMART com o disco
        // certo usa PnpDeviceId, nunca o sufixo numerico do InstanceName.
        // Este teste reproduz o cenario (dois discos, PNPDeviceID diferentes,
        // ambos "_0") e confere que cada SMART vai para o disco certo.
        private static void SmartMatchByPnpDeviceId(TestRunner t)
        {
            t.Suite("CrossCheck: SMART casado por PnpDeviceId, nao por sufixo numerico colidente");

            FakeWmi wmi = new FakeWmi();
            wmi.On("MSFT_PhysicalDisk",
                FakeWmi.Row("DeviceId", "0", "ObjectId", "{nvme0}", "FriendlyName", "NVMe Samsung 970 EVO",
                    "SerialNumber", "SN-NVME", "Size", (ulong)500000000000, "MediaType", 4, "BusType", 17,
                    "HealthStatus", 0, "OperationalStatus", 2),
                FakeWmi.Row("DeviceId", "1", "ObjectId", "{sata1}", "FriendlyName", "SATA WDC HDD",
                    "SerialNumber", "SN-SATA", "Size", (ulong)1000000000000, "MediaType", 3, "BusType", 11,
                    "HealthStatus", 0, "OperationalStatus", 2));
            wmi.On("Win32_DiskDrive",
                FakeWmi.Row("Index", 0, "Model", "NVMe Samsung 970 EVO", "SerialNumber", "SN-NVME",
                    "Size", (ulong)500000000000, "InterfaceType", "SCSI", "Status", "OK",
                    "PNPDeviceID", @"SCSI\Disk&Ven_NVMe&Prod_Samsung_970EVO\4&1a2b3c4d&0&000000"),
                FakeWmi.Row("Index", 1, "Model", "SATA WDC HDD", "SerialNumber", "SN-SATA",
                    "Size", (ulong)1000000000000, "InterfaceType", "SCSI", "Status", "OK",
                    "PNPDeviceID", @"SCSI\Disk&Ven_WDC&Prod_HDD1TB\5&2b3c4d5e&0&000000"));
            // As duas InstanceName terminam em "_0" - o LUN 0 de CADA
            // controlador, nao um indice global. E exatamente o cenario de
            // colisao que o casamento por PnpDeviceId precisa resolver.
            wmi.On("MSStorageDriver_FailurePredictStatus",
                FakeWmi.Row("InstanceName", @"SCSI\Disk&Ven_NVMe&Prod_Samsung_970EVO\4&1a2b3c4d&0&000000_0",
                    "PredictFailure", true, "Reason", 0),
                FakeWmi.Row("InstanceName", @"SCSI\Disk&Ven_WDC&Prod_HDD1TB\5&2b3c4d5e&0&000000_0",
                    "PredictFailure", false, "Reason", 0));

            ScanContext ctx = Fixture.Context(false);
            Inventory inv = new Inventory();
            new StorageCollector().Collect(ctx, Fixture.Sources(wmi, new FakeRegistry(), new FakeEventLog(), new FakeProcessRunner()), inv);

            DiskInfo nvme = null, sata = null;
            foreach (DiskInfo d in inv.Disks)
            {
                if (d.Model == "NVMe Samsung 970 EVO") nvme = d;
                else if (d.Model == "SATA WDC HDD") sata = d;
            }

            t.NotNull("disco NVMe encontrado", nvme);
            t.NotNull("disco SATA encontrado", sata);
            t.True("SMART do NVMe (PredictFailure=true) foi para o NVMe, nao para o SATA por colisao de sufixo",
                nvme != null && nvme.SmartPredictFailure == true);
            t.True("SMART do SATA (PredictFailure=false) foi para o SATA, nao ficou sem atribuicao",
                sata != null && sata.SmartPredictFailure == false);
        }

        private static void CpuHappyPath(TestRunner t)
        {
            t.Suite("Coletor de CPU: caminho feliz");

            FakeWmi wmi = new FakeWmi();
            wmi.On("Win32_Processor",
                FakeWmi.Row("Name", "Intel(R) Xeon(R) CPU E5-2620 v4", "Manufacturer", "GenuineIntel",
                    "Architecture", 9, "Family", 6, "Description", "Intel64 Family 6 Model 79 Stepping 1",
                    "SocketDesignation", "CPU0", "NumberOfCores", 4, "NumberOfLogicalProcessors", 8,
                    "MaxClockSpeed", 2100, "CurrentClockSpeed", 2100, "L2CacheSize", 1024, "L3CacheSize", 20480,
                    "VirtualizationFirmwareEnabled", true, "SecondLevelAddressTranslationExtensions", true,
                    "LoadPercentage", 12, "Status", "OK"),
                FakeWmi.Row("Name", "Intel(R) Xeon(R) CPU E5-2620 v4", "Manufacturer", "GenuineIntel",
                    "Architecture", 9, "Family", 6, "Description", "Intel64 Family 6 Model 79 Stepping 1",
                    "SocketDesignation", "CPU1", "NumberOfCores", 4, "NumberOfLogicalProcessors", 8,
                    "MaxClockSpeed", 2100, "CurrentClockSpeed", 2100, "L2CacheSize", 1024, "L3CacheSize", 20480,
                    "VirtualizationFirmwareEnabled", true, "SecondLevelAddressTranslationExtensions", true,
                    "LoadPercentage", 18, "Status", "OK"));

            ScanContext ctx = Fixture.Context(false);
            SourceSet src = Fixture.Sources(wmi, new FakeRegistry(), new FakeEventLog(), new FakeProcessRunner());
            Inventory inv = new Inventory();

            new CpuCollector().Collect(ctx, src, inv);

            t.Equal("soma os nucleos fisicos dos dois sockets (4+4)", 8, inv.Cpu.PhysicalCores);
            t.Equal("soma as threads dos dois sockets (8+8), nao usa NumberOfCores no lugar de threads", 16, inv.Cpu.LogicalProcessors);
            t.Equal("conta os dois sockets", 2, inv.Cpu.SocketCount);
            t.Equal("nome vem da primeira linha", "Intel(R) Xeon(R) CPU E5-2620 v4", inv.Cpu.Name);
            t.Equal("status OK preservado", "OK", inv.Cpu.WmiStatus);
        }

        private static void StorageHappyPath(TestRunner t)
        {
            t.Suite("Coletor de armazenamento: caminho feliz");

            FakeWmi wmi = new FakeWmi();
            wmi.On("MSFT_PhysicalDisk",
                FakeWmi.Row("DeviceId", "0", "ObjectId", "{disk0}", "FriendlyName", "Samsung SSD 970 EVO 500GB",
                    "SerialNumber", "S4J2NF0M123456", "FirmwareVersion", "2B2QEXM7",
                    "Size", (ulong)500107862016, "MediaType", 4, "BusType", 17,
                    "HealthStatus", 0, "OperationalStatus", 2));
            wmi.On("Win32_DiskDrive",
                FakeWmi.Row("Index", 0, "Model", "Samsung SSD 970 EVO 500GB", "SerialNumber", "S4J2NF0M123456",
                    "FirmwareRevision", "2B2QEXM7", "Size", (ulong)500107862016, "InterfaceType", "SCSI",
                    "Status", "OK", "MediaType", "Fixed hard disk media"));

            ScanContext ctx = Fixture.Context(false);
            SourceSet src = Fixture.Sources(wmi, new FakeRegistry(), new FakeEventLog(), new FakeProcessRunner());
            Inventory inv = new Inventory();

            new StorageCollector().Collect(ctx, src, inv);

            t.Equal("um disco fisico enumerado", 1, inv.Disks.Count);
            DiskInfo d = inv.Disks[0];
            t.Equal("modelo veio da MSFT_PhysicalDisk", "Samsung SSD 970 EVO 500GB", d.Model);
            t.Equal("saude decodificada (0 = Healthy)", "Healthy", d.HealthStatus);
            t.Equal("tipo de midia decodificado (4 = SSD)", "SSD", d.MediaType);
            t.Equal("barramento decodificado (17 = NVMe)", "NVMe", d.BusType);
            t.Equal("tamanho preservado", (ulong)500107862016, d.SizeBytes);
            t.True("Win32_DiskDrive.Status='OK' concorda com HealthStatus='Healthy' - flag gravada pelo cross-check", d.HealthConfirmedByLegacyStatus);
            t.True("nenhuma divergencia de saude quando as duas fontes concordam", ctx.Inconsistencies.Count == 0);
        }

        private static void BatteryHappyPath(TestRunner t)
        {
            t.Suite("Coletor de bateria: caminho feliz");

            FakeWmi wmi = new FakeWmi();
            wmi.On("Win32_Battery",
                FakeWmi.Row("Name", "Bateria interna", "DeviceID", "BAT0",
                    "EstimatedChargeRemaining", 85, "BatteryStatus", 2, "Chemistry", 6,
                    "DesignVoltage", (ulong)11400));

            ScanContext ctx = Fixture.Context(false);
            SourceSet src = Fixture.Sources(wmi, new FakeRegistry(), new FakeEventLog(), new FakeProcessRunner());
            Inventory inv = new Inventory();

            new BatteryCollector().Collect(ctx, src, inv);

            t.NotNull("bateria detectada", inv.Battery);
            t.Equal("carga estimada preservada", 85, inv.Battery.ChargePercent);
            t.Equal("status decodificado (2 = ligado na tomada)", "Ligado na tomada (AC)", inv.Battery.Status);
            t.Equal("quimica decodificada (6 = litio-ion)", "Litio-ion", inv.Battery.Chemistry);
            t.Equal("voltagem de projeto preservada", 11400, inv.Battery.VoltageMv);
            t.Equal("uma bateria contada", 1, inv.Battery.BatteryCount);
        }

        private static void NetworkHappyPath(TestRunner t)
        {
            t.Suite("Coletor de rede: caminho feliz");

            FakeWmi wmi = new FakeWmi();
            wmi.On("Win32_NetworkAdapter",
                FakeWmi.Row("Index", 7, "Name", "Realtek PCIe GbE Family Controller", "NetConnectionID", "Ethernet",
                    "NetConnectionStatus", 2, "Speed", (ulong)1000000000, "MACAddress", "AA:BB:CC:DD:EE:FF",
                    "Manufacturer", "Realtek", "AdapterTypeID", 0, "PhysicalAdapter", true, "NetEnabled", true,
                    "ConfigManagerErrorCode", 0));
            wmi.On("Win32_NetworkAdapterConfiguration",
                FakeWmi.Row("Index", 7, "IPAddress", new string[] { "192.168.1.50" },
                    "DefaultIPGateway", new string[] { "192.168.1.1" },
                    "DNSServerSearchOrder", new string[] { "8.8.8.8" }, "DHCPEnabled", true,
                    "MACAddress", "AA:BB:CC:DD:EE:FF"));

            ScanContext ctx = Fixture.Context(false);
            SourceSet src = Fixture.Sources(wmi, new FakeRegistry(), new FakeEventLog(), new FakeProcessRunner());
            Inventory inv = new Inventory();

            new NetworkCollector(false).Collect(ctx, src, inv);

            t.Equal("um adaptador enumerado", 1, inv.Network.Adapters.Count);
            NetworkAdapterInfo n = inv.Network.Adapters[0];
            t.Equal("nome de conexao preferido sobre a descricao", "Ethernet", n.Name);
            t.Equal("endereco MAC preservado", "AA:BB:CC:DD:EE:FF", n.MacAddress);
            t.True("status 2 vira IsUp=true", n.IsUp == true);
        }

        // ---------- cross-check ----------

        private static void CpuNameCrossCheck(TestRunner t)
        {
            t.Suite("CrossCheck: nome da CPU (WMI x registro do kernel)");

            FakeWmi wmiAgree = new FakeWmi();
            wmiAgree.On("Win32_Processor", FakeWmi.Row("Name", "Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz", "Status", "OK"));
            FakeRegistry regAgree = new FakeRegistry();
            regAgree.Value("HKLM", @"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString",
                "Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz");

            ScanContext ctxAgree = Fixture.Context(false);
            Inventory invAgree = new Inventory();
            new CpuCollector().Collect(ctxAgree, Fixture.Sources(wmiAgree, regAgree, new FakeEventLog(), new FakeProcessRunner()), invAgree);

            t.True("fontes concordam - flag de confirmacao gravada", invAgree.Cpu.NameConfirmedByRegistry);
            t.Equal("nenhuma divergencia quando os nomes normalizados sao iguais", 0, ctxAgree.Inconsistencies.Count);

            FakeWmi wmiDiverge = new FakeWmi();
            wmiDiverge.On("Win32_Processor", FakeWmi.Row("Name", "Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz", "Status", "OK"));
            FakeRegistry regDiverge = new FakeRegistry();
            regDiverge.Value("HKLM", @"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString",
                "AMD Ryzen 5 3600 6-Core Processor");

            ScanContext ctxDiverge = Fixture.Context(false);
            Inventory invDiverge = new Inventory();
            new CpuCollector().Collect(ctxDiverge, Fixture.Sources(wmiDiverge, regDiverge, new FakeEventLog(), new FakeProcessRunner()), invDiverge);

            t.False("fontes divergem - flag de confirmacao NAO gravada", invDiverge.Cpu.NameConfirmedByRegistry);
            t.Equal("a divergencia entra em ctx.Inconsistencies", 1, ctxDiverge.Inconsistencies.Count);
            t.Equal("o assunto identifica o fato divergente", "Modelo da CPU", ctxDiverge.Inconsistencies[0].Subject);
            t.Equal("as duas leituras ficam citadas lado a lado", 2, ctxDiverge.Inconsistencies[0].Readings.Count);

            // O teste CPU-001 nao pode sair com a mesma confianca nos dois
            // cenarios - so o que realmente teve uma segunda fonte
            // confirmando pode reivindicar o bonus.
            TestResult passAgree = new List<TestResult>(new CpuTests().Run(ctxAgree, invAgree))[0];
            TestResult passDiverge = new List<TestResult>(new CpuTests().Run(ctxDiverge, invDiverge))[0];
            t.True("confianca com fontes concordando e maior que com fontes divergindo",
                passAgree.Confidence > passDiverge.Confidence);
        }

        private static void StorageHealthCrossCheck(TestRunner t)
        {
            t.Suite("CrossCheck: saude do disco (MSFT_PhysicalDisk x Win32_DiskDrive)");

            // Cenario onde as fontes concordam (mesma configuracao do teste
            // de caminho feliz acima, refeita aqui para comparar confianca).
            FakeWmi wmiAgree = new FakeWmi();
            wmiAgree.On("MSFT_PhysicalDisk",
                FakeWmi.Row("DeviceId", "0", "ObjectId", "{disk0}", "FriendlyName", "Disco Teste",
                    "SerialNumber", "SN1", "Size", (ulong)256000000000, "MediaType", 4, "BusType", 11,
                    "HealthStatus", 0, "OperationalStatus", 2));
            wmiAgree.On("Win32_DiskDrive",
                FakeWmi.Row("Index", 0, "Model", "Disco Teste", "SerialNumber", "SN1",
                    "Size", (ulong)256000000000, "InterfaceType", "SATA", "Status", "OK"));

            ScanContext ctxAgree = Fixture.Context(false);
            Inventory invAgree = new Inventory();
            new StorageCollector().Collect(ctxAgree, Fixture.Sources(wmiAgree, new FakeRegistry(), new FakeEventLog(), new FakeProcessRunner()), invAgree);

            FakeWmi wmiDiverge = new FakeWmi();
            wmiDiverge.On("MSFT_PhysicalDisk",
                FakeWmi.Row("DeviceId", "0", "ObjectId", "{disk0}", "FriendlyName", "Disco Teste",
                    "SerialNumber", "SN1", "Size", (ulong)256000000000, "MediaType", 4, "BusType", 11,
                    "HealthStatus", 0, "OperationalStatus", 2));
            wmiDiverge.On("Win32_DiskDrive",
                FakeWmi.Row("Index", 0, "Model", "Disco Teste", "SerialNumber", "SN1",
                    "Size", (ulong)256000000000, "InterfaceType", "SATA", "Status", "Pred Fail"));

            ScanContext ctxDiverge = Fixture.Context(false);
            Inventory invDiverge = new Inventory();
            new StorageCollector().Collect(ctxDiverge, Fixture.Sources(wmiDiverge, new FakeRegistry(), new FakeEventLog(), new FakeProcessRunner()), invDiverge);

            t.False("Win32_DiskDrive.Status='Pred Fail' diverge de HealthStatus='Healthy' - flag NAO gravada",
                invDiverge.Disks[0].HealthConfirmedByLegacyStatus);

            bool foundDiskInconsistency = false;
            foreach (Inconsistency inc in ctxDiverge.Inconsistencies)
                if (inc.Subject.StartsWith("Saude do disco", StringComparison.Ordinal)) foundDiskInconsistency = true;
            t.True("a divergencia entra em ctx.Inconsistencies", foundDiskInconsistency);

            // MSFT_PhysicalDisk.HealthStatus continua sendo a fonte de
            // STATUS de STO-001 (permanece Healthy/Pass mesmo com a
            // segunda fonte discordando - a divergencia por si so nao
            // reclassifica o disco, so rebaixa a confianca do achado, que e
            // exatamente o mecanismo que ARQUITETURA.md promete).
            TestResult stoAgree = null, stoDiverge = null;
            foreach (TestResult r in new StorageTests().Run(ctxAgree, invAgree)) if (r.Id == "STO-001-01") stoAgree = r;
            foreach (TestResult r in new StorageTests().Run(ctxDiverge, invDiverge)) if (r.Id == "STO-001-01") stoDiverge = r;

            t.NotNull("STO-001 (concordancia) foi produzido", stoAgree);
            t.NotNull("STO-001 (divergencia) foi produzido", stoDiverge);
            t.True("confianca com fontes concordando e maior que com fontes divergindo",
                stoAgree.Confidence > stoDiverge.Confidence);
        }

        private static void MemoryTotalCrossCheck(TestRunner t)
        {
            t.Suite("CrossCheck: RAM total (soma dos modulos x Win32_ComputerSystem)");

            FakeWmi wmi = new FakeWmi();
            wmi.On("Win32_PhysicalMemory",
                FakeWmi.Row("DeviceLocator", "DIMM0", "BankLabel", "BANK0", "Capacity", (ulong)8589934592,
                    "Speed", 3200, "ConfiguredClockSpeed", 3200, "MemoryType", 26, "FormFactor", 8,
                    "Manufacturer", "Corsair", "PartNumber", "CMK16GX4M2B3200C16", "ConfiguredVoltage", 1200));
            // Win32_ComputerSystem reporta 1 GiB a menos que a soma dos
            // modulos - divergencia real que o cross-check precisa detectar.
            wmi.On("Win32_ComputerSystem",
                FakeWmi.Row("TotalPhysicalMemory", (ulong)(8589934592L - 1073741824L)));

            ScanContext ctx = Fixture.Context(false);
            Inventory inv = new Inventory();
            new MemoryCollector().Collect(ctx, Fixture.Sources(wmi, new FakeRegistry(), new FakeEventLog(), new FakeProcessRunner()), inv);

            t.Equal("Win32_ComputerSystem.TotalPhysicalMemory foi lido (fonte C do item 7 da ARQUITETURA)",
                (ulong)(8589934592L - 1073741824L), inv.Memory.ComputerSystemTotalBytes);

            bool foundRamInconsistency = false;
            foreach (Inconsistency inc in ctx.Inconsistencies)
                if (inc.Subject == "Total de memoria RAM (Win32_ComputerSystem)") foundRamInconsistency = true;
            t.True("divergencia de 1 GiB entre soma dos modulos e Win32_ComputerSystem e registrada", foundRamInconsistency);
        }
    }
}
