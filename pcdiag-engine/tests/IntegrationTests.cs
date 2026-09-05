using System;
using System.Collections.Generic;
using System.IO;
using PcDiag.Analysis;
using PcDiag.Collectors;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Reporting;
using PcDiag.Sources;

namespace PcDiag.Testing
{
    public static class IntegrationTests
    {
        public static void Run(TestRunner t)
        {
            FullPipeline(t);
            TimedOutModuleNeverLooksHealthy(t);
            HtmlRendersKnownFinding(t);
            PrivacySafeHtmlDoesNotLeak(t);
            HostileInputInReport(t);
            FailureInjection(t);
            BaselineComparison(t);
            NoAdminCoverage(t);
            CorrelationRelatedTestIdsExist(t);
            NotApplicableNeverCountsAsUnmeasuredCoverage(t);
        }

        // NotApplicable (aqui, NET-003 - nenhum adaptador Ethernet na
        // maquina de teste, so Wi-Fi) nao pode contar como "teste que nao
        // pode ser executado" no sumario global, nem sobrescrever o badge
        // da categoria "Rede" (NET-001 e NET-002 aprovados) para "NAO SE
        // APLICA".
        private static void NotApplicableNeverCountsAsUnmeasuredCoverage(TestRunner t)
        {
            t.Suite("Regressao: NotApplicable nao conta como cobertura perdida nem sobrescreve o status da categoria");

            Inventory inv = HealthyMachine();
            ScanContext ctx = Fixture.Context(true);
            DiagnosticReport report = DiagnosticEngine.Analyze(ctx, inv, Suites());

            TestResult net003 = null;
            foreach (TestResult r in report.Tests) if (r.Id == "NET-003") net003 = r;
            t.NotNull("NET-003 existe no laudo (sem Ethernet, so Wi-Fi)", net003);
            t.Equal("NET-003 e NotApplicable neste cenario", TestStatus.NotApplicable, net003.Status);

            t.True("NET-003 (NotApplicable) entra no contador proprio, nao em TestsNotExecuted",
                report.Summary.TestsNotApplicable > 0);

            ComponentHealth rede = null;
            foreach (ComponentHealth c in report.ComponentHealth) if (c.Component == "Rede") rede = c;
            t.NotNull("categoria Rede existe no laudo", rede);
            t.False("categoria com testes aprovados nao vira NAO SE APLICA so por causa de um NotApplicable",
                rede.Status == TestStatus.NotApplicable);
        }

        // Engine.StorageCausingCrashes e SlowMachineExplanation citam os IDs
        // base dos testes ("STO-001", "STO-005"), mas StorageTests.cs gera
        // IDs com sufixo por disco/volume (STO-001-01, STO-005-C, ...) -
        // HtmlReport.cs itera RelatedTestIds para casar a correlacao com o
        // teste que a sustenta, e um ID que nunca existe em report.Tests
        // nunca casa com nada. Este teste roda o pipeline completo com um
        // disco doente e um volume de sistema com pouco espaco livre e
        // confere que TODO RelatedTestId de TODA correlacao aponta para um
        // Id que de fato existe em report.Tests.
        private static void CorrelationRelatedTestIdsExist(TestRunner t)
        {
            t.Suite("Regressao: RelatedTestIds das correlacoes sempre apontam para um teste que existe");

            Inventory inv = HealthyMachine();
            inv.Disks[0].HealthStatus = "Unhealthy";
            inv.Events.DiskControllerErrors = 12;

            // Reaproveita o volume de sistema (C:) que HealthyMachine() ja
            // cria - adicionar um segundo VolumeInfo com a mesma letra
            // duplicaria o ID STO-005-C gerado por StorageTests.cs.
            inv.Volumes[0].FreePercent = 3.0;

            ScanContext ctx = Fixture.Context(true);
            DiagnosticReport report = DiagnosticEngine.Analyze(ctx, inv, Suites());

            Dictionary<string, bool> testIds = new Dictionary<string, bool>();
            foreach (TestResult r in report.Tests) if (r.Id != null) testIds[r.Id] = true;

            int correlationsChecked = 0, relatedIdsChecked = 0, missing = 0;
            foreach (Correlation c in report.Correlations)
            {
                correlationsChecked++;
                foreach (string relatedId in c.RelatedTestIds)
                {
                    relatedIdsChecked++;
                    if (!testIds.ContainsKey(relatedId)) missing++;
                }
            }

            t.True("pelo menos uma correlacao foi produzida neste cenario", correlationsChecked > 0);
            t.True("pelo menos um RelatedTestId foi de fato conferido", relatedIdsChecked > 0);
            t.Equal("nenhum RelatedTestId aponta para um Id inexistente em report.Tests", 0, missing);
        }

        private static List<IDiagnosticTest> Suites()
        {
            List<IDiagnosticTest> suites = new List<IDiagnosticTest>();
            suites.Add(new SystemTests());
            suites.Add(new CpuTests());
            suites.Add(new MemoryTests());
            suites.Add(new GpuTests());
            suites.Add(new StorageTests());
            suites.Add(new DeviceTests());
            suites.Add(new NetworkTests());
            suites.Add(new SecurityTests());
            suites.Add(new BatteryTests());
            suites.Add(new EventTests());
            suites.Add(new PerformanceTests());
            suites.Add(new StressTests());
            return suites;
        }

        // Maquina sintetica saudavel, para exercitar o pipeline inteiro:
        // Collector -> Inventory -> Test -> Analise -> Relatorio.
        private static Inventory HealthyMachine()
        {
            Inventory inv = new Inventory();

            inv.Machine.Manufacturer = "Dell Inc.";
            inv.Machine.Model = "Latitude 5420";
            inv.Machine.Hostname = "PC-CLIENTE";
            inv.Machine.SerialNumber = "5CD1234ABC";
            inv.Machine.IsPortable = true;
            inv.Machine.FormFactor = "Notebook";

            inv.Os.Caption = "Windows 11 Pro";
            inv.Os.BuildNumber = 22631;
            inv.Os.DisplayVersion = "23H2";
            inv.Os.ActivationStatus = "Ativado";
            inv.Os.IsActivated = true;
            inv.Os.UptimeHours = 12;
            inv.Os.LastUpdateInstalled = DateTime.Now.AddDays(-10);
            inv.Os.UpdatesInstalledCount = 42;

            inv.Firmware.FirmwareType = "UEFI";
            inv.Firmware.FirmwareTypeSource = "GetFirmwareType (API nativa)";
            inv.Firmware.SecureBootState = "Ativado";
            inv.Firmware.TpmPresent = true;
            inv.Firmware.TpmVersion = "2.0";
            inv.Firmware.TpmEnabled = true;
            inv.Firmware.ReleaseDate = DateTime.Now.AddYears(-2);
            inv.Firmware.AgeYears = 2;

            inv.Cpu.Name = "11th Gen Intel(R) Core(TM) i7-1185G7";
            inv.Cpu.PhysicalCores = 4;
            inv.Cpu.LogicalProcessors = 8;
            inv.Cpu.SocketCount = 1;
            inv.Cpu.WmiStatus = "OK";
            inv.Cpu.TemperatureC = 52;
            inv.Cpu.TemperatureSource = "Sensor de hardware";
            inv.Cpu.VirtualizationEnabled = true;

            inv.Memory.InstalledBytes = 17179869184UL;
            inv.Memory.UsableBytes = 16800000000UL;
            inv.Memory.ReservedBytes = inv.Memory.InstalledBytes.Value - inv.Memory.UsableBytes.Value;
            inv.Memory.UsagePercent = 45;
            inv.Memory.AvailableBytes = 9000000000UL;
            inv.Memory.SlotsUsed = 2;
            inv.Memory.SlotsTotalReportedByFirmware = 2;

            MemoryModule m1 = new MemoryModule();
            m1.Slot = "ChannelA-DIMM0"; m1.CapacityBytes = 8589934592UL; m1.ConfiguredSpeedMhz = 3200; m1.MemoryType = "DDR4";
            MemoryModule m2 = new MemoryModule();
            m2.Slot = "ChannelB-DIMM0"; m2.CapacityBytes = 8589934592UL; m2.ConfiguredSpeedMhz = 3200; m2.MemoryType = "DDR4";
            inv.Memory.Modules.Add(m1);
            inv.Memory.Modules.Add(m2);
            inv.Memory.ChannelConfiguration = MemoryCollector.InferChannelConfiguration(inv.Memory.Modules);

            GpuInfo gpu = new GpuInfo();
            gpu.Name = "Intel(R) Iris(R) Xe Graphics";
            gpu.PciVendorId = "8086";
            gpu.Kind = "Integrada";
            gpu.DriverVersion = "31.0.101.4502";
            gpu.DriverDate = DateTime.Now.AddMonths(-8);
            gpu.DriverAgeYears = 0.7;
            gpu.DriverProvider = "Intel Corporation";
            gpu.IsGenericMicrosoftDriver = false;
            inv.Gpus.Add(gpu);

            DiskInfo disk = new DiskInfo();
            disk.Index = 0;
            disk.Model = "SAMSUNG MZVLB512HBJQ";
            disk.SerialNumber = "S4ENNF0M123456";
            disk.MediaType = "SSD";
            disk.BusType = "NVMe";
            disk.SizeBytes = 512110190592UL;
            disk.HealthStatus = "Healthy";
            disk.OperationalStatus = "OK";
            disk.WearPercent = 4;
            disk.PowerOnHours = 3200;
            disk.TemperatureC = 41;
            disk.TemperatureSource = "MSFT_StorageReliabilityCounter";
            disk.SmartPredictFailure = false;
            disk.SmartSource = "MSStorageDriver_FailurePredictStatus";
            disk.IsBootDisk = true;
            disk.VolumeLetters.Add("C:");
            inv.Disks.Add(disk);

            VolumeInfo vol = new VolumeInfo();
            vol.DriveLetter = "C:";
            vol.Label = "Windows";
            vol.FileSystem = "NTFS";
            vol.SizeBytes = 510000000000UL;
            vol.FreeBytes = 300000000000UL;
            vol.FreePercent = 58.8;
            vol.IsBootVolume = true;
            vol.PhysicalDiskIndex = 0;
            vol.BitLockerStatus = "Criptografado";
            vol.BitLockerSource = "Win32_EncryptableVolume";
            vol.DirtyBit = false;
            inv.Volumes.Add(vol);

            inv.Security.BitLockerSystemDrive = "Criptografado";
            inv.Security.DefenderRealtimeProtection = "Enabled";
            inv.Security.DefenderSignatureAgeDays = 1;
            inv.Security.DefenderSignatureDate = DateTime.Now.AddDays(-1);
            inv.Security.FirewallDomain = "Enabled";
            inv.Security.FirewallPrivate = "Enabled";
            inv.Security.FirewallPublic = "Enabled";
            inv.Security.UacState = "Enabled";
            inv.Security.UacConsentPromptLevel = 5;
            inv.Security.GuestAccountEnabled = false;
            inv.Security.BuiltinAdminEnabled = false;
            inv.Security.LocalAccountsEnabled = 2;

            BatteryInfo battery = new BatteryInfo();
            battery.Name = "DELL ABC123";
            battery.ChargePercent = 88;
            battery.Status = "Totalmente carregada";
            battery.DesignCapacityMwh = 60000;
            battery.FullChargeCapacityMwh = 55000;
            battery.HealthPercent = 91.7;
            battery.CycleCount = 120;
            battery.HealthSource = "powercfg /batteryreport";
            inv.Battery = battery;

            NetworkAdapterInfo nic = new NetworkAdapterInfo();
            nic.Name = "Wi-Fi";
            nic.InterfaceType = "Wi-Fi";
            nic.IsUp = true;
            nic.MacAddress = "AA:BB:CC:DD:EE:FF";
            nic.IPv4Addresses.Add("192.168.0.10");
            nic.Gateways.Add("192.168.0.1");
            nic.DnsServers.Add("192.168.0.1");
            inv.Network.Adapters.Add(nic);
            inv.Network.AdaptersUp = 1;
            inv.Network.GatewayReachable = "Yes";
            inv.Network.DnsResolves = "Yes";
            inv.Network.HttpsReachable = "Yes";
            inv.Network.InternetReachable = "Yes";
            inv.Network.ConnectivityNote = NetworkCollector.BuildConnectivityDiagnosis(inv.Network);

            inv.Events.Accessible = true;
            inv.Events.WindowDays = 7;
            inv.Events.WheaCorrectedCount = 0;
            inv.Events.WheaUncorrectedCount = 0;
            inv.Events.UnexpectedShutdowns = 0;
            inv.Events.DiskControllerErrors = 0;
            inv.Events.MinidumpCount = 0;
            inv.Events.ServiceFailures = 0;
            inv.Events.AppCrashes = 1;
            inv.Events.BugChecksCollected = true;
            EventBucket bucket = new EventBucket();
            bucket.LogName = "System"; bucket.Critical = 0; bucket.Error = 4; bucket.Warning = 12;
            inv.Events.Buckets.Add(bucket);

            inv.DevicesNativeSourceAvailable = true;
            DeviceInfo device = new DeviceInfo();
            device.InstanceId = @"PCI\VEN_8086&DEV_9A49\3&11583659&0&10";
            device.Name = "Intel(R) Iris(R) Xe Graphics";
            device.Class = "Display";
            device.IsPresent = true;
            inv.Devices.Add(device);

            DriverInfo driver = new DriverInfo();
            driver.DeviceName = "Intel(R) Iris(R) Xe Graphics";
            driver.Provider = "Intel Corporation";
            driver.Version = "31.0.101.4502";
            driver.IsSigned = true;
            inv.Drivers.Add(driver);

            inv.Performance.CpuLoadPercent = 8;
            inv.Performance.ProcessCount = 180;

            SoftwareInfo office = new SoftwareInfo();
            office.Name = "Microsoft 365 Apps"; office.Category = "Office"; office.Version = "16.0";
            inv.Software.Add(office);

            return inv;
        }

        private static void FullPipeline(TestRunner t)
        {
            t.Suite("Integracao: pipeline completo");

            ScanContext ctx = Fixture.Context(true);
            Inventory inv = HealthyMachine();

            DiagnosticReport report = DiagnosticEngine.Analyze(ctx, inv, Suites());

            t.True("o pipeline produziu testes", report.Tests.Count > 20);
            t.NotNull("resumo executivo gerado", report.Summary);
            t.NotNull("metadados gerados", report.Metadata);
            t.True("saude por area calculada", report.ComponentHealth.Count > 5);

            // O valor esperado e recalculado de forma independente a partir
            // das contagens reais de report.Tests (mesma formula de
            // BuildSummary: medidos / (total - naoAplicaveis)), entao
            // qualquer divergencia entre CoveragePercent e a contagem real -
            // incluindo um valor fixo arbitrario - e detectada, sem depender
            // de a fixture desta maquina produzir 100%.
            int totalTests = 0, measuredTests = 0, notApplicableTests = 0;
            foreach (TestResult r in report.Tests)
            {
                totalTests++;
                if (r.Status == TestStatus.Pass || r.Status == TestStatus.Info || r.IsProblem) measuredTests++;
                else if (r.Status == TestStatus.NotApplicable) notApplicableTests++;
            }
            int applicableTests = totalTests - notApplicableTests;
            double expectedCoverage = applicableTests <= 0 ? 0 : Math.Round((double)measuredTests / applicableTests * 100.0, 1);
            t.Equal("cobertura reportada bate com a recalculada a partir das contagens reais (nunca um numero fixo)",
                expectedCoverage, report.Summary.CoveragePercent);

            // Cada iteracao acumula um booleano por invariante (sem break) e
            // a assertiva final le esses acumuladores reais, nunca um
            // literal fixo - garante que o cenario de area sem medicao e o
            // de area inaplicavel sejam de fato verificados sempre que
            // ocorrerem no laudo.
            bool areaSemMedicaoTemCoberturaZero = true;
            bool areaSemMedicaoTemResumoExplicito = true;
            bool areaInaplicavelTemRotulo = true;
            int areasVerificadas = 0;

            foreach (ComponentHealth c in report.ComponentHealth)
            {
                areasVerificadas++;
                if (c.TestsPassed + c.TestsProblem == 0 && !c.EntirelyNotApplicable)
                {
                    areaSemMedicaoTemCoberturaZero &= c.CoveragePercent == 0;
                    areaSemMedicaoTemResumoExplicito &= c.Summary != null &&
                        c.Summary.IndexOf("nao diz nada sobre a saude", StringComparison.Ordinal) >= 0;
                }
                if (c.EntirelyNotApplicable)
                    areaInaplicavelTemRotulo &= c.Summary != null &&
                        c.Summary.IndexOf("Nao se aplica", StringComparison.Ordinal) >= 0;
            }
            t.True("pelo menos uma area de componente foi de fato percorrida", areasVerificadas > 5);
            t.True("area sem medicao tem cobertura zero", areaSemMedicaoTemCoberturaZero);
            t.True("area sem medicao diz explicitamente que nao diz nada sobre a saude", areaSemMedicaoTemResumoExplicito);
            t.True("area inaplicavel e rotulada como tal", areaInaplicavelTemRotulo);

            t.Equal("maquina saudavel nao tem achados criticos", 0, report.Summary.CriticalIssues);
            t.True("score alto para maquina saudavel", report.Summary.HealthScore >= 85);
            t.Equal("status coerente com o score", "SAUDAVEL", report.Summary.Status);

            // Cada teste conta as violacoes E o total verificado entra num
            // Equal/True de verdade, que so passa quando NENHUMA violacao
            // existe - nao quando nenhuma foi encontrada por um loop que
            // desiste na primeira, o que garante que a suite so fica verde
            // quando os valores reais foram de fato conferidos.
            int semId = 0, semMotivo = 0, foraDeFaixa = 0, semEvidenciaEmAchado = 0, verificados = 0;
            foreach (TestResult r in report.Tests)
            {
                verificados++;
                if (string.IsNullOrEmpty(r.Id)) semId++;
                if (!r.WasExecuted && string.IsNullOrEmpty(r.NotTestedReason)) semMotivo++;
                if (r.IsProblem && (r.Confidence < Confidence.Min || r.Confidence > Confidence.Max)) foraDeFaixa++;
                if (r.IsProblem && r.Evidence.Count == 0) semEvidenciaEmAchado++;
            }
            t.True("pelo menos um teste foi de fato verificado", verificados > 20);
            t.Equal("todo teste tem ID", 0, semId);
            t.Equal("todo teste nao executado tem motivo", 0, semMotivo);
            t.Equal("todo achado tem confianca dentro de Confidence.Min..Max (nunca 0, nunca >99)", 0, foraDeFaixa);
            t.Equal("todo achado cita pelo menos uma evidencia", 0, semEvidenciaEmAchado);

            ReportEnvelope envelope = ReportEnvelope.From(report, new ComparisonResult());
            string json = JsonWriter.Serialize(envelope, false, false);

            t.DoesNotThrow("o report.json gerado e um JSON valido", delegate { JsonParser.Parse(json); });
            t.Contains("o JSON traz a impressao digital para comparacao", json, "fingerprint");
            t.Contains("o JSON traz o score", json, "healthScore");
            t.Contains("o JSON traz a versao das regras", json, "rulesVersion");

            string directory = Path.Combine(Path.GetTempPath(), "PcDiagTest_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            try
            {
                Directory.CreateDirectory(directory);
                string htmlPath = Path.Combine(directory, "report.html");
                HtmlReport.Write(htmlPath, envelope, true);

                t.True("o report.html foi gravado", File.Exists(htmlPath));
                string html = File.ReadAllText(htmlPath);
                t.Contains("o HTML declara a codificacao", html, "charset=\"UTF-8\"");
                t.Contains("o HTML traz o resumo executivo", html, "Resumo executivo");
                t.Contains("o HTML traz a secao de achados", html, "Achados");
                t.True("o HTML tem tamanho compativel com um laudo completo", html.Length > 8000);
            }
            finally
            {
                try { Directory.Delete(directory, true); } catch { }
            }
        }

        // Um modulo com TIMEOUT (ex.: Storage inteiro nunca examinado) pode
        // pesar pouco na cobertura AGREGADA perto de dezenas de outros
        // testes que passaram em outras areas - o gate de
        // MinCoverageForVerdict precisa disparar mesmo assim, para que o
        // laudo nao saia SAUDAVEL/100 com uma area inteira nunca medida.
        // Este teste reproduz o cenario: StorageTests com inv.Disks vazio
        // (como fica depois de um timeout do StorageCollector) gera so 3
        // resultados nao executados contra ~60 aprovados em outras areas -
        // cobertura agregada continua bem acima de 60%.
        private static void TimedOutModuleNeverLooksHealthy(TestRunner t)
        {
            t.Suite("Regressao: modulo com TIMEOUT nunca fica escondido atras da cobertura agregada");

            Inventory inv = HealthyMachine();
            inv.Disks.Clear(); // como StorageCollector deixa o Inventory quando abandona por timeout

            ScanContext ctx = Fixture.Context(true);
            ModuleOutcome timedOut = new ModuleOutcome();
            timedOut.Module = "Storage";
            timedOut.TimedOut = true;
            timedOut.Succeeded = false;
            timedOut.Error = "TIMEOUT apos 30000ms - a execucao continuou sem este modulo.";
            ctx.ModuleOutcomes.Add(timedOut);

            DiagnosticReport report = DiagnosticEngine.Analyze(ctx, inv, Suites());

            t.True("cobertura agregada continua alta apesar do modulo abandonado (prova o gate antigo nao bastava)",
                report.Summary.CoveragePercent >= DiagnosticEngine.MinCoverageForVerdict);
            t.True("status nunca fica SAUDAVEL com um modulo inteiro em timeout", report.Summary.Status != "SAUDAVEL");
            t.True("a area degradada entra explicitamente no resumo", report.Summary.DegradedAreas.Count > 0);
            t.Contains("o headline cita o modulo que nao rodou", report.Summary.Headline, "Storage");
        }

        // As assertivas sobre o HTML nao podem se limitar a presenca dos
        // TITULOS fixos ("Resumo executivo", "Achados", que sao strings
        // estaticas sempre emitidas) e ao tamanho total do arquivo - e
        // preciso conferir que um achado especifico aparece dentro da
        // secao. Este teste monta uma maquina com um defeito conhecido e
        // concreto e confere que o TEXTO do achado (nao so o titulo da
        // secao) chega ao HTML, e que o numero de blocos de achado bate com
        // report.Tests.Count(r => r.IsProblem).
        private static void HtmlRendersKnownFinding(TestRunner t)
        {
            t.Suite("Integracao: HTML renderiza achados de verdade");

            Inventory inv = HealthyMachine();
            inv.Disks[0].HealthStatus = "Unhealthy";

            ScanContext ctx = Fixture.Context(true);
            DiagnosticReport report = DiagnosticEngine.Analyze(ctx, inv, Suites());

            int problems = 0;
            foreach (TestResult r in report.Tests) if (r.IsProblem) problems++;
            t.True("a maquina sintetica tem pelo menos um achado real", problems > 0);

            ReportEnvelope envelope = ReportEnvelope.From(report, new ComparisonResult());
            string directory = Path.Combine(Path.GetTempPath(), "PcDiagTest_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            try
            {
                Directory.CreateDirectory(directory);
                string htmlPath = Path.Combine(directory, "report.html");
                HtmlReport.Write(htmlPath, envelope, true);
                string html = File.ReadAllText(htmlPath);

                t.Contains("o texto do achado (nao so o titulo da secao) chega ao HTML",
                    html, "diferente de Healthy");
                t.Contains("a recomendacao do achado chega ao HTML", html, "backup");

                // Isola o cartao "Achados" (que so contem Finding(sb, t) por
                // TestResult problematico) do resto do documento - correlacoes
                // e a tabela "Todos os testes" tambem usam marcacao parecida
                // em outras secoes e nao devem entrar nesta contagem.
                int start = html.IndexOf("<h2>Achados</h2>", StringComparison.Ordinal);
                int end = start >= 0 ? html.IndexOf("<h2>", start + 10, StringComparison.Ordinal) : -1;
                t.True("a secao Achados foi localizada no HTML", start >= 0 && end > start);
                string achadosSection = start >= 0 && end > start ? html.Substring(start, end - start) : "";

                int blocks = CountOccurrences(achadosSection, "class=\"finding");
                t.Equal("o numero de blocos de achado no HTML bate com report.Tests.Count(IsProblem)", problems, blocks);
            }
            finally
            {
                try { Directory.Delete(directory, true); } catch { }
            }
        }

        private static int CountOccurrences(string haystack, string needle)
        {
            int count = 0, index = 0;
            while ((index = haystack.IndexOf(needle, index, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                count++;
                index += needle.Length;
            }
            return count;
        }

        // HtmlReport.cs imprime um banner dizendo que numero de
        // serie/hostname/usuario/MAC/IP foram substituidos por [REDACTED]
        // quando --privacy-safe esta ativo. Isso so e verdade se
        // Redaction.Apply (Redaction.cs) for chamado uma unica vez em
        // Entry.cs ANTES de qualquer formato de saida ser gerado - a ordem
        // importa. Este teste reproduz o pipeline real (Redaction.Apply ->
        // Write) e confere que o dado sensivel nao sobrevive no arquivo
        // entregue.
        private static void PrivacySafeHtmlDoesNotLeak(TestRunner t)
        {
            t.Suite("Integracao: modo privacidade nao vaza dado sensivel no HTML");

            Inventory inv = HealthyMachine();
            inv.Machine.SerialNumber = "5CD1234ABC";
            inv.Machine.Hostname = "PC-CLIENTE-REAL";

            ScanContext ctx = Fixture.Context(true);
            ctx.Options.PrivacySafe = true;
            DiagnosticReport report = DiagnosticEngine.Analyze(ctx, inv, Suites());
            ReportEnvelope envelope = ReportEnvelope.From(report, new ComparisonResult());

            Redaction.Apply(envelope, "algum-usuario-que-nao-aparece");

            string directory = Path.Combine(Path.GetTempPath(), "PcDiagTest_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            try
            {
                Directory.CreateDirectory(directory);
                string htmlPath = Path.Combine(directory, "report.html");
                HtmlReport.Write(htmlPath, envelope, true);
                string html = File.ReadAllText(htmlPath);

                t.DoesNotContain("numero de serie real nao aparece no HTML com --privacy-safe", html, "5CD1234ABC");
                t.DoesNotContain("hostname real nao aparece no HTML com --privacy-safe", html, "PC-CLIENTE-REAL");
                t.Contains("o banner de modo privacidade e verdadeiro - o dado foi mesmo mascarado", html, "[REDACTED]");
            }
            finally
            {
                try { Directory.Delete(directory, true); } catch { }
            }
        }

        // REGRESSAO: no coletor antigo, nome de dispositivo e mensagem de
        // evento entravam crus no HTML.
        private static void HostileInputInReport(TestRunner t)
        {
            t.Suite("Integracao: conteudo hostil no laudo");

            Inventory inv = HealthyMachine();
            inv.Machine.Hostname = "<script>alert('xss')</script>";
            inv.Machine.Model = "Modelo \"aspas\" & <b>tags</b>";
            inv.Disks[0].Model = "<img src=x onerror=alert(1)>";

            DeviceInfo hostile = new DeviceInfo();
            hostile.InstanceId = "USB\\VID_0000";
            hostile.Name = "</td></tr><script>evil()</script>";
            hostile.Class = "USB";
            hostile.IsPresent = true;
            hostile.ProblemCode = 10;
            hostile.ProblemMeaning = Native.ProblemCodeMeaning(10);
            hostile.IsHardwareSuspect = true;
            inv.Devices.Add(hostile);

            ScanContext ctx = Fixture.Context(true);
            DiagnosticReport report = DiagnosticEngine.Analyze(ctx, inv, Suites());
            ReportEnvelope envelope = ReportEnvelope.From(report, new ComparisonResult());

            string directory = Path.Combine(Path.GetTempPath(), "PcDiagTest_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            try
            {
                Directory.CreateDirectory(directory);
                string htmlPath = Path.Combine(directory, "report.html");
                HtmlReport.Write(htmlPath, envelope, true);
                string html = File.ReadAllText(htmlPath);

                t.DoesNotContain("script do hostname nao chega cru ao HTML", html, "<script>alert('xss')</script>");
                t.DoesNotContain("tag de imagem maliciosa nao chega crua", html, "<img src=x onerror");
                t.DoesNotContain("quebra de tabela injetada nao chega crua", html, "</td></tr><script>");
                t.Contains("o conteudo aparece escapado", html, "&lt;script&gt;");
                t.Contains("o nome do dispositivo continua legivel no laudo", html, "evil()");

                string json = JsonWriter.Serialize(envelope, false, false);
                t.DoesNotThrow("o JSON continua valido com conteudo hostil", delegate { JsonParser.Parse(json); });
            }
            finally
            {
                try { Directory.Delete(directory, true); } catch { }
            }
        }

        // Injecao de falha (item 48): toda fonte quebrada ao mesmo tempo. A
        // ferramenta precisa produzir um laudo honesto, nao morrer.
        private static void FailureInjection(TestRunner t)
        {
            t.Suite("Injecao de falha: todas as fontes quebradas");

            FakeWmi wmi = new FakeWmi();
            wmi.Fail("Win32_ComputerSystem", new System.Management.ManagementException("WMI indisponivel"));
            wmi.Fail("Win32_OperatingSystem", new System.Management.ManagementException("WMI indisponivel"));
            wmi.Fail("Win32_Processor", new TimeoutException("consulta expirou"));
            wmi.Fail("MSFT_PhysicalDisk", new UnauthorizedAccessException("acesso negado"));
            wmi.Fail("Win32_VideoController", new Exception("provedor corrompido"));
            wmi.Fail("Win32_NetworkAdapter", new Exception("falha"));
            wmi.Fail("Win32_Service", new Exception("falha"));
            wmi.Fail("Win32_Battery", new Exception("falha"));

            FakeRegistry registry = new FakeRegistry();
            registry.Deny("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            registry.Deny("HKLM", @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");

            FakeEventLog events = new FakeEventLog();
            events.FailWith(new UnauthorizedAccessException("log negado"));

            FakeProcessRunner processes = new FakeProcessRunner();

            ScanContext ctx = Fixture.Context(false);
            SourceSet sources = Fixture.Sources(wmi, registry, events, processes);
            Inventory inv = new Inventory();

            List<ICollector> collectors = new List<ICollector>();
            collectors.Add(new SystemCollector());
            collectors.Add(new CpuCollector());
            collectors.Add(new MemoryCollector());
            collectors.Add(new GpuCollector());
            collectors.Add(new StorageCollector());
            collectors.Add(new NetworkCollector(false));
            collectors.Add(new SecurityCollector());
            collectors.Add(new BatteryCollector());
            collectors.Add(new EventsCollector(7));
            collectors.Add(new SoftwareCollector());
            collectors.Add(new StressCollector());
            // Sensor e Performance tambem precisam ser exercitados aqui,
            // junto com os coletores acima. Device fica de fora deste
            // cenario especifico: CollectNative() usa cfgmgr32 via delegate
            // (Native.cs), um caminho que nao passa pelo SourceSet e
            // portanto nao ha como "quebrar" nesta simulacao - ele sempre le
            // a arvore de dispositivos REAL da maquina que roda o teste, o
            // que tornaria este cenario dependente de hardware (uma maquina
            // com um dispositivo com erro real produziria um achado de
            // severidade Alta genuino e quebraria a assercao de "cobertura
            // baixa e inconclusiva" abaixo). O caminho feliz e a
            // sobrevivencia de DeviceCollector ja sao cobertos por
            // CollectorTests.cs e pelos scans reais de ponta a ponta
            // rodados durante o desenvolvimento.
            collectors.Add(new SensorCollector());
            collectors.Add(new PerformanceCollector());

            foreach (ICollector collector in collectors)
            {
                ICollector current = collector;
                t.DoesNotThrow("modulo " + current.Name + " sobrevive a fonte quebrada", delegate
                {
                    ModuleRunner.Run(ctx, current.Name, delegate { current.Collect(ctx, sources, inv); }, 15000);
                });
            }

            DiagnosticReport report = null;
            t.DoesNotThrow("a analise roda mesmo sem inventario", delegate
            {
                report = DiagnosticEngine.Analyze(ctx, inv, Suites());
            });

            t.NotNull("um laudo foi produzido apesar de tudo falhar", report);
            t.True("os testes foram avaliados", report.Tests.Count > 20);
            t.True("a maioria fica como nao executada", report.Summary.TestsNotExecuted > 0);

            // O ponto decisivo: nenhuma falha de coleta pode virar aprovacao.
            int passedWithoutData = 0;
            foreach (TestResult r in report.Tests)
            {
                if (r.Status == TestStatus.Pass && r.Evidence.Count == 0) passedWithoutData++;
            }
            t.Equal("nenhum teste passa sem evidencia nenhuma", 0, passedWithoutData);

            t.True("a cobertura reportada e baixa e honesta", report.Summary.CoveragePercent < 60);
            t.Contains("o resumo avisa que nao da para concluir", report.Summary.Headline, "nao permite concluir");

            // Uma assertiva ">= 0" sobre um contador que nunca e negativo
            // seria tautologica - passaria mesmo com ErrorCount==0, ou seja,
            // mesmo que nenhuma das fontes WMI quebradas acima tivesse
            // deixado rastro no canal de erros. Por isso a assertiva confere
            // conteudo real: pelo menos uma entrada por classe WMI quebrada
            // precisa aparecer no canal LogChannel.Errors.
            t.True("as falhas foram registradas no log (pelo menos uma por fonte WMI quebrada)",
                ctx.Log.ErrorCount >= 8);

            string json = null;
            t.DoesNotThrow("o laudo degradado ainda serializa", delegate
            {
                json = JsonWriter.Serialize(ReportEnvelope.From(report, new ComparisonResult()), false, false);
            });
            t.DoesNotThrow("e o JSON continua valido", delegate { JsonParser.Parse(json); });
        }

        private static void BaselineComparison(TestRunner t)
        {
            t.Suite("Comparacao entre atendimentos");

            ScanContext ctx1 = Fixture.Context(true);
            Inventory before = HealthyMachine();
            DiagnosticReport reportBefore = DiagnosticEngine.Analyze(ctx1, before, Suites());

            string directory = Path.Combine(Path.GetTempPath(), "PcDiagTest_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            try
            {
                Directory.CreateDirectory(directory);
                string baselinePath = Path.Combine(directory, "report.json");
                JsonReport.Write(baselinePath, ReportEnvelope.From(reportBefore, new ComparisonResult()), false);

                // Segundo atendimento: RAM dobrada, driver atualizado, disco
                // agora com desgaste, e espaco livre menor.
                Inventory after = HealthyMachine();
                after.Memory.InstalledBytes = 34359738368UL;
                after.Memory.Modules[0].CapacityBytes = 17179869184UL;
                after.Memory.Modules[1].CapacityBytes = 17179869184UL;
                after.Gpus[0].DriverVersion = "32.0.101.5000";
                after.Disks[0].WearPercent = 22;
                after.Volumes[0].FreePercent = 9;
                after.Volumes[0].FreeBytes = 45000000000UL;

                ScanContext ctx2 = Fixture.Context(true);
                DiagnosticReport reportAfter = DiagnosticEngine.Analyze(ctx2, after, Suites());

                ComparisonResult comparison = Comparison.Compare(reportAfter, baselinePath, ctx2.Log);

                t.True("a comparacao esta disponivel", comparison.Available);
                t.NotNull("o scan de referencia foi identificado", comparison.BaselineScanId);
                t.True("mudancas foram detectadas", comparison.Changes.Count > 0);
                t.True("o score anterior foi lido", comparison.ScoreBefore.HasValue);

                bool memoryChanged = false, driverChanged = false, testChanged = false;
                foreach (ChangeEntry c in comparison.Changes)
                {
                    if (c.Key.IndexOf("memory.installedBytes", StringComparison.Ordinal) >= 0) memoryChanged = true;
                    if (c.Key.EndsWith(".driver", StringComparison.Ordinal)) driverChanged = true;
                    if (c.Key.StartsWith("test.", StringComparison.Ordinal)) testChanged = true;
                }

                t.True("upgrade de memoria foi detectado", memoryChanged);
                t.True("atualizacao de driver foi detectada", driverChanged);
                t.True("mudanca no resultado de um teste foi detectada", testChanged);

                // Comparar um scan com ele mesmo nao pode acusar mudanca.
                ComparisonResult identical = Comparison.Compare(reportBefore, baselinePath, ctx1.Log);
                int realChanges = 0;
                foreach (ChangeEntry c in identical.Changes)
                {
                    if (!c.Key.StartsWith("test.", StringComparison.Ordinal)) realChanges++;
                }
                t.Equal("scan identico nao acusa mudanca de hardware", 0, realChanges);

                // Linha de base ausente ou corrompida degrada com elegancia.
                ComparisonResult missing = Comparison.Compare(reportAfter, Path.Combine(directory, "nao-existe.json"), ctx2.Log);
                t.False("linha de base ausente nao fica disponivel", missing.Available);
                t.Contains("e o motivo e explicado", missing.Note, "nao encontrado");

                string corruptPath = Path.Combine(directory, "corrompido.json");
                File.WriteAllText(corruptPath, "{isso nao e json");
                ComparisonResult corrupt = Comparison.Compare(reportAfter, corruptPath, ctx2.Log);
                t.False("linha de base corrompida nao fica disponivel", corrupt.Available);
                t.Contains("e o motivo tambem e explicado", corrupt.Note, "ilegivel");
            }
            finally
            {
                try { Directory.Delete(directory, true); } catch { }
            }
        }

        private static void NoAdminCoverage(TestRunner t)
        {
            t.Suite("Execucao sem privilegio de Administrador");

            ScanContext ctx = Fixture.Context(false);
            Inventory inv = HealthyMachine();

            // Sem elevacao, os dados privilegiados nao existiriam.
            inv.Disks[0].SmartPredictFailure = null;
            inv.Disks[0].SmartSource = null;
            inv.Disks[0].WearPercent = null;
            inv.Disks[0].TemperatureC = null;
            inv.Cpu.TemperatureC = null;
            inv.Security.DefenderRealtimeProtection = "RequiresAdmin";
            inv.Security.DefenderSignatureAgeDays = null;
            inv.Events.Accessible = false;
            inv.Events.InaccessibleReason = "Leitura do log 'System' negada - requer privilegio de Administrador.";

            DiagnosticReport report = DiagnosticEngine.Analyze(ctx, inv, Suites());

            int requiresAdmin = 0;
            int falsePass = 0;
            foreach (TestResult r in report.Tests)
            {
                if (r.Status == TestStatus.RequiresAdmin)
                {
                    requiresAdmin++;
                    if (string.IsNullOrEmpty(r.NotTestedReason)) falsePass++;
                }
            }

            t.True("varios testes ficam como REQUER ADMIN", requiresAdmin >= 4);
            t.Equal("todos explicam o motivo", 0, falsePass);
            t.False("o score nao e penalizado pela falta de privilegio", report.Summary.HealthScore < 70);
            t.True("a cobertura reflete o que nao foi medido", report.Summary.CoveragePercent < 100);
            t.False("sem privilegio a ferramenta nao inventa criticidade", report.Summary.CriticalIssues > 0);
        }
    }
}
