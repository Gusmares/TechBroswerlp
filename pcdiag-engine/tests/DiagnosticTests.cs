using System;
using System.Collections.Generic;
using PcDiag.Analysis;
using PcDiag.Collectors;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Testing
{
    // Testes de regra de diagnostico.
    //
    // Varios destes sao TESTES DE REGRESSAO de comportamentos que
    // precisavam de correcao no coletor antigo: cada um fixa um
    // comportamento que estava errado antes, para que nao volte.
    public static class DiagnosticTests
    {
        public static void Run(TestRunner t)
        {
            Scoring(t);
            NeverPassWhenNotTested(t);
            WheaSeparation(t);
            DiskThresholdPerVolume(t);
            DiskHealthClassification(t);
            LinkSpeedUnits(t);
            GpuClassification(t);
            VramSaturation(t);
            MemoryReserved(t);
            MemoryReservedIntegratedGpuHigherThreshold(t);
            BatteryMultiple(t);
            PlaceholderSerials(t);
            ReferenceParsing(t);
            ChannelInference(t);
            DefenderReasons(t);
            FirewallUnconfirmedProfiles(t);
            DeviceSourceDegraded(t);
            FalsePositivesFoundInTheField(t);
            Correlations(t);
            ThermalAndStability(t);
            MultiSocketWorstStatus(t);
            IdleVsLoadTemperatureThresholds(t);
            GpuCode43Severity(t);
            SensorMatching(t);
            DisabledDeviceReportedAsInfo(t);
            UnknownDriverSignatureNeverCountsAsSigned(t);
            GpuConfidenceReflectsSourceQuality(t);
        }

        // SensorSource e SensorCollector nao tem fake (Fixture.Sources fixa
        // Sensors = null incondicionalmente) porque SourceSet.Sensors e
        // tipado como a classe SELADA SensorSource (Sources/SensorSource.cs),
        // que nao implementa nenhuma interface - nao da para fakear por
        // substituicao sem alterar Sources/SensorSource.cs e
        // Collectors/Base.cs, fora do escopo deste lote. O que E testavel
        // sem fake nenhum sao as duas funcoes ESTATICAS e PURAS que fazem o
        // casamento sensor->hardware, que e onde mora a logica que este
        // laudo mais depende (a temperatura de CPU e o achado mais grave
        // que a ferramenta produz): SensorSource.Find (busca por tipo de
        // hardware/sensor/nome) e SensorCollector.FindForHardware
        // (casamento por token do nome do dispositivo, ordenado do mais
        // especifico para o mais generico).
        private static void SensorMatching(TestRunner t)
        {
            t.Suite("Regressao: casamento de leitura de sensor com hardware");

            List<SensorReading> readings = new List<SensorReading>();
            SensorReading cpuTemp = new SensorReading();
            cpuTemp.Hardware = "AMD Ryzen 7 5800X"; cpuTemp.HardwareType = "Cpu"; cpuTemp.SensorType = "Temperature";
            cpuTemp.Name = "Core (Tctl/Tdie)"; cpuTemp.Value = 62.5;
            readings.Add(cpuTemp);

            SensorReading distanceToTjMax = new SensorReading();
            distanceToTjMax.Hardware = "AMD Ryzen 7 5800X"; distanceToTjMax.HardwareType = "Cpu"; distanceToTjMax.SensorType = "Temperature";
            distanceToTjMax.Name = "Core (0) Distance to TjMax"; distanceToTjMax.Value = 15.0;
            readings.Add(distanceToTjMax);

            // "Distance to TjMax" NAO e temperatura - e quanto falta para o
            // limite termico. Sem o filtro, uma CPU QUENTE (perto do limite,
            // Distance baixa) apareceria com uma leitura de temperatura
            // BAIXA - o diagnostico inverteria o sinal de superaquecimento.
            double? found = SensorSource.Find(readings, "Cpu", "Temperature", new string[] { "Core" });
            t.Equal("acha a temperatura real, nao a Distance to TjMax", 62.5, found.Value);

            List<SensorReading> onlyDistance = new List<SensorReading>();
            onlyDistance.Add(distanceToTjMax);
            t.Null("sem leitura real de temperatura, Distance sozinha nao vira resultado", SensorSource.Find(onlyDistance, "Cpu", "Temperature", null));

            t.Null("sem lista de leituras, Find nao lanca e devolve null", SensorSource.Find(null, "Cpu", "Temperature", null));

            // FindForHardware: nome do disco "Samsung 970 EVO Plus" tem o
            // fabricante ("Samsung") como primeiro token - o casamento
            // precisa preferir o token mais ESPECIFICO ("970" ou "EVO"), nao
            // o nome do fabricante, para nao confundir leituras de discos
            // diferentes do mesmo fabricante na mesma maquina.
            List<SensorReading> diskReadings = new List<SensorReading>();
            SensorReading samsungDisk = new SensorReading();
            samsungDisk.Hardware = "Samsung SSD 970 EVO Plus 1TB"; samsungDisk.HardwareType = "Storage"; samsungDisk.SensorType = "Temperature";
            samsungDisk.Name = "Temperature"; samsungDisk.Value = 41.0;
            diskReadings.Add(samsungDisk);

            SensorReading otherSamsungDisk = new SensorReading();
            otherSamsungDisk.Hardware = "Samsung SSD 870 QVO 2TB"; otherSamsungDisk.HardwareType = "Storage"; otherSamsungDisk.SensorType = "Temperature";
            otherSamsungDisk.Name = "Temperature"; otherSamsungDisk.Value = 33.0;
            diskReadings.Add(otherSamsungDisk);

            double? matched = SensorCollector.FindForHardware(diskReadings, "Storage", "Temperature", "Samsung SSD 970 EVO Plus 1TB");
            t.Equal("casa pelo token mais especifico do nome, nao pelo fabricante", 41.0, matched.Value);

            t.Null("sem nome de dispositivo, FindForHardware nao lanca e devolve null",
                SensorCollector.FindForHardware(diskReadings, "Storage", "Temperature", null));
        }

        // Maquina de 2 sockets com socket0=OK e socket1=Degraded - o status
        // agregado precisa ser o PIOR entre as linhas, nao so o da primeira.
        private static void MultiSocketWorstStatus(TestRunner t)
        {
            t.Suite("Regressao: CPU de 2 sockets nao esconde socket degradado");

            FakeWmi wmi = new FakeWmi();
            wmi.On("Win32_Processor",
                FakeWmi.Row("Name", "Intel(R) Xeon(R) CPU E5-2620 v4", "SocketDesignation", "CPU0",
                    "NumberOfCores", 8, "NumberOfLogicalProcessors", 16, "Status", "OK"),
                FakeWmi.Row("Name", "Intel(R) Xeon(R) CPU E5-2620 v4", "SocketDesignation", "CPU1",
                    "NumberOfCores", 8, "NumberOfLogicalProcessors", 16, "Status", "Degraded"));

            ScanContext ctx = Fixture.Context(false);
            Inventory inv = new Inventory();
            new CpuCollector().Collect(ctx, Fixture.Sources(wmi, new FakeRegistry(), new FakeEventLog(), new FakeProcessRunner()), inv);

            t.Equal("status agregado e o PIOR entre os sockets, nao o do primeiro", "Degraded", inv.Cpu.WmiStatus);

            TestResult cpu001 = new List<TestResult>(new CpuTests().Run(ctx, inv))[0];
            t.Equal("CPU-001 acusa o socket degradado", TestStatus.Error, cpu001.Status);
        }

        // Os mesmos limiares de carga (85/95 C) nao podem ser aplicados a
        // uma leitura de repouso, e uma leitura de repouso nao pode ser
        // rotulada "sob carga total" so porque o modulo de stress RODOU
        // (Executed=true) sem produzir amostra termica sob carga de verdade.
        private static void IdleVsLoadTemperatureThresholds(TestRunner t)
        {
            t.Suite("Regressao: limiares de temperatura de CPU distintos para repouso x carga");

            // 70 C em repouso: abaixo do limiar de CARGA (85), mas acima do
            // limiar de REPOUSO (60) - tinha que acusar atencao, e antes do
            // fix passava batido como PASS.
            Inventory idle = new Inventory();
            idle.Cpu.TemperatureC = 70;
            idle.Stress = null;
            TestResult idleResult = new List<TestResult>(new CpuTests().Run(Ctx(true), idle))[1]; // Temperature() e o segundo teste da suite
            t.Equal("70 C em repouso aciona o limiar de REPOUSO (60), nao o de carga (85)", TestStatus.Warning, idleResult.Status);
            t.Contains("o contexto do achado diz 'em repouso'", idleResult.Result, "repouso");

            // Modulo de stress rodou (Executed=true) mas SEM produzir
            // amostra termica sob carga (CpuMaxTempC null - sensor
            // indisponivel so durante a fase de carga): a leitura que
            // sobrou e a de repouso, e afirmar "sob carga total" seria
            // etiqueta falsa.
            Inventory executedButNoLoadSample = new Inventory();
            executedButNoLoadSample.Cpu.TemperatureC = 70;
            executedButNoLoadSample.Stress = new StressResults();
            executedButNoLoadSample.Stress.Executed = true;
            executedButNoLoadSample.Stress.CpuMaxTempC = null;
            TestResult noSampleResult = new List<TestResult>(new CpuTests().Run(Ctx(true), executedButNoLoadSample))[1];
            t.Contains("Executed=true sem CpuMaxTempC ainda e tratado como repouso, nao como carga", noSampleResult.Result, "repouso");
        }

        // ARQUITETURA.md 5 define "Dispositivo com Code 43/10 -> ERROR/HIGH",
        // nao CRITICAL.
        private static void GpuCode43Severity(TestRunner t)
        {
            t.Suite("Regressao: GPU Code 43 segue ARQUITETURA.md 5 (ERROR/HIGH, nao CRITICAL)");

            GpuInfo g = new GpuInfo();
            g.Name = "GPU de teste";
            g.ConfigManagerErrorCode = 43;
            Inventory inv = new Inventory();
            inv.Gpus.Add(g);

            TestResult gpu001 = new List<TestResult>(new GpuTests().Run(Ctx(true), inv))[0];
            t.Equal("Code 43 e ERROR (nao CRITICAL)", TestStatus.Error, gpu001.Status);
            t.Equal("severidade High", Severity.High, gpu001.Severity);
        }

        // Sem segunda fonte independente confirmando o estado da GPU,
        // AgreeingSource() nao pode ser reivindicado; e quando a
        // classificacao veio de heuristica de nome em vez de identificador
        // estavel, a confianca precisa ser MENOR ainda que a de uma
        // classificacao por VendorId - nunca igual.
        private static void GpuConfidenceReflectsSourceQuality(TestRunner t)
        {
            t.Suite("Regressao: confianca de GPU reflete a qualidade real da fonte");

            GpuInfo byVendorId = new GpuInfo();
            byVendorId.Name = "NVIDIA GeForce RTX 4060";
            byVendorId.Kind = "Dedicada";
            byVendorId.KindSource = "VendorId";
            Inventory invVendorId = new Inventory();
            invVendorId.Gpus.Add(byVendorId);
            TestResult gpuVendorId = new List<TestResult>(new GpuTests().Run(Ctx(true), invVendorId))[0];

            GpuInfo byHeuristic = new GpuInfo();
            byHeuristic.Name = "AMD Radeon RX 6600";
            byHeuristic.Kind = "Dedicada";
            byHeuristic.KindSource = "Heuristica de nome (AMD)";
            Inventory invHeuristic = new Inventory();
            invHeuristic.Gpus.Add(byHeuristic);
            TestResult gpuHeuristic = new List<TestResult>(new GpuTests().Run(Ctx(true), invHeuristic))[0];

            t.True("classificacao por heuristica de nome tem confianca menor que por VendorId",
                gpuHeuristic.Confidence < gpuVendorId.Confidence);
            // 70 (Authoritative) sem AgreeingSource - nunca 80, que exigiria
            // uma segunda fonte de fato confirmada.
            t.Equal("sem segunda fonte confirmada, VendorId fica em 70 (nao 80)", 70, gpuVendorId.Confidence);
        }

        // A analise termica e de estabilidade so pode ser exercitada de ponta
        // a ponta com sensores e privilegio de Administrador. Aqui ela e
        // testada como funcao pura sobre uma linha do tempo sintetica - que e
        // exatamente o motivo de os testes nao acessarem o sistema.
        private static void ThermalAndStability(TestRunner t)
        {
            t.Suite("Carga: estabilidade aritmetica");

            Inventory inv = StressInventory();
            inv.Stress.Cpu.ArithmeticErrors = 3;
            inv.Stress.Cpu.FaultyProcessors.Add(5);
            inv.Stress.Cpu.FirstErrorDetail = "acumulador 2, faixa 1: esperado 2097152, obtido 2097151";

            List<TestResult> results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            TestResult stability = Find(results, "STR-002");
            t.Equal("erro de calculo sob carga e critico", TestStatus.Critical, stability.Status);
            t.True("o laudo diz em qual processador logico o erro apareceu",
                stability.Result.IndexOf("5", StringComparison.Ordinal) >= 0);

            inv.Stress.Cpu.ArithmeticErrors = 0;
            inv.Stress.Cpu.FaultyProcessors.Clear();
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("sem erro de calculo o teste passa", TestStatus.Pass, Find(results, "STR-002").Status);

            // Sem o motor nativo nao ha conferencia possivel: o resultado
            // precisa ser "nao verificado", jamais "aprovado".
            inv.Stress.EngineFallbackReason = "VirtualProtect bloqueado por politica";
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("sem verificacao aritmetica o teste nao e aprovado",
                TestStatus.NotTested, Find(results, "STR-002").Status);
            inv.Stress.EngineFallbackReason = null;

            t.Suite("Carga: temperatura e ventoinha");

            // Sem sensor, o teste termico NUNCA pode virar aprovacao.
            inv.Stress.Thermal = new ThermalProfile();
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("carga sem sensor de temperatura nao vira aprovacao",
                TestStatus.NotTested, Find(results, "STR-001").Status);

            inv.Stress.Thermal = Thermal(40, 98, 12.0, 3000);
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("98 C sob carga passa do limiar critico", TestStatus.Error, Find(results, "STR-001").Status);

            inv.Stress.Thermal = Thermal(40, 88, 12.0, 3000);
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("88 C sob carga gera atencao", TestStatus.Warning, Find(results, "STR-001").Status);

            inv.Stress.Thermal = Thermal(40, 72, 12.0, 3000);
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("72 C sob carga total e aprovado", TestStatus.Pass, Find(results, "STR-001").Status);

            // Ventoinha parada com a CPU quente e defeito que o diagnostico em
            // repouso nunca pega - em repouso ela legitimamente nao gira.
            inv.Stress.Thermal = Thermal(40, 92, 12.0, 0);
            inv.Stress.Thermal.IdleFanRpm = 0;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("ventoinha parada com CPU a 92 C e critico",
                TestStatus.Critical, Find(results, "STR-005").Status);

            // A mesma ventoinha parada com a maquina fria nao acusa defeito:
            // pode ser controle semi-passivo funcionando.
            inv.Stress.Thermal = Thermal(30, 45, 12.0, 0);
            inv.Stress.Thermal.IdleFanRpm = 0;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("ventoinha parada com a maquina fria nao acusa defeito",
                TestStatus.Unknown, Find(results, "STR-005").Status);

            inv.Stress.Thermal = Thermal(40, 90, 12.0, 1020);
            inv.Stress.Thermal.IdleFanRpm = 1000;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("ventoinha que nao acelera com o calor gera atencao",
                TestStatus.Warning, Find(results, "STR-005").Status);

            t.Suite("Carga: throttling e recuperacao termica");

            inv.Stress.Thermal = Thermal(40, 94, 12.0, 3000);
            inv.Stress.Cpu.FirstWindowGflops = 700;
            inv.Stress.Cpu.LastWindowGflops = 420;
            inv.Stress.Cpu.SustainPercent = 60;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("perda de 40% do desempenho sob carga e erro de alta severidade",
                TestStatus.Error, Find(results, "STR-004").Status);

            inv.Stress.Cpu.LastWindowGflops = 630;
            inv.Stress.Cpu.SustainPercent = 90;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("perda de 10% gera atencao", TestStatus.Info, Find(results, "STR-004").Status);

            inv.Stress.Cpu.LastWindowGflops = 693;
            inv.Stress.Cpu.SustainPercent = 99;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("desempenho mantido e aprovado", TestStatus.Pass, Find(results, "STR-004").Status);

            // Recuperacao: o par subida/descida separa projeto apertado de
            // dissipador entupido.
            inv.Stress.Thermal.RecoveryTempC = 75;
            inv.Stress.Thermal.RecoverySeconds = 45;
            inv.Stress.Thermal.CooldownRateCPerMinute = 25;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("continuar 35 C acima do repouso apos a carga gera atencao",
                TestStatus.Warning, Find(results, "STR-007").Status);

            inv.Stress.Thermal.RecoveryTempC = 45;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("voltar ao patamar de repouso e aprovado",
                TestStatus.Pass, Find(results, "STR-007").Status);

            t.Suite("Carga: integridade de memoria e disco");

            inv.Stress.Memory = new MemoryStressResult();
            inv.Stress.Memory.Executed = true;
            inv.Stress.Memory.BytesTested = 512L * 1024L * 1024L;
            inv.Stress.Memory.Passes = 2;
            inv.Stress.Memory.PatternsRun.Add("xadrez 0xAA");
            inv.Stress.Memory.ErrorCount = 1;
            inv.Stress.Memory.FirstErrorDetail = "padrao 'xadrez 0xAA', palavra 91231";

            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("uma unica divergencia de memoria ja e critica",
                TestStatus.Critical, Find(results, "STR-008").Status);

            inv.Stress.Memory.ErrorCount = 0;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("memoria sem divergencia e aprovada", TestStatus.Pass, Find(results, "STR-008").Status);

            // Dado que volta diferente do que foi gravado supera qualquer
            // consideracao de velocidade: 900 MB/s num SSD passaria folgado.
            DiskBenchmark disk = new DiskBenchmark();
            disk.DriveLetter = "C:";
            disk.PhysicalDiskIndex = 0;
            disk.MediaType = "SSD";
            disk.WriteMbPerSec = 900;
            disk.IntegrityChecked = true;
            disk.IntegrityErrors = 2;
            inv.Stress.DiskBenchmarks.Clear();
            inv.Stress.DiskBenchmarks.Add(disk);

            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("corrupcao na releitura supera a velocidade aprovada",
                TestStatus.Critical, Find(results, "STR-003-C").Status);

            t.Suite("Carga: GPU nunca e aprovada sem carga 3D");

            // A ferramenta nao aplica carga grafica. GPU quente vale como
            // achado; GPU fria NAO vale como aprovacao.
            inv.Stress.Thermal.MaxGpuTempC = 40;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("GPU fria sem carga 3D fica como informativo, nunca aprovado",
                TestStatus.Info, Find(results, "STR-013").Status);

            inv.Stress.Thermal.MaxGpuTempC = 95;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("GPU a 95 C sem carga 3D e erro de alta severidade",
                TestStatus.Error, Find(results, "STR-013").Status);

            t.Suite("Carga: GPU com --gpu-stress (carga 3D real)");

            // Com carga real E aceleracao de hardware confirmada, GPU fria
            // agora PODE ser aprovada de verdade - e exatamente o que a
            // ferramenta nao podia afirmar antes de existir esta fase.
            inv.Stress.Gpu = new GpuStressResult();
            inv.Stress.Gpu.Executed = true;
            inv.Stress.Gpu.HardwareAccelerated = true;
            inv.Stress.Gpu.RenderDevice = "NVIDIA GeForce GTX 1660 SUPER";
            inv.Stress.Thermal.MaxGpuTempC = 40;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("GPU fria sob carga 3D real e aprovada",
                TestStatus.Pass, Find(results, "STR-013").Status);

            inv.Stress.Thermal.MaxGpuTempC = 95;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("GPU a 95 C sob carga 3D real continua erro de alta severidade",
                TestStatus.Error, Find(results, "STR-013").Status);

            // Renderizador de SOFTWARE (GPU hibrida mal configurada, sessao
            // remota): a fase rodou, mas nao tocou GPU nenhuma - nao pode
            // aprovar nada, mesmo com a fase "executada".
            inv.Stress.Gpu.HardwareAccelerated = false;
            inv.Stress.Gpu.RenderDevice = "GDI Generic";
            inv.Stress.Thermal.MaxGpuTempC = 40;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("carga em renderizador de software nunca aprova a GPU",
                TestStatus.Info, Find(results, "STR-013").Status);

            t.Suite("Carga: sustentacao de fps da GPU");

            inv.Stress.Gpu.HardwareAccelerated = true;
            inv.Stress.Gpu.RenderDevice = "NVIDIA GeForce GTX 1660 SUPER";

            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("sem dados de fps o teste de sustentacao nao e testado",
                TestStatus.NotTested, Find(results, "STR-014").Status);

            inv.Stress.Gpu.FirstWindowFps = 240;
            inv.Stress.Gpu.LastWindowFps = 120;
            inv.Stress.Gpu.SustainPercent = 50;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("perda de 50% do fps e erro de alta severidade",
                TestStatus.Error, Find(results, "STR-014").Status);

            inv.Stress.Gpu.LastWindowFps = 236;
            inv.Stress.Gpu.SustainPercent = 98;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("fps mantido e aprovado", TestStatus.Pass, Find(results, "STR-014").Status);

            // Em renderizador de software o fps nao significa nada sobre a
            // GPU - nunca pode virar aprovacao nem erro.
            inv.Stress.Gpu.HardwareAccelerated = false;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("fps em renderizador de software nao e testado",
                TestStatus.NotTested, Find(results, "STR-014").Status);

            inv.Stress.Gpu = null;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            t.Equal("sem --gpu-stress o teste de sustentacao nao e testado",
                TestStatus.NotTested, Find(results, "STR-014").Status);
        }

        private static Inventory StressInventory()
        {
            Inventory inv = new Inventory();
            inv.Cpu.LogicalProcessors = 12;

            inv.Stress = new StressResults();
            inv.Stress.Executed = true;
            inv.Stress.DurationSeconds = 180;
            inv.Stress.Engine = "FMA de 256 bits (AVX2), 14 cadeias independentes";

            inv.Stress.Cpu = new CpuStressResult();
            inv.Stress.Cpu.ThreadCount = 12;
            inv.Stress.Cpu.ThreadsPinned = true;
            inv.Stress.Cpu.DurationSeconds = 180;
            inv.Stress.Cpu.TotalOperations = 44627864322048L;
            inv.Stress.Cpu.MaxLoadPercent = 100;

            return inv;
        }

        private static ThermalProfile Thermal(double idle, double max, double secondsToPeak, double maxFanRpm)
        {
            ThermalProfile p = new ThermalProfile();
            p.IdleTempC = idle;
            p.MaxTempC = max;
            p.AverageUnderLoadC = (idle + max) / 2;
            p.SecondsToPeak = secondsToPeak;
            p.RampRateCPerMinute = (max - idle) / secondsToPeak * 60.0;
            p.MaxFanRpm = maxFanRpm;
            p.IdleFanRpm = maxFanRpm > 0 ? 800 : 0;
            return p;
        }

        // REGRESSAO: os dois falsos positivos que a propria ferramenta produziu
        // na primeira execucao real, antes de serem corrigidos.
        private static void FalsePositivesFoundInTheField(TestRunner t)
        {
            t.Suite("Regressao: falsos positivos vistos em execucao real");

            // 1) O Windows Defender roda de ProgramData por design (ele se
            // atualiza fora do Windows Update). Acusa-lo de suspeito levaria o
            // tecnico a mexer justamente na protecao da maquina.
            t.False("binario do Defender em ProgramData nao e local incomum",
                Helpers.IsUnusualExecutableLocation(
                    @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MsMpEng.exe"));

            t.False("servico normal em Program Files nao e local incomum",
                Helpers.IsUnusualExecutableLocation(@"C:\Program Files\App\svc.exe"));
            t.False("servico do sistema nao e local incomum",
                Helpers.IsUnusualExecutableLocation(@"C:\Windows\System32\svchost.exe"));

            // Os locais genuinamente anomalos continuam sendo sinalizados.
            t.True("Temp do usuario continua sendo local incomum",
                Helpers.IsUnusualExecutableLocation(@"C:\Users\Ana\AppData\Local\Temp\x.exe"));
            t.True("AppData\\Roaming continua sendo local incomum",
                Helpers.IsUnusualExecutableLocation(@"C:\Users\Ana\AppData\Roaming\thing\svc.exe"));
            t.True("Downloads continua sendo local incomum",
                Helpers.IsUnusualExecutableLocation(@"C:\Users\Ana\Downloads\setup.exe"));
            t.True("lixeira continua sendo local incomum",
                Helpers.IsUnusualExecutableLocation(@"C:\$Recycle.Bin\S-1-5-21\x.exe"));

            // 2) HTREE\ROOT\0 e a raiz da arvore de dispositivos e existe em
            // toda maquina Windows: nao e um dispositivo sem driver.
            t.True("HTREE e reconhecido como pseudo-dispositivo",
                Helpers.IsPseudoEnumerator("HTREE", @"HTREE\ROOT\0"));
            t.True("SWD e reconhecido como pseudo-dispositivo",
                Helpers.IsPseudoEnumerator("SWD", @"SWD\PRINTENUM\..."));
            t.False("PCI e hardware de verdade", Helpers.IsPseudoEnumerator("PCI", @"PCI\VEN_8086"));
            t.False("USB e hardware de verdade", Helpers.IsPseudoEnumerator("USB", @"USB\VID_046D"));

            Inventory inv = new Inventory();

            DeviceInfo treeRoot = new DeviceInfo();
            treeRoot.InstanceId = @"HTREE\ROOT\0";
            treeRoot.Name = @"HTREE\ROOT\0";
            treeRoot.Enumerator = "HTREE";
            treeRoot.IsPresent = true;
            inv.Devices.Add(treeRoot);

            DeviceInfo realDevice = new DeviceInfo();
            realDevice.InstanceId = @"PCI\VEN_8086&DEV_1234\3&abc";
            realDevice.Name = "Placa de rede";
            realDevice.Class = "Net";
            realDevice.Enumerator = "PCI";
            realDevice.IsPresent = true;
            inv.Devices.Add(realDevice);

            List<TestResult> results = new List<TestResult>(new DeviceTests().Run(Ctx(true), inv));
            TestResult unknownDevices = Find(results, "DEV-002");
            t.Equal("a raiz da arvore nao vira 'dispositivo sem driver'", TestStatus.Pass, unknownDevices.Status);

            // Hardware real sem driver continua sendo detectado.
            DeviceInfo missingDriver = new DeviceInfo();
            missingDriver.InstanceId = @"PCI\VEN_10EC&DEV_8168\4&xyz";
            missingDriver.Name = "Unknown device";
            missingDriver.Enumerator = "PCI";
            missingDriver.IsPresent = true;
            missingDriver.ProblemCode = 28;
            missingDriver.ProblemMeaning = Native.ProblemCodeMeaning(28);
            inv.Devices.Add(missingDriver);

            results = new List<TestResult>(new DeviceTests().Run(Ctx(true), inv));
            unknownDevices = Find(results, "DEV-002");
            t.Equal("hardware real sem driver continua sendo sinalizado", TestStatus.Warning, unknownDevices.Status);
            t.Contains("o laudo cita o dispositivo certo", unknownDevices.Result, "Unknown device");
        }

        private static ScanContext Ctx(bool elevated)
        {
            return Fixture.Context(elevated);
        }

        private static void Scoring(TestRunner t)
        {
            t.Suite("Pontuacao (score)");

            List<TestResult> tests = new List<TestResult>();
            t.Equal("sem achados o score e 100", 100, DiagnosticEngine.ComputeScore(tests));

            TestResult critical = T.Make("X-1", "x", "c", "d");
            T.Critical(critical, "grave", "fazer algo", 90);
            tests.Add(critical);
            t.Equal("um achado critico desconta 40", 60, DiagnosticEngine.ComputeScore(tests));
            t.Equal("achado critico forca status CRITICO", "CRITICO", DiagnosticEngine.ScoreStatus(60, true, 100.0));

            // O ponto mais importante do modelo de score: nao ter conseguido
            // medir NAO e defeito do equipamento e nao pode descontar pontos.
            List<TestResult> skipped = new List<TestResult>();
            TestResult notTested = T.Make("X-2", "y", "c", "d");
            T.NotTested(notTested, "sem privilegio");
            skipped.Add(notTested);

            TestResult requiresAdmin = T.Make("X-3", "z", "c", "d");
            T.RequiresAdmin(requiresAdmin, "Ler SMART");
            skipped.Add(requiresAdmin);

            TestResult notApplicable = T.Make("X-4", "w", "c", "d");
            T.NotApplicable(notApplicable, "desktop sem bateria");
            skipped.Add(notApplicable);

            t.Equal("testes nao executados nao descontam pontos", 100, DiagnosticEngine.ComputeScore(skipped));
            t.Equal("penalidade de NotTested e zero", 0, DiagnosticEngine.Penalty(notTested));
            t.Equal("penalidade de RequiresAdmin e zero", 0, DiagnosticEngine.Penalty(requiresAdmin));

            TestResult info = T.Make("X-5", "i", "c", "d");
            T.Info(info, "apenas contexto", 80);
            t.Equal("resultado informativo nao desconta", 0, DiagnosticEngine.Penalty(info));

            TestResult warnHigh = T.Make("X-6", "wh", "c", "d");
            T.Warn(warnHigh, Severity.High, "r", "rec", 80);
            TestResult warnLow = T.Make("X-7", "wl", "c", "d");
            T.Warn(warnLow, Severity.Low, "r", "rec", 80);
            t.True("severidade alta desconta mais que baixa",
                DiagnosticEngine.Penalty(warnHigh) > DiagnosticEngine.Penalty(warnLow));

            t.Equal("score nunca fica negativo", 0, DiagnosticEngine.ComputeScore(
                new List<TestResult> { critical, critical, critical, critical }));

            t.Equal("faixa saudavel", "SAUDAVEL", DiagnosticEngine.ScoreStatus(90, false, 100.0));
            t.Equal("faixa de atencao", "ATENCAO", DiagnosticEngine.ScoreStatus(70, false, 100.0));
            t.Equal("faixa critica por score baixo", "CRITICO", DiagnosticEngine.ScoreStatus(40, false, 100.0));

            // Cobertura baixa tem que vencer o score, mesmo um score "bom"
            // (nada foi medido = nada descontou). Achado critico ainda vence
            // o gate de cobertura - e informacao real, nao pode ficar
            // escondida atras de "inconclusivo".
            t.Equal("cobertura baixa vira INCONCLUSIVO mesmo com score 100", "INCONCLUSIVO",
                DiagnosticEngine.ScoreStatus(100, false, 0.0));
            t.Equal("cobertura no limiar (60%) ainda e um veredito de verdade", "SAUDAVEL",
                DiagnosticEngine.ScoreStatus(90, false, 60.0));
            t.Equal("cobertura logo abaixo do limiar vira INCONCLUSIVO", "INCONCLUSIVO",
                DiagnosticEngine.ScoreStatus(90, false, 59.9));
            t.Equal("achado critico vence o gate de cobertura", "CRITICO",
                DiagnosticEngine.ScoreStatus(60, true, 0.0));

            // Score 88 (so um Warning/High descontando 12 pontos) nao pode
            // sair SAUDAVEL e verde - hasHigh forca no minimo ATENCAO, no
            // mesmo espirito de hasCritical.
            t.Equal("achado de alta severidade nunca fica escondido atras de score alto", "ATENCAO",
                DiagnosticEngine.ScoreStatus(88, false, true, 100.0));
            t.Equal("achado High vence o gate de cobertura, igual achado Critical", "ATENCAO",
                DiagnosticEngine.ScoreStatus(90, false, true, 0.0));
            t.Equal("score < 50 ainda vence hasHigh - nao rebaixa CRITICO genuino para ATENCAO", "CRITICO",
                DiagnosticEngine.ScoreStatus(40, false, true, 100.0));
            t.Equal("hasCritical sempre vence hasHigh", "CRITICO",
                DiagnosticEngine.ScoreStatus(88, true, true, 100.0));
        }

        // REGRESSAO: no coletor antigo, quando Get-WinEvent falhava, o fallback
        // era a mensagem "Nenhum evento de erro encontrado" - ou seja, falha de
        // leitura virava atestado de saude.
        private static void NeverPassWhenNotTested(TestRunner t)
        {
            t.Suite("Regressao: ausencia de dado nunca vira aprovacao");

            Inventory inv = new Inventory();
            inv.Events.Accessible = false;
            inv.Events.InaccessibleReason = "Leitura do log 'System' negada - requer privilegio de Administrador.";
            inv.Events.WindowDays = 7;

            ScanContext ctx = Ctx(false);
            List<TestResult> results = new List<TestResult>(new MemoryTests().Run(ctx, inv));

            TestResult whea = Find(results, "MEM-005");
            t.NotNull("teste de erros WHEA existe", whea);
            t.False("log inacessivel nao produz aprovacao", whea.Status == TestStatus.Pass);
            t.Equal("log inacessivel por privilegio vira REQUER ADMIN", TestStatus.RequiresAdmin, whea.Status);
            t.NotNull("resultado nao executado sempre traz o motivo", whea.NotTestedReason);

            // Idem para disco: sem SMART disponivel, o teste nao pode passar.
            Inventory inv2 = new Inventory();
            DiskInfo d = new DiskInfo();
            d.Index = 0;
            d.Model = "DISCO TESTE";
            d.HealthStatus = "Healthy";
            d.MediaType = "SSD";
            inv2.Disks.Add(d);

            List<TestResult> storage = new List<TestResult>(new StorageTests().Run(Ctx(false), inv2));
            TestResult smart = Find(storage, "STO-002-01");
            t.NotNull("teste SMART existe", smart);
            t.Equal("sem privilegio o SMART vira REQUER ADMIN", TestStatus.RequiresAdmin, smart.Status);
            t.False("SMART indisponivel nao e aprovacao", smart.Status == TestStatus.Pass);

            TestResult wear = Find(storage, "STO-003-01");
            t.Equal("desgaste sem privilegio vira REQUER ADMIN", TestStatus.RequiresAdmin, wear.Status);
        }

        // REGRESSAO: o coletor antigo somava eventos WHEA de qualquer nivel e
        // chamava tudo de "erro de hardware na memoria", inclusive erros
        // CORRIGIDOS, que sao rotina em maquina saudavel.
        private static void WheaSeparation(TestRunner t)
        {
            t.Suite("Regressao: WHEA corrigido nao e defeito");

            Inventory inv = new Inventory();
            inv.Events.Accessible = true;
            inv.Events.WindowDays = 7;
            inv.Events.WheaCorrectedCount = 12;
            inv.Events.WheaUncorrectedCount = 0;

            List<TestResult> results = new List<TestResult>(new MemoryTests().Run(Ctx(true), inv));
            TestResult whea = Find(results, "MEM-005");

            t.Equal("erros apenas corrigidos ficam como INFO", TestStatus.Info, whea.Status);
            t.False("erros corrigidos nao contam como problema", whea.IsProblem);
            t.Equal("erro corrigido nao desconta pontos", 0, DiagnosticEngine.Penalty(whea));
            t.Contains("o texto explica que corrigido e rotina", whea.Result, "saudaveis");

            inv.Events.WheaUncorrectedCount = 2;
            results = new List<TestResult>(new MemoryTests().Run(Ctx(true), inv));
            whea = Find(results, "MEM-005");

            t.Equal("erro nao corrigido vira ERRO", TestStatus.Error, whea.Status);
            t.Equal("severidade alta para erro nao corrigido", Severity.High, whea.Severity);
            t.Contains("recomendacao nao atribui o erro so a memoria", whea.Recommendation, "PCIe");

            // Se SO a consulta de NAO corrigidos falhar (fica null) mas a
            // de corrigidos responder, o teste nao pode afirmar "nenhum nao
            // corrigido" - essa e exatamente a contagem que faltou.
            Inventory onlyCorrectedKnown = new Inventory();
            onlyCorrectedKnown.Events.Accessible = true;
            onlyCorrectedKnown.Events.WindowDays = 7;
            onlyCorrectedKnown.Events.WheaCorrectedCount = 5;
            onlyCorrectedKnown.Events.WheaUncorrectedCount = null;
            List<TestResult> partial = new List<TestResult>(new MemoryTests().Run(Ctx(true), onlyCorrectedKnown));
            TestResult wheaPartial = Find(partial, "MEM-005");
            t.Equal("sem a contagem de NAO corrigidos o teste nao pode concluir", TestStatus.NotTested, wheaPartial.Status);
            t.False("nao vira Info afirmando 'nenhum nao corrigido' sem ter medido isso", wheaPartial.Status == TestStatus.Info);
        }

        // REGRESSAO: o coletor antigo decidia o limiar com "existe ALGUM SSD na
        // maquina?", entao julgava um HD com regua de SSD e gerava alerta falso
        // de disco degradado.
        private static void DiskThresholdPerVolume(TestRunner t)
        {
            t.Suite("Regressao: limiar de disco por volume, nao por maquina");

            Inventory inv = new Inventory();

            DiskInfo ssd = new DiskInfo();
            ssd.Index = 0; ssd.MediaType = "SSD"; ssd.Model = "SSD RAPIDO";
            inv.Disks.Add(ssd);

            DiskInfo hdd = new DiskInfo();
            hdd.Index = 1; hdd.MediaType = "HDD"; hdd.Model = "HD MECANICO";
            inv.Disks.Add(hdd);

            VolumeInfo volumeOnHdd = new VolumeInfo();
            volumeOnHdd.DriveLetter = "D:";
            volumeOnHdd.PhysicalDiskIndex = 1;
            inv.Volumes.Add(volumeOnHdd);

            t.Equal("o volume D: e mapeado para o HD, nao para o SSD",
                "HDD", StressCollector.MediaTypeForVolume(inv, volumeOnHdd));

            inv.Stress = new StressResults();
            inv.Stress.Executed = true;
            inv.Stress.DurationSeconds = 20;

            DiskBenchmark benchmark = new DiskBenchmark();
            benchmark.DriveLetter = "D:";
            benchmark.PhysicalDiskIndex = 1;
            benchmark.MediaType = "HDD";
            benchmark.WriteMbPerSec = 120;  // normal para HD, "lento" para SSD
            inv.Stress.DiskBenchmarks.Add(benchmark);

            List<TestResult> results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            TestResult diskTest = Find(results, "STR-003-D");

            t.NotNull("teste de velocidade do volume D existe", diskTest);
            t.Equal("120 MB/s em HD e aprovado (nao e alerta de SSD lento)", TestStatus.Pass, diskTest.Status);

            benchmark.MediaType = "SSD";
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            diskTest = Find(results, "STR-003-D");
            t.Equal("os mesmos 120 MB/s em SSD tambem passam", TestStatus.Pass, diskTest.Status);

            benchmark.WriteMbPerSec = 30;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            diskTest = Find(results, "STR-003-D");
            t.Equal("30 MB/s em SSD gera atencao", TestStatus.Warning, diskTest.Status);

            benchmark.MediaType = "HDD";
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            diskTest = Find(results, "STR-003-D");
            t.Equal("os mesmos 30 MB/s em HD sao aprovados", TestStatus.Pass, diskTest.Status);

            benchmark.MediaType = null;
            results = new List<TestResult>(new StressTests().Run(Ctx(true), inv));
            diskTest = Find(results, "STR-003-D");
            t.Equal("sem tipo de disco conhecido nao ha julgamento", TestStatus.Info, diskTest.Status);
        }

        // STO-001 precisa exigir igualdade explicita com "Healthy" e tratar
        // tudo mais (Unhealthy, Warning, ou um valor desconhecido/futuro que
        // a WMI venha a expor) como Critical, alinhado com ARQUITETURA.md 5
        // ("Saude de disco != Healthy -> CRITICAL/CRITICAL") - nunca um Pass
        // generico para um valor que nao seja explicitamente "Healthy".
        private static void DiskHealthClassification(TestRunner t)
        {
            t.Suite("Regressao: classificacao de saude do disco != Healthy");

            t.Equal("Healthy explicito e aprovado", TestStatus.Pass, DiskHealthResult("Healthy").Status);
            t.Equal("Unhealthy vira Critical", TestStatus.Critical, DiskHealthResult("Unhealthy").Status);
            t.Equal("Warning tambem vira Critical (nao mais Error/High)", TestStatus.Critical, DiskHealthResult("Warning").Status);
            t.Equal("Unknown continua Unknown, nao Critical nem Pass", TestStatus.Unknown, DiskHealthResult("Unknown").Status);

            TestResult futureEnum = DiskHealthResult("Degraded");
            t.Equal("valor nao reconhecido nunca cai num Pass generico", TestStatus.Critical, futureEnum.Status);
            t.Contains("o laudo cita o valor bruto recebido, nao afirma Healthy", futureEnum.Result, "Degraded");
        }

        private static TestResult DiskHealthResult(string status)
        {
            Inventory inv = new Inventory();
            DiskInfo d = new DiskInfo();
            d.Index = 0;
            d.HealthStatus = status;
            inv.Disks.Add(d);
            List<TestResult> results = new List<TestResult>(new StorageTests().Run(Ctx(true), inv));
            return Find(results, "STO-001-01");
        }

        // REGRESSAO: o coletor antigo dividia bits/s por 1048576, exibindo
        // 953 Mbps num link de 1 Gbps.
        private static void LinkSpeedUnits(TestRunner t)
        {
            t.Suite("Regressao: unidade de velocidade de link");

            Inventory inv = new Inventory();
            NetworkAdapterInfo a = new NetworkAdapterInfo();
            a.Name = "Ethernet";
            a.InterfaceType = "Ethernet";
            a.IsUp = true;
            a.LinkSpeedBitsPerSecond = 1000000000L;
            inv.Network.Adapters.Add(a);

            List<TestResult> results = new List<TestResult>(new NetworkTests().Run(Ctx(true), inv));
            TestResult link = Find(results, "NET-003");

            string evidence = "";
            foreach (Evidence e in link.Evidence) evidence += e.Value + " ";

            t.Contains("1 Gbps aparece como 1000 Mbps", evidence, "1000 Mbps");
            t.DoesNotContain("nao aparece o valor errado de 953 Mbps", evidence, "953");
            t.Equal("link gigabit e aprovado", TestStatus.Pass, link.Status);

            a.LinkSpeedBitsPerSecond = 100000000L;
            results = new List<TestResult>(new NetworkTests().Run(Ctx(true), inv));
            link = Find(results, "NET-003");
            t.Equal("link de 100 Mbps vira informativo", TestStatus.Info, link.Status);
        }

        private static void GpuClassification(TestRunner t)
        {
            t.Suite("Classificacao de GPU");

            GpuInfo nvidia = new GpuInfo();
            nvidia.Name = "NVIDIA GeForce RTX 4060";
            nvidia.PciVendorId = "10DE";
            GpuCollector.Classify(nvidia, null);
            t.Equal("NVIDIA e dedicada", "Dedicada", nvidia.Kind);
            t.Contains("fonte da classificacao e o VendorId", nvidia.KindSource, "VendorId");

            GpuInfo intel = new GpuInfo();
            intel.Name = "Intel(R) UHD Graphics 620";
            intel.PciVendorId = "8086";
            GpuCollector.Classify(intel, null);
            t.Equal("Intel comum e integrada", "Integrada", intel.Kind);

            GpuInfo arc = new GpuInfo();
            arc.Name = "Intel(R) Arc(TM) A770 Graphics";
            arc.PciVendorId = "8086";
            GpuCollector.Classify(arc, null);
            t.Equal("Intel Arc e dedicada", "Dedicada", arc.Kind);

            GpuInfo radeon = new GpuInfo();
            radeon.Name = "AMD Radeon RX 6600";
            radeon.PciVendorId = "1002";
            GpuCollector.Classify(radeon, null);
            t.Equal("Radeon RX e dedicada", "Dedicada", radeon.Kind);

            GpuInfo apu = new GpuInfo();
            apu.Name = "AMD Radeon(TM) Graphics";
            apu.PciVendorId = "1002";
            GpuCollector.Classify(apu, null);
            t.Equal("grafico integrado de APU e integrado", "Integrada", apu.Kind);

            GpuInfo vm = new GpuInfo();
            vm.Name = "VMware SVGA 3D";
            vm.PciVendorId = "15AD";
            GpuCollector.Classify(vm, null);
            t.Equal("adaptador de maquina virtual e identificado", "Virtual", vm.Kind);

            // Honestidade: quando nao da para decidir, o resultado e
            // "Indeterminado", nunca um chute apresentado como fato.
            GpuInfo unknown = new GpuInfo();
            unknown.Name = "Placa Generica";
            unknown.PciVendorId = "ABCD";
            GpuCollector.Classify(unknown, null);
            t.Equal("fabricante desconhecido fica indeterminado", "Indeterminado", unknown.Kind);
        }

        // REGRESSAO: AdapterRAM e DWORD de 32 bits e satura em ~4 GB. O valor
        // saturado nao pode ser apresentado como se fosse a VRAM real.
        private static void VramSaturation(TestRunner t)
        {
            t.Suite("Regressao: VRAM saturada em 32 bits");

            FakeWmi wmi = new FakeWmi();
            wmi.On("Win32_VideoController", FakeWmi.Row(
                "Name", "NVIDIA GeForce RTX 4060",
                "PNPDeviceID", @"PCI\VEN_10DE&DEV_2882&SUBSYS_40BD1458&REV_A1\4&2ab1c5f&0&0008",
                "AdapterRAM", (uint)4293918720,
                "DriverVersion", "31.0.15.3623",
                "Status", "OK"));

            FakeRegistry registry = new FakeRegistry();
            ScanContext ctx = Ctx(true);
            Inventory inv = new Inventory();

            new GpuCollector().Collect(ctx, Fixture.Sources(wmi, registry, null, null), inv);

            t.Equal("a GPU fisica foi coletada", 1, inv.Gpus.Count);
            GpuInfo g = inv.Gpus[0];
            t.Null("valor saturado nao e apresentado como VRAM real", g.VramBytes);
            t.Contains("o motivo da ausencia e explicito", g.VramSource, "32 bits");
            t.Equal("PCI VendorId extraido", "10DE", g.PciVendorId);
            t.Equal("PCI DeviceId extraido", "2882", g.PciDeviceId);

            // Com o valor de 64 bits no registro, a VRAM correta aparece.
            registry.SubKeys("HKLM", @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}", "0000");
            string key = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000";
            registry.Value("HKLM", key, "DriverDesc", "NVIDIA GeForce RTX 4060");
            registry.Value("HKLM", key, "MatchingDeviceId", @"pci\ven_10de&dev_2882");
            registry.Value("HKLM", key, "HardwareInformation.qwMemorySize", 8589934592UL);

            Inventory inv2 = new Inventory();
            new GpuCollector().Collect(Ctx(true), Fixture.Sources(wmi, registry, null, null), inv2);
            t.Equal("VRAM de 64 bits lida do registro", 8589934592UL, inv2.Gpus[0].VramBytes);
            t.Contains("fonte da VRAM e registrada", inv2.Gpus[0].VramSource, "qwMemorySize");
        }

        private static void MemoryReserved(TestRunner t)
        {
            t.Suite("Memoria instalada x utilizavel");

            Inventory inv = new Inventory();
            inv.Memory.InstalledBytes = 34359738368UL;   // 32 GB
            inv.Memory.UsableBytes = 31890604032UL;      // ~29,7 GB
            inv.Memory.ReservedBytes = inv.Memory.InstalledBytes.Value - inv.Memory.UsableBytes.Value;

            GpuInfo integrated = new GpuInfo();
            integrated.Kind = "Integrada";
            inv.Gpus.Add(integrated);

            List<TestResult> results = new List<TestResult>(new MemoryTests().Run(Ctx(true), inv));
            TestResult reserved = Find(results, "MEM-002");

            t.Equal("reserva pequena com video integrado e contexto, nao alerta", TestStatus.Info, reserved.Status);
            t.Contains("o laudo explica a causa da reserva", reserved.Result, "GPU integrada");
            t.Equal("resultado informativo nao desconta pontos", 0, DiagnosticEngine.Penalty(reserved));

            // Reserva muito grande deixa de ser explicavel por video integrado.
            inv.Memory.UsableBytes = 17179869184UL;  // metade
            inv.Memory.ReservedBytes = inv.Memory.InstalledBytes.Value - inv.Memory.UsableBytes.Value;
            results = new List<TestResult>(new MemoryTests().Run(Ctx(true), inv));
            reserved = Find(results, "MEM-002");

            t.Equal("reserva de 50% vira alerta", TestStatus.Warning, reserved.Status);
            t.Contains("a recomendacao aponta o msconfig", reserved.Recommendation, "msconfig");
        }

        // Cenario real (8 GB instalados, 6 GB utilizaveis, GPU integrada com
        // Kind=Integrada) - reserva de 25%, explicavel pela UMA da GPU
        // integrada (chega a ~2 GB em 8 GB de RAM). Nao pode virar alerta so
        // por bater num numero redondo.
        private static void MemoryReservedIntegratedGpuHigherThreshold(TestRunner t)
        {
            t.Suite("Regressao: reserva de memoria com GPU integrada usa limiar mais alto");

            Inventory inv = new Inventory();
            inv.Memory.InstalledBytes = 8589934592UL;    // 8 GB
            inv.Memory.UsableBytes = 6442450944UL;       // 6 GB (25% reservado)
            inv.Memory.ReservedBytes = inv.Memory.InstalledBytes.Value - inv.Memory.UsableBytes.Value;

            GpuInfo integrated = new GpuInfo();
            integrated.Kind = "Integrada";
            integrated.Name = "AMD Radeon(TM) Vega 8 Graphics";
            inv.Gpus.Add(integrated);

            List<TestResult> results = new List<TestResult>(new MemoryTests().Run(Ctx(true), inv));
            TestResult reserved = Find(results, "MEM-002");

            t.Equal("25% de reserva com GPU integrada nao e alerta", TestStatus.Info, reserved.Status);

            // Sem GPU integrada, o mesmo 25% ja e alerta - o limiar so sobe
            // quando ha video integrado de fato presente.
            inv.Gpus.Clear();
            results = new List<TestResult>(new MemoryTests().Run(Ctx(true), inv));
            reserved = Find(results, "MEM-002");
            t.Equal("25% de reserva SEM GPU integrada continua sendo alerta", TestStatus.Warning, reserved.Status);
        }

        // REGRESSAO: o coletor antigo lia apenas a PRIMEIRA bateria do XML,
        // errando a saude em notebooks com duas baterias.
        private static void BatteryMultiple(TestRunner t)
        {
            t.Suite("Regressao: notebook com duas baterias");

            string xml =
                "<?xml version=\"1.0\"?><BatteryReport xmlns=\"http://schemas.microsoft.com/battery/2012\">" +
                "<Batteries>" +
                "<Battery><DesignCapacity>50000</DesignCapacity><FullChargeCapacity>25000</FullChargeCapacity><CycleCount>300</CycleCount></Battery>" +
                "<Battery><DesignCapacity>50000</DesignCapacity><FullChargeCapacity>45000</FullChargeCapacity><CycleCount>150</CycleCount></Battery>" +
                "</Batteries></BatteryReport>";

            BatteryInfo b = new BatteryInfo();
            BatteryCollector.ParseBatteryReport(xml, b);

            t.Equal("capacidade de projeto soma as duas baterias", 100000, b.DesignCapacityMwh);
            t.Equal("capacidade atual soma as duas baterias", 70000, b.FullChargeCapacityMwh);
            t.Equal("saude calculada sobre o conjunto", 70d, b.HealthPercent);
            t.Equal("ciclos usam o maior valor entre as baterias", 300, b.CycleCount);

            // Bateria nova as vezes reporta um pouco acima de 100%; satura
            // para 100% sem afirmar um fato que os dados nao sustentam.
            string overSmall = "<?xml version=\"1.0\"?><BatteryReport xmlns=\"http://schemas.microsoft.com/battery/2012\">" +
                "<Batteries><Battery><DesignCapacity>50000</DesignCapacity><FullChargeCapacity>51000</FullChargeCapacity></Battery></Batteries></BatteryReport>";
            BatteryInfo b2 = new BatteryInfo();
            BatteryCollector.ParseBatteryReport(overSmall, b2);
            t.Equal("saude pouco acima de 100% e limitada a 100%", 100d, b2.HealthPercent);

            // Excesso GRANDE (> 105%) e sinal de DesignCapacity
            // subestimada/unidade divergente, nao de bateria saudavel -
            // saturar em silencio para 100% seria um PASS falso.
            string overLarge = "<?xml version=\"1.0\"?><BatteryReport xmlns=\"http://schemas.microsoft.com/battery/2012\">" +
                "<Batteries><Battery><DesignCapacity>50000</DesignCapacity><FullChargeCapacity>54000</FullChargeCapacity></Battery></Batteries></BatteryReport>";
            BatteryInfo b3 = new BatteryInfo();
            BatteryCollector.ParseBatteryReport(overLarge, b3);
            t.Null("excesso grande (>105%) nao vira saude 100% falsa", b3.HealthPercent);
            t.True("o motivo e os valores brutos ficam em HealthSource",
                b3.HealthSource != null && b3.HealthSource.Contains("DesignCapacity=50000") && b3.HealthSource.Contains("FullChargeCapacity=54000"));

            t.DoesNotThrow("XML vazio nao lanca", delegate { BatteryCollector.ParseBatteryReport("", new BatteryInfo()); });
        }

        private static void PlaceholderSerials(TestRunner t)
        {
            t.Suite("Valores de template do SMBIOS");

            t.True("'To be filled by O.E.M.' e placeholder", SystemCollector.IsPlaceholder("To be filled by O.E.M."));
            t.True("'Default string' e placeholder", SystemCollector.IsPlaceholder("Default string"));
            t.True("'System Serial Number' e placeholder", SystemCollector.IsPlaceholder("System Serial Number"));
            t.True("sequencia repetida e placeholder", SystemCollector.IsPlaceholder("00000000"));
            t.True("string vazia e placeholder", SystemCollector.IsPlaceholder("   "));
            t.True("nulo e placeholder", SystemCollector.IsPlaceholder(null));
            t.False("serial real nao e placeholder", SystemCollector.IsPlaceholder("5CD1234ABC"));
            t.False("modelo real nao e placeholder", SystemCollector.IsPlaceholder("Latitude 5420"));
        }

        private static void ReferenceParsing(TestRunner t)
        {
            t.Suite("Parsing de referencias WMI");

            t.Equal("formato completo do provedor",
                "Disk #0, Partition #1",
                StorageCollector.ExtractDeviceIdFromReference(
                    "\\\\PC\\root\\cimv2:Win32_DiskPartition.DeviceID=\"Disk #0, Partition #1\""));

            t.Equal("formato abreviado",
                "C:",
                StorageCollector.ExtractDeviceIdFromReference("Win32_LogicalDisk (DeviceID = \"C:\")"));

            t.Null("referencia vazia devolve null", StorageCollector.ExtractDeviceIdFromReference(""));
            t.Null("referencia sem DeviceID devolve null", StorageCollector.ExtractDeviceIdFromReference("qualquer coisa"));

            // Escape WQL: ObjectId de storage contem aspas e barras.
            t.Equal("barras e aspas sao escapadas no WQL",
                "a\\\\b\\\"c",
                StorageCollector.EscapeWqlLiteral("a\\b\"c"));

            t.Equal("letra de unidade normalizada", "C:", Helpers.NormalizeDriveLetter("c"));
            t.Equal("letra com dois pontos normalizada", "D:", Helpers.NormalizeDriveLetter("d:"));
            t.Null("valor invalido nao vira letra", Helpers.NormalizeDriveLetter("xyz"));
        }

        private static void ChannelInference(TestRunner t)
        {
            t.Suite("Inferencia de canais de memoria");

            List<MemoryModule> dual = new List<MemoryModule>();
            dual.Add(Module("ChannelA-DIMM0"));
            dual.Add(Module("ChannelB-DIMM0"));
            t.Contains("dois canais identificados", MemoryCollector.InferChannelConfiguration(dual), "Dual-channel");

            List<MemoryModule> single = new List<MemoryModule>();
            single.Add(Module("DIMM_A1"));
            t.Contains("um modulo e single-channel", MemoryCollector.InferChannelConfiguration(single), "Single-channel");

            // Quando os rotulos nao permitem concluir, o resultado e null
            // (desconhecido) em vez de um palpite.
            List<MemoryModule> opaque = new List<MemoryModule>();
            opaque.Add(Module("SlotX"));
            opaque.Add(Module("SlotY"));
            t.Null("rotulos opacos nao geram palpite", MemoryCollector.InferChannelConfiguration(opaque));

            t.Null("lista vazia devolve null", MemoryCollector.InferChannelConfiguration(new List<MemoryModule>()));
            t.Null("lista nula devolve null", MemoryCollector.InferChannelConfiguration(null));
        }

        private static MemoryModule Module(string slot)
        {
            MemoryModule m = new MemoryModule();
            m.Slot = slot;
            m.CapacityBytes = 8589934592UL;
            return m;
        }

        // Quando a fonte nativa (SetupAPI/CfgMgr32) falha mas a WMI ainda
        // enche inv.Devices, DEV-001 nao pode aprovar "zero problema" citando
        // confianca de duas fontes - SetupAPI e a fonte que enxerga
        // dispositivo oculto/fantasma, e ela nunca respondeu nesse cenario.
        private static void DeviceSourceDegraded(TestRunner t)
        {
            t.Suite("Regressao: fonte nativa de dispositivos indisponivel nao aprova as cegas");

            Inventory inv = new Inventory();
            inv.DevicesNativeSourceAvailable = false;
            inv.DevicesNativeSourceUnavailableReason = "teste: SetupAPI falhou";
            DeviceInfo wmiOnly = new DeviceInfo();
            wmiOnly.InstanceId = "PCI\\TESTE";
            wmiOnly.Name = "Dispositivo via WMI";
            wmiOnly.IsPresent = true;
            inv.Devices.Add(wmiOnly);

            List<TestResult> results = new List<TestResult>(new DeviceTests().Run(Ctx(true), inv));
            TestResult dev001 = Find(results, "DEV-001");
            t.False("fonte nativa indisponivel nunca aprova as cegas", dev001.Status == TestStatus.Pass);
            t.Equal("vira Unknown, nao Pass, quando zero problemas mas a fonte autoritativa nao respondeu",
                TestStatus.Unknown, dev001.Status);

            inv.DevicesNativeSourceAvailable = true;
            results = new List<TestResult>(new DeviceTests().Run(Ctx(true), inv));
            dev001 = Find(results, "DEV-001");
            t.Equal("com a fonte nativa disponivel, zero problema volta a ser Pass", TestStatus.Pass, dev001.Status);
        }

        // Dispositivo desativado administrativamente (Code 22 - placa de
        // rede/Wi-Fi desligada no Gerenciador de Dispositivos, causa
        // frequente de "nao conecta") nao pode sumir dentro de um Pass
        // generico quando nao ha nenhum outro problema.
        private static void DisabledDeviceReportedAsInfo(TestRunner t)
        {
            t.Suite("Regressao: dispositivo desativado (Code 22) gera INFO, nao um Pass silencioso");

            Inventory inv = new Inventory();
            inv.DevicesNativeSourceAvailable = true;
            DeviceInfo wifiDisabled = new DeviceInfo();
            wifiDisabled.InstanceId = @"PCI\VEN_8086&DEV_2723";
            wifiDisabled.Name = "Intel(R) Wi-Fi 6 AX200";
            wifiDisabled.Class = "Net";
            wifiDisabled.IsPresent = true;
            wifiDisabled.ProblemCode = 22;
            wifiDisabled.IsAdministrativeChoice = true;
            inv.Devices.Add(wifiDisabled);

            List<TestResult> results = new List<TestResult>(new DeviceTests().Run(Ctx(true), inv));
            TestResult dev001 = Find(results, "DEV-001");
            t.Equal("dispositivo desativado, sem outro problema, vira INFO (nao Pass)", TestStatus.Info, dev001.Status);
            t.Contains("o laudo cita o dispositivo desativado pelo nome", dev001.Result, "Wi-Fi 6 AX200");
            t.Contains("o laudo cita o codigo de problema", dev001.Result, "Code 22");
        }

        // Driver com IsSigned nulo (WMI nao reportou a propriedade) nao pode
        // ser somado silenciosamente ao grupo "possui assinatura digital
        // confirmada".
        private static void UnknownDriverSignatureNeverCountsAsSigned(TestRunner t)
        {
            t.Suite("Regressao: assinatura de driver desconhecida nao vira 'todos assinados'");

            Inventory inv = new Inventory();
            DriverInfo knownSigned = new DriverInfo();
            knownSigned.DeviceName = "Driver A"; knownSigned.IsSigned = true;
            inv.Drivers.Add(knownSigned);

            DriverInfo unknownSignature = new DriverInfo();
            unknownSignature.DeviceName = "Driver B"; unknownSignature.IsSigned = null;
            inv.Drivers.Add(unknownSignature);

            List<TestResult> results = new List<TestResult>(new DeviceTests().Run(Ctx(true), inv));
            TestResult dev004 = Find(results, "DEV-004");
            t.False("assinatura desconhecida nunca vira Pass afirmando 'todos assinados'", dev004.Status == TestStatus.Pass);
            t.Equal("driver com IsSigned nulo vira INFO, nao Pass", TestStatus.Info, dev004.Status);

            // Agora com todos os drivers confirmados assinados, o Pass volta.
            inv.Drivers[1].IsSigned = true;
            results = new List<TestResult>(new DeviceTests().Run(Ctx(true), inv));
            dev004 = Find(results, "DEV-004");
            t.Equal("com todos confirmados assinados, DEV-004 aprova", TestStatus.Pass, dev004.Status);
        }

        // O Defender desligado tem tres significados muito diferentes, e so um
        // deles e problema de seguranca.
        // Perfil null ou "Unknown" isolado nao pode dar Pass "ativo em todos
        // os perfis avaliados" - esse perfil especifico nunca foi avaliado.
        private static void FirewallUnconfirmedProfiles(TestRunner t)
        {
            t.Suite("Regressao: firewall com perfil nao confirmado nao aprova tudo");

            Inventory mixedNull = new Inventory();
            mixedNull.Security.FirewallDomain = null;
            mixedNull.Security.FirewallPrivate = "Unknown";
            mixedNull.Security.FirewallPublic = "Enabled";
            List<TestResult> r1 = new List<TestResult>(new SecurityTests().Run(Ctx(true), mixedNull));
            TestResult fw1 = Find(r1, "SEC-003");
            t.False("perfil null/Unknown misto nunca vira Pass", fw1.Status == TestStatus.Pass);
            t.Equal("mistura de confirmado e nao confirmado vira Unknown", TestStatus.Unknown, fw1.Status);

            Inventory allNull = new Inventory();
            List<TestResult> r2 = new List<TestResult>(new SecurityTests().Run(Ctx(true), allNull));
            TestResult fw2 = Find(r2, "SEC-003");
            t.Equal("todos os perfis ausentes vira Unknown", TestStatus.Unknown, fw2.Status);

            Inventory oneDisabled = new Inventory();
            oneDisabled.Security.FirewallDomain = "Enabled";
            oneDisabled.Security.FirewallPrivate = null;
            oneDisabled.Security.FirewallPublic = "Disabled";
            List<TestResult> r3 = new List<TestResult>(new SecurityTests().Run(Ctx(true), oneDisabled));
            TestResult fw3 = Find(r3, "SEC-003");
            t.Equal("perfil Publico desligado ainda e detectado mesmo com outro perfil nao lido", TestStatus.Error, fw3.Status);
        }

        private static void DefenderReasons(TestRunner t)
        {
            t.Suite("Defender: distinguir a razao do desligamento");

            Inventory byUser = new Inventory();
            byUser.Security.DefenderRealtimeProtection = "Disabled";
            byUser.Security.DefenderRealtimeReason = "User";
            TestResult r1 = Find(new List<TestResult>(new SecurityTests().Run(Ctx(true), byUser)), "SEC-001");
            // ARQUITETURA.md 5 define "desativado POR USUARIO ->
            // WARNING/HIGH", nao ERROR/HIGH.
            t.Equal("desligado pelo usuario e WARNING (ARQUITETURA.md 5)", TestStatus.Warning, r1.Status);
            t.Equal("severidade alta", Severity.High, r1.Severity);

            Inventory byPolicy = new Inventory();
            byPolicy.Security.DefenderRealtimeProtection = "Disabled";
            byPolicy.Security.DefenderRealtimeReason = "Policy";
            TestResult r2 = Find(new List<TestResult>(new SecurityTests().Run(Ctx(true), byPolicy)), "SEC-001");
            t.Equal("desligado por politica e apenas INFO", TestStatus.Info, r2.Status);
            t.Equal("decisao administrativa nao desconta pontos", 0, DiagnosticEngine.Penalty(r2));

            Inventory byThirdParty = new Inventory();
            byThirdParty.Security.DefenderRealtimeProtection = "Disabled";
            byThirdParty.Security.DefenderRealtimeReason = "ThirdPartyAv";
            TestResult r3 = Find(new List<TestResult>(new SecurityTests().Run(Ctx(true), byThirdParty)), "SEC-001");
            t.Equal("desligado por outro antivirus e comportamento correto", TestStatus.Pass, r3.Status);

            Inventory noAdmin = new Inventory();
            noAdmin.Security.DefenderRealtimeProtection = "RequiresAdmin";
            TestResult r4 = Find(new List<TestResult>(new SecurityTests().Run(Ctx(false), noAdmin)), "SEC-001");
            t.Equal("sem privilegio vira REQUER ADMIN", TestStatus.RequiresAdmin, r4.Status);

            // Decodificacao do productState do Security Center. Valores
            // reais (0x061100 = Defender ativo nesta maquina, confirmado no
            // WMI; 0x060100 = desligado; 0x041010 = terceiro ativo com
            // assinatura vencida) - o estado vive no byte 8-15, nao no 16-23
            // (que e so o TIPO de provedor).
            // Os valores antigos deste teste (0x111000/0x101000) tinham os
            // dois bytes com o mesmo bit ligado por coincidencia e passavam
            // com a decodificacao errada tambem - nao provavam nada.
            AntivirusProduct defenderOn = new AntivirusProduct();
            SecurityCollector.DecodeProductState(0x061100, defenderOn);
            t.Equal("produto ativo detectado (Defender real, ligado)", true, defenderOn.IsEnabled);
            t.Equal("assinatura em dia", true, defenderOn.IsUpToDate);

            AntivirusProduct defenderOff = new AntivirusProduct();
            SecurityCollector.DecodeProductState(0x060100, defenderOff);
            t.Equal("produto desativado detectado", false, defenderOff.IsEnabled);

            AntivirusProduct thirdPartyStale = new AntivirusProduct();
            SecurityCollector.DecodeProductState(0x041010, thirdPartyStale);
            t.Equal("terceiro ativo mesmo com assinatura vencida", true, thirdPartyStale.IsEnabled);
            t.Equal("assinatura vencida detectada", false, thirdPartyStale.IsUpToDate);
        }

        private static void Correlations(TestRunner t)
        {
            t.Suite("Correlacao sintoma - evidencia - causa");

            // Desligamentos + temperatura alta = protecao termica.
            Inventory thermal = new Inventory();
            thermal.Events.WindowDays = 7;
            thermal.Events.UnexpectedShutdowns = 4;
            thermal.Cpu.TemperatureC = 96;

            List<Correlation> c1 = DiagnosticEngine.Correlate(Ctx(true), thermal, new List<TestResult>());
            t.True("uma correlacao foi produzida", c1.Count >= 1);
            t.Contains("causa aponta protecao termica", c1[0].LikelyCause, "termica");
            t.True("a correlacao traz evidencias", c1[0].Evidence.Count >= 2);
            t.True("confianca dentro da faixa valida", c1[0].Confidence > 0 && c1[0].Confidence <= Confidence.Max);

            // Mesmo sintoma sem TemperatureC/WheaUncorrectedCount medidos: a
            // causa nao pode ser afirmada como termica - o texto precisa
            // dizer que os dados NAO FORAM MEDIDOS, nao que foram medidos e
            // deram negativo (as duas coisas tem implicacao pratica bem
            // diferente para o tecnico).
            Inventory noEvidence = new Inventory();
            noEvidence.Events.WindowDays = 7;
            noEvidence.Events.UnexpectedShutdowns = 3;

            List<Correlation> c2 = DiagnosticEngine.Correlate(Ctx(true), noEvidence, new List<TestResult>());
            t.DoesNotContain("sem evidencia nao se afirma causa termica", c2[0].LikelyCause, "protecao termica");
            t.Contains("o texto declara que os dados NAO FORAM MEDIDOS, nao que foram medidos e deram negativo",
                c2[0].LikelyCause, "Nao foi possivel medir");
            t.True("confianca menor quando falta evidencia", c2[0].Confidence < c1[0].Confidence);

            // Mesmo sintoma, mas com temperatura e WHEA de fato MEDIDOS e
            // normais: agora sim o texto pode afirmar "sem evidencia" - a
            // distincao entre este caso e o anterior e exatamente essa:
            // dados medidos e normais versus dados nunca medidos.
            Inventory measuredClean = new Inventory();
            measuredClean.Events.WindowDays = 7;
            measuredClean.Events.UnexpectedShutdowns = 3;
            measuredClean.Cpu.TemperatureC = 45;
            measuredClean.Events.WheaUncorrectedCount = 0;

            List<Correlation> c2b = DiagnosticEngine.Correlate(Ctx(true), measuredClean, new List<TestResult>());
            t.DoesNotContain("com dados medidos e normais, nao se afirma causa termica", c2b[0].LikelyCause, "protecao termica");
            t.Contains("agora o texto pode afirmar ausencia de evidencia - os dados foram medidos", c2b[0].LikelyCause, "Sem evidencia");
            t.True("confianca maior quando os dados FORAM medidos (mesmo que negativos) do que quando faltam",
                c2b[0].Confidence > c2[0].Confidence);

            // Um unico desligamento nao gera correlacao (evita alarme por ruido).
            Inventory single = new Inventory();
            single.Events.WindowDays = 7;
            single.Events.UnexpectedShutdowns = 1;
            t.Equal("evento isolado nao vira correlacao", 0,
                DiagnosticEngine.Correlate(Ctx(true), single, new List<TestResult>()).Count);

            // WHEA nao corrigido + tela azul = falha de hardware, alta confianca.
            Inventory hardware = new Inventory();
            hardware.Events.WindowDays = 7;
            hardware.Events.WheaUncorrectedCount = 3;
            BugCheckEvent hwBugCheck = new BugCheckEvent();
            hwBugCheck.StopCode = "0x124";
            hardware.Events.BugChecks.Add(hwBugCheck);

            List<Correlation> c3 = DiagnosticEngine.Correlate(Ctx(true), hardware, new List<TestResult>());
            bool found = false;
            foreach (Correlation c in c3)
            {
                // WHEA-Logger e o bugcheck vem os dois do log de eventos (a
                // propria evidencia da correlacao rotula ambos como
                // "EventLog") - chamar isso de "duas fontes independentes"
                // seria uma alegacao mais forte do que os dados sustentam. O
                // texto fala em "dois sinais no log de eventos", sem a
                // palavra "independentes".
                if (c.LikelyCause != null && c.LikelyCause.IndexOf("dois sinais no log de eventos", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    found = true;
                    t.Equal("falha confirmada por dois sinais e critica", Severity.Critical, c.Severity);
                    t.True("confianca alta com dois sinais concordantes", c.Confidence >= 80);
                    t.DoesNotContain("== Regressao: nao alega fontes independentes quando as duas evidencias sao do EventLog",
                        c.LikelyCause, "fontes independentes");
                }
            }
            t.True("correlacao de hardware foi emitida", found);

            // Maquina sem sintomas nao produz causa nenhuma.
            t.Equal("inventario limpo nao gera correlacao", 0,
                DiagnosticEngine.Correlate(Ctx(true), new Inventory(), new List<TestResult>()).Count);
        }

        private static TestResult Find(List<TestResult> results, string id)
        {
            foreach (TestResult r in results)
            {
                if (string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase)) return r;
            }
            return null;
        }
    }
}
