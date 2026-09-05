using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    // Teste de carga. NUNCA roda por padrao: exige --stress explicito, porque
    // aquece o equipamento do cliente de proposito.
    //
    // O que este modulo faz e o que o diagnostico em repouso nao consegue:
    //
    //  - carrega TODOS os nucleos com FMA de 256 bits emitido em codigo de
    //    maquina, que satura as unidades vetoriais e leva a CPU ao consumo
    //    maximo. Um laco em C# comum nao chega perto disso e por isso nunca
    //    revelaria uma refrigeracao no limite;
    //  - confere o resultado aritmetico a cada lote. CPU instavel erra conta
    //    antes de travar, e esse erro e detectavel;
    //  - amostra temperatura, ventoinha, consumo e vazao a cada segundo, do
    //    repouso ate depois do fim da carga. A curva separa "esquentou e
    //    estabilizou" de "esquentou ate o limite e perdeu desempenho";
    //  - testa a memoria com padroes de memtest e o disco com verificacao de
    //    integridade, nao so de velocidade.
    public sealed class StressCollector : ICollector
    {
        public string Name { get { return "Stress"; } }

        private const int BaselineSeconds = 6;

        // Teto para a espera de estabilizacao da linha de base (ver
        // RunBaseline). Sem teto, uma maquina que nunca volta perto do
        // repouso (ventoinha travada, ambiente muito quente) prenderia o
        // tecnico indefinidamente.
        private const int MaxBaselineSeconds = 30;
        private const int MaxCooldownSeconds = 45;
        private const int BlocksPerCall = 256;

        private long _totalOperations;
        private long _totalGpuFrames;
        private TelemetryMonitor _monitor;

        // Corte de seguranca por temperatura: sem isto a carga total de CPU
        // rodaria pelo tempo pedido no relogio (ate 2h), sem nenhum freio
        // alem do proprio throttling do hardware. Volatile porque e lido
        // pelas threads de queima (BurnLoop/BurnManaged) e escrito pela
        // thread supervisora de RunCpuStress.
        private volatile bool _cpuThermalAbort;

        // engine.Dispose() (chamado no finally de Collect) libera as
        // paginas de codigo executavel com VirtualFree.
        // Se alguma thread de queima nao terminou dentro do prazo de espera
        // (travou de verdade, nao so demorou), ela continua executando
        // instrucoes dentro dessas paginas - VirtualFree nessa hora produz
        // access violation, uma excecao de estado corrompido que o .NET 4.8
        // nao captura sem legacyCorruptedStateExceptionsPolicy (ausente
        // neste projeto), derrubando o processo inteiro sem gerar laudo.
        // Setado como true quando alguma thread nao confirma o Join: nesse
        // caso o Dispose e deliberadamente pulado (vazamento de memoria
        // aceitavel - o processo esta prestes a fechar de qualquer forma)
        // em vez de arriscar liberar paginas ainda em uso.
        private volatile bool _unsafeToDisposeEngine;

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            StressResults s = new StressResults();
            inv.Stress = s;

            // O CPUID roda SEMPRE, mesmo sem --stress: e leitura pura, custa
            // microssegundos e responde com autoridade coisas que o WMI erra
            // (modelo real, extensoes, presenca de hipervisor).
            string engineReason;
            LowLevelEngine engine = LowLevelEngine.TryCreate(out engineReason);

            try
            {
                if (engine != null)
                {
                    FillCpuIdentity(ctx, inv, engine);
                    s.Engine = engine.BurnDescription;
                }
                else
                {
                    s.EngineFallbackReason = engineReason;
                    s.Engine = "laco gerenciado (codigo nativo indisponivel)";
                    ctx.Log.Warn(Name, "Motor de baixo nivel indisponivel: " + engineReason);
                }

                if (!ctx.Options.AllowStress)
                {
                    s.Executed = false;
                    s.SkipReason = "Teste de carga nao solicitado. Use --stress para executar (exige consentimento porque aquece o equipamento).";
                    return;
                }

                RunAllPhases(ctx, src, inv, s, engine);
            }
            finally
            {
                // Nunca libera as paginas de codigo executavel se alguma
                // thread de carga ficou presa (ver _unsafeToDisposeEngine,
                // setado em RunCpuStress).
                if (engine != null && !_unsafeToDisposeEngine) engine.Dispose();
            }
        }

        private void RunAllPhases(ScanContext ctx, SourceSet src, Inventory inv, StressResults s, LowLevelEngine engine)
        {
            s.Executed = true;
            s.DurationSeconds = ctx.Options.StressSeconds;
            s.CpuIdleTempC = inv.Cpu.TemperatureC;

            ctx.Log.Security(Name, "Teste de carga AUTORIZADO pelo operador: " + ctx.Options.StressSeconds +
                "s de CPU com " + s.Engine + ".");

            ThreadControl.KeepAwake(true);
            _monitor = new TelemetryMonitor(ctx, src, this);
            _monitor.Start();

            try
            {
                // Cada Add() abaixo so acontece DEPOIS que a fase
                // correspondente de fato terminou - registrar antes da
                // chamada deixaria o report.json afirmando fases que nunca
                // chegaram ao fim, caso o modulo seja interrompido no meio
                // (excecao, thread abandonada por timeout do orquestrador).

                // 1) Repouso. Sem esta referencia nao ha como dizer quanto a
                //    carga aqueceu - so a que temperatura chegou.
                _monitor.Phase = "repouso";
                bool baselineStable = RunBaseline(ctx);
                s.PhasesExecuted.Add("Linha de base em repouso (" +
                    (baselineStable ? "estabilizada" : "nao estabilizou dentro do teto de " + MaxBaselineSeconds + "s") + ")");

                // 2) Carga total de CPU.
                _monitor.Phase = "carga";
                RunCpuStress(ctx, inv, s, engine);
                s.PhasesExecuted.Add("Carga total de CPU (" + ctx.Options.StressSeconds + "s)");

                // 3) Resfriamento: quanto o equipamento recupera sozinho.
                _monitor.Phase = "resfriamento";
                RunCooldown(s);
                s.PhasesExecuted.Add("Resfriamento monitorado (ate " + MaxCooldownSeconds + "s)");

                // 4) Carga real de GPU - totalmente opcional (--gpu-stress).
                // Sem a flag, a GPU continua so monitorada (sensor lido
                // passivamente durante a carga de CPU acima), exatamente
                // como antes desta fase existir.
                if (ctx.Options.AllowGpuStress)
                {
                    _monitor.Phase = "carga_gpu";
                    RunGpuStress(ctx, s);
                    s.PhasesExecuted.Add("Carga real de GPU (" + ctx.Options.StressSeconds + "s)");
                }
                else
                {
                    GpuStressResult skippedGpu = new GpuStressResult();
                    skippedGpu.Executed = false;
                    skippedGpu.SkipReason = "Teste de carga de GPU nao solicitado. Use --gpu-stress para aplicar carga 3D real.";
                    s.Gpu = skippedGpu;
                }

                // 5) Memoria.
                if (ctx.Options.AllowMemoryTest)
                {
                    _monitor.Phase = "memoria";
                    RunMemoryStress(ctx, s, engine);
                    s.PhasesExecuted.Add("Teste de integridade e banda de memoria");
                }
                else
                {
                    s.Memory = new MemoryStressResult();
                    s.Memory.Executed = false;
                    s.Memory.SkipReason = "Teste de memoria nao executado - exige --memory-test.";
                    RunMemoryBandwidthOnly(ctx, s, engine);
                }

                // 6) Disco.
                if (ctx.Options.AllowDiskWriteBenchmark)
                {
                    _monitor.Phase = "disco";
                    RunDiskBenchmark(ctx, src, inv, s);
                    s.PhasesExecuted.Add("Benchmark e verificacao de integridade de disco");
                }
                else
                {
                    s.DiskBenchmarks.Add(NoteOnly("Benchmark de disco nao executado - exige --disk-benchmark (escreve arquivo temporario no disco do cliente)."));
                }
            }
            finally
            {
                _monitor.Stop();
                ThreadControl.KeepAwake(false);
            }

            s.Timeline.AddRange(_monitor.Samples);
            s.Thermal = BuildThermalProfile(s, inv);
            s.GpuNote = BuildGpuNote(s);

            if (s.Thermal != null && s.Thermal.MaxTempC.HasValue)
            {
                s.CpuMaxTempC = s.Thermal.MaxTempC;
                inv.Cpu.TemperatureC = s.CpuMaxTempC;
                inv.Cpu.TemperatureSource = "Sensor de hardware, maximo sob carga total";
            }
        }

        // ---------------- identidade da CPU pelo silicio ----------------

        private void FillCpuIdentity(ScanContext ctx, Inventory inv, LowLevelEngine engine)
        {
            Try.Do(ctx, Name, "identificacao da CPU via CPUID", delegate
            {
                CpuIdFacts f = engine.Facts;
                CpuLowLevelInfo info = new CpuLowLevelInfo();

                info.Source = "Instrucao CPUID (leitura direta do processador)";
                info.Vendor = f.Vendor;
                info.BrandString = f.BrandString;
                info.Family = f.Family;
                info.ModelId = f.Model;
                info.Stepping = f.Stepping;
                info.Features = f.FeatureSummary();
                info.Avx2 = f.Avx2;
                info.Fma = f.Fma;
                info.Avx512 = f.Avx512F;
                info.InvariantTsc = f.InvariantTsc;
                info.TurboBoost = f.TurboBoost;
                info.DigitalThermalSensor = f.DigitalThermalSensor;
                info.HypervisorPresent = f.Hypervisor;
                info.HypervisorVendor = f.HypervisorVendor;

                foreach (CacheDescriptor c in f.Caches) info.Caches.Add(c.ToString());

                info.TscMhz = MeasureTscMhz(engine);
                inv.Cpu.LowLevel = info;

                // O CPUID e mais confiavel que o WMI para virtualizacao: le o
                // bit que o proprio hipervisor precisa expor, em vez de
                // adivinhar pelo nome do fabricante da placa.
                if (f.Hypervisor && inv.Machine != null && !inv.Machine.IsVirtualMachine.HasValue)
                {
                    inv.Machine.IsVirtualMachine = true;
                    inv.Machine.VirtualizationHint = "Bit de hipervisor presente no CPUID (" +
                        (f.HypervisorVendor == null ? "fabricante nao identificado" : f.HypervisorVendor) + ")";
                }
            });
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll")]
        private static extern UIntPtr SetThreadAffinityMask(IntPtr thread, UIntPtr mask);

        // A frequencia calculada a partir de dois RDTSC so e confiavel
        // quando o proprio CPUID afirma TSC invariante
        // (bit lido em LowLevel.cs, Nehalem/Barcelona em diante) - sem ele o
        // contador anda na frequencia P-state INSTANTANEA (varia com
        // throttling/turbo durante os 200ms da medida) em vez de a
        // frequencia base fixa que o calculo assume, e em CPU virtualizada
        // com TSC nao sincronizado entre nucleos o numero e so ruido. Alem
        // disso, sem prender a thread a um unico processador logico durante
        // a janela de medicao, o agendador do Windows pode migrar a thread
        // de nucleo no meio da leitura - mesmo com TSC invariante presente,
        // isso pode ler dominios diferentes numa maquina multi-soquete.
        private static double? MeasureTscMhz(LowLevelEngine engine)
        {
            if (!engine.Facts.InvariantTsc) return null;

            IntPtr thread = GetCurrentThread();
            UIntPtr previousMask = SetThreadAffinityMask(thread, new UIntPtr(1UL));
            try
            {
                ulong start = engine.ReadTsc();
                Stopwatch sw = Stopwatch.StartNew();
                Thread.Sleep(200);
                sw.Stop();
                ulong end = engine.ReadTsc();

                if (sw.Elapsed.TotalSeconds <= 0 || end <= start) return null;
                return Math.Round((end - start) / sw.Elapsed.TotalSeconds / 1e6, 0);
            }
            finally
            {
                // Restaura a afinidade original da thread - o pino acima e
                // so para a janela de medicao, nao para o resto do scan.
                if (previousMask != UIntPtr.Zero) SetThreadAffinityMask(thread, previousMask);
            }
        }

        // ---------------- carga de CPU ----------------

        private void RunCpuStress(ScanContext ctx, Inventory inv, StressResults s, LowLevelEngine engine)
        {
            int threadCount = inv.Cpu.LogicalProcessors.HasValue && inv.Cpu.LogicalProcessors.Value > 0
                ? inv.Cpu.LogicalProcessors.Value
                : Environment.ProcessorCount;
            if (threadCount < 1) threadCount = 1;

            // "r" fica LOCAL ate o fim do metodo - publicar em s.Cpu (=
            // inv.Stress.Cpu) cedo demais deixaria um objeto parcialmente
            // preenchido visivel para qualquer leitor concorrente de
            // inv.Stress (ex.: o serializador do laudo, se este modulo for
            // abandonado por timeout do orquestrador e o relatorio for
            // montado enquanto a thread supervisora ainda esta rodando) - um
            // leitor poderia ver TotalOperations > 0 com ArithmeticErrors
            // == 0 so porque a agregacao de erros (mais abaixo) ainda nao
            // rodou, e reportar um resultado falso positivo.
            CpuStressResult r = new CpuStressResult();
            r.ThreadCount = threadCount;
            r.DurationSeconds = ctx.Options.StressSeconds;

            // Prender cada thread a um processador logico serve ao
            // diagnostico, nao ao desempenho: sem isso o Windows migra as
            // threads e um nucleo defeituoso pode passar despercebido - ou
            // errar sem que se saiba qual foi.
            //
            // ThreadsPinned precisa refletir o retorno real de
            // SetThreadAffinityMask (que PinToProcessor ja devolve), nao so
            // a intencao de tentar com base em threadCount<=64 - se a
            // fixacao falhar de verdade (thread ja tinha afinidade
            // restrita por politica, erro do SO), afirmar "fixadas" sem
            // confirmar faria um erro aritmetico atribuido ao "processador
            // logico N" citar o SLOT, nao o processador REAL onde a thread
            // de fato rodou - podendo apontar o dedo para o nucleo errado.
            bool canPin = threadCount <= 64;
            bool[] pinSucceeded = new bool[threadCount];

            // Sem sensor nao ha como frear a carga por temperatura: a carga
            // ainda roda (o operador pediu explicitamente com --stress), mas
            // o laudo precisa deixar claro que a protecao nao estava ativa,
            // em vez de simplesmente ficar calado sobre o risco.
            r.ThermalProtectionActive = ctx.SensorsAvailable;
            if (!r.ThermalProtectionActive)
                ctx.Log.Warn(Name, "Sensor de temperatura indisponivel: a carga total de CPU vai rodar SEM protecao termica automatica.");

            DateTime deadline = DateTime.UtcNow.AddSeconds(ctx.Options.StressSeconds);
            Interlocked.Exchange(ref _totalOperations, 0);
            _monitor.MarkThroughputStart();

            long[] errorsPerThread = new long[threadCount];
            string[] errorDetail = new string[threadCount];
            Thread[] workers = new Thread[threadCount];

            for (int i = 0; i < threadCount; i++)
            {
                int slot = i;
                Thread t = new Thread(delegate()
                {
                    // Sem este try/catch, QUALQUER excecao nao tratada aqui
                    // (OutOfMemoryException no AllocHGlobal de BurnUnit,
                    // falha de PinToProcessor relancada, etc.) seria uma
                    // excecao nao tratada de thread em background - o CLR
                    // derrubaria o PROCESSO INTEIRO, e o laudo (HTML/JSON,
                    // so gerado depois que Collect retorna) nunca chegaria a
                    // existir. O erro fica registrado para esta thread e as
                    // demais continuam.
                    try
                    {
                        if (canPin) pinSucceeded[slot] = ThreadControl.PinToProcessor(slot);
                        BurnLoop(engine, deadline, slot, errorsPerThread, errorDetail);
                    }
                    catch (Exception ex)
                    {
                        // errorsPerThread[slot] forca esta falha a aparecer
                        // na agregacao abaixo (que ignora slots com contador
                        // zero) - uma thread que morreu de excecao precisa
                        // ser tao visivel no laudo quanto um erro aritmetico.
                        errorsPerThread[slot] = 1;
                        errorDetail[slot] = "thread de carga abortou: " + ex.GetType().Name + ": " + ex.Message;
                    }
                });
                t.IsBackground = true;
                t.Name = "burn-" + i;
                workers[i] = t;
            }

            for (int i = 0; i < threadCount; i++) workers[i].Start();

            double peakLoad = 0;
            int hotSamples = 0;
            while (DateTime.UtcNow < deadline && !_cpuThermalAbort)
            {
                Sleep(1000);
                // SampleCpuLoad devolve null quando a amostra nao e
                // confiavel, em vez de um valor inflado silenciosamente
                // cortado em 100 - amostra invalida simplesmente nao
                // atualiza o pico, nao conta como 0 nem como 100.
                double? load = PerformanceCollector.SampleCpuLoad(300);
                if (load.HasValue && load.Value > peakLoad) peakLoad = load.Value;

                // Corte de emergencia: duas leituras seguidas no ou acima do
                // limiar critico interrompem a carga na hora, em vez de
                // esperar o tempo pedido esgotar. Duas amostras (nao uma) so
                // para nao abortar por um pico isolado de leitura ruidosa do
                // sensor - o sinal termico real de superaquecimento persiste.
                double? temp = _monitor.LastCpuTemp;
                if (temp.HasValue && temp.Value >= ctx.Options.CpuCritC)
                {
                    hotSamples++;
                    if (hotSamples >= 2)
                    {
                        _cpuThermalAbort = true;
                        r.AbortedAtTempC = temp.Value;
                        ctx.Log.Error(Name, "SEGURANCA: carga de CPU interrompida - temperatura atingiu " +
                            temp.Value.ToString("F1", CultureInfo.InvariantCulture) + " C (limiar critico: " +
                            ctx.Options.CpuCritC + " C).");
                    }
                }
                else
                {
                    hotSamples = 0;
                }
            }

            // Confere o retorno de cada Join - uma thread que nao termina
            // dentro do prazo continua rodando (e potencialmente executando
            // codigo nativo dentro das paginas executaveis da engine). Se
            // isso acontecer, o engine.Dispose() do chamador (Collect) tem
            // que ser pulado - ver _unsafeToDisposeEngine.
            bool allThreadsStopped = true;
            for (int i = 0; i < threadCount; i++)
            {
                workers[i].Join(30000);
                if (workers[i].IsAlive) allThreadsStopped = false;
            }

            if (!allThreadsStopped)
            {
                _unsafeToDisposeEngine = true;
                ctx.Log.Error(Name, "SEGURANCA: uma ou mais threads de carga de CPU nao terminaram apos o prazo de espera; " +
                    "as paginas de codigo executavel NAO serao liberadas para evitar access violation (vazamento deliberado).");
            }

            // ThreadsPinned reflete o que de fato aconteceu (todas as
            // fixacoes confirmadas), nao so a intencao de tentar.
            bool allPinned = canPin;
            if (canPin)
                for (int i = 0; i < threadCount; i++)
                    if (!pinSucceeded[i]) { allPinned = false; break; }
            r.ThreadsPinned = allPinned;

            for (int i = 0; i < threadCount; i++)
            {
                if (errorsPerThread[i] <= 0) continue;
                r.ArithmeticErrors += errorsPerThread[i];

                // So atribui o erro a um processador logico especifico
                // quando a fixacao daquela thread foi CONFIRMADA - sem
                // fixacao, o Windows pode ter migrado a thread para
                // qualquer nucleo durante a carga, e apontar o slot i como
                // "o processador defeituoso" seria uma acusacao sem lastro.
                if (allPinned) r.FaultyProcessors.Add(i);

                if (r.FirstErrorDetail == null && errorDetail[i] != null)
                {
                    string where = allPinned ? "processador logico " + i : "thread " + i + " (fixacao nao confirmada - nucleo real desconhecido)";
                    r.FirstErrorDetail = where + ": " + errorDetail[i];
                }
            }

            r.TotalOperations = Interlocked.Read(ref _totalOperations);
            r.MaxLoadPercent = Math.Round(peakLoad, 1);
            s.CpuMaxLoadPercent = r.MaxLoadPercent;

            ApplyThroughputWindows(r, _monitor.Samples);

            // Mantido para nao quebrar comparacoes com laudos antigos, que
            // registravam vazao em Mops/s.
            if (ctx.Options.StressSeconds > 0)
                s.CpuThroughputMops = Math.Round(r.TotalOperations / (double)ctx.Options.StressSeconds / 1e6, 1);

            // A publicacao em inv.Stress.Cpu so acontece aqui, como ULTIMA
            // instrucao do metodo, com "r" ja totalmente preenchido (erros
            // agregados, vazao calculada). A barreira garante que todas as
            // escritas acima fiquem visiveis ANTES que qualquer thread
            // concorrente possa observar s.Cpu.
            Thread.MemoryBarrier();
            s.Cpu = r;
        }

        private void BurnLoop(LowLevelEngine engine, DateTime deadline, int slot, long[] errors, string[] detail)
        {
            if (engine == null)
            {
                long managed = BurnManaged(deadline);
                Interlocked.Add(ref _totalOperations, managed);
                return;
            }

            BurnUnit unit = new BurnUnit(engine);
            try
            {
                while (DateTime.UtcNow < deadline && !_cpuThermalAbort)
                {
                    long ops = unit.RunBlock(BlocksPerCall);
                    Interlocked.Add(ref _totalOperations, ops);
                }
            }
            finally
            {
                errors[slot] = unit.ArithmeticErrors;
                detail[slot] = unit.FirstErrorDetail;
                unit.Dispose();
            }
        }

        // Reserva para quando a pagina de codigo executavel e barrada. Aquece
        // menos - e o laudo diz isso, em vez de fingir que o teste foi igual.
        private long BurnManaged(DateTime deadline)
        {
            long operations = 0;
            double acc = 1.0000001;
            int check = 0;

            while (true)
            {
                for (int i = 1; i <= 20000; i++)
                {
                    acc = acc * 1.0000001 + (i % 7);
                    if (acc > 1e12) acc = 1.0000001;
                }
                operations += 40000;

                if (++check >= 8)
                {
                    check = 0;
                    if (DateTime.UtcNow >= deadline || _cpuThermalAbort) break;
                }
            }
            return operations;
        }

        // Compara o primeiro terco da carga com o ultimo. Queda de vazao com
        // temperatura alta e throttling termico medido pelo desempenho
        // realmente entregue - nao depende de MSR nem de driver.
        // O laco supervisor de RunCpuStress so reavalia o deadline depois
        // de Sleep(1000) + SampleCpuLoad(...) - as threads de queima param
        // em poucos ms ao cruzar o deadline, mas a fase so muda de "carga"
        // para "resfriamento" quando o supervisor TERMINA sua iteracao
        // atual, que pode continuar por mais tempo. Durante essa sobra, o
        // TelemetryMonitor continua amostrando com Phase=="carga" e
        // ThroughputGflops proximo de zero (threads ja paradas), o que
        // contaminaria a janela "ultimo terco" com amostras que na verdade
        // sao de PARADA, nao de carga sustentada. Por isso o filtro e por
        // tempo, nao so por rotulo de fase: qualquer amostra alem do fim
        // esperado da carga (inicio da fase + duracao pedida, com uma folga
        // de 2s) e descartada aqui mesmo que ainda tenha Phase=="carga".
        private static void ApplyThroughputWindows(CpuStressResult r, List<TelemetrySample> samples)
        {
            double? loadStartSecond = null;
            foreach (TelemetrySample sample in samples)
            {
                if (sample.Phase == "carga") { loadStartSecond = sample.AtSecond; break; }
            }

            double loadEndCutoff = loadStartSecond.HasValue
                ? loadStartSecond.Value + r.DurationSeconds + 2.0
                : double.MaxValue;

            List<double> flops = new List<double>();
            foreach (TelemetrySample sample in samples)
            {
                if (sample.Phase != "carga" || !sample.ThroughputGflops.HasValue) continue;
                if (sample.AtSecond > loadEndCutoff) continue;
                flops.Add(sample.ThroughputGflops.Value);
            }

            if (flops.Count < 6) return;

            // A primeira amostra pega o arranque das threads; descartada.
            flops.RemoveAt(0);
            int window = flops.Count / 3;
            if (window < 2) return;

            double first = 0, last = 0, peak = 0;
            for (int i = 0; i < window; i++) first += flops[i];
            for (int i = flops.Count - window; i < flops.Count; i++) last += flops[i];
            foreach (double v in flops) if (v > peak) peak = v;

            r.FirstWindowGflops = Math.Round(first / window, 2);
            r.LastWindowGflops = Math.Round(last / window, 2);
            r.PeakGflops = Math.Round(peak, 2);

            if (r.FirstWindowGflops.Value > 0)
                r.SustainPercent = Math.Round(r.LastWindowGflops.Value / r.FirstWindowGflops.Value * 100.0, 1);
        }

        // ---------------- carga de GPU ----------------

        // Fase totalmente opcional (--gpu-stress): aplica carga 3D real via
        // GpuLoadEngine (OpenGL de funcao fixa) e le temperatura/utilizacao
        // pelo MESMO sensor cross-vendor (LibreHardwareMonitorLib) que ja
        // alimenta a leitura passiva de STR-013 - nao depende de nvidia-smi
        // nem de nenhuma ferramenta exclusiva de um fabricante.
        //
        // A janela/contexto OpenGL so pode ser criada e usada pela MESMA
        // thread (regra do Win32/WGL) - por isso toda a fase roda dentro da
        // thread "carga-gpu" abaixo, do TryCreate ao Dispose, e este metodo
        // (que roda na thread supervisora) so espera o resultado.
        private void RunGpuStress(ScanContext ctx, StressResults s)
        {
            GpuStressResult r = new GpuStressResult();
            r.DurationSeconds = ctx.Options.StressSeconds;

            int stressSeconds = ctx.Options.StressSeconds;
            int gpuCritC = ctx.Options.GpuCritC;

            string createReason = null;
            GpuLoadEngine engine = null;
            ManualResetEvent created = new ManualResetEvent(false);
            double? abortedAtTemp = null;
            Interlocked.Exchange(ref _totalGpuFrames, 0);

            Thread renderThread = new Thread(delegate()
            {
                try
                {
                    engine = GpuLoadEngine.TryCreate(out createReason);
                }
                finally
                {
                    created.Set();
                }
                if (engine == null) return;

                try
                {
                    _monitor.MarkGpuThroughputStart();
                    DateTime deadline = DateTime.UtcNow.AddSeconds(stressSeconds);
                    int hotSamples = 0;

                    while (DateTime.UtcNow < deadline)
                    {
                        if (!engine.PumpMessages()) break;
                        engine.RenderFrame();
                        Interlocked.Increment(ref _totalGpuFrames);

                        // Mesmo corte de emergencia da CPU (ver RunCpuStress):
                        // duas amostras seguidas no ou acima do limiar critico
                        // interrompem a carga na hora, em vez de esperar o
                        // tempo pedido esgotar.
                        double? temp = _monitor.LastGpuTemp;
                        if (temp.HasValue && temp.Value >= gpuCritC)
                        {
                            hotSamples++;
                            if (hotSamples >= 2)
                            {
                                abortedAtTemp = temp.Value;
                                ctx.Log.Error(Name, "SEGURANCA: carga de GPU interrompida - temperatura atingiu " +
                                    temp.Value.ToString("F1", CultureInfo.InvariantCulture) + " C (limiar critico: " + gpuCritC + " C).");
                                break;
                            }
                        }
                        else
                        {
                            hotSamples = 0;
                        }
                    }
                }
                finally
                {
                    engine.Dispose();
                }
            });
            renderThread.IsBackground = true;
            renderThread.Name = "carga-gpu";
            renderThread.Start();

            // A criacao da janela/contexto e questao de milissegundos - um
            // teto de 15s so cobre um driver excepcionalmente lento a
            // responder, nunca a carga inteira.
            created.WaitOne(15000);

            if (engine == null)
            {
                r.Executed = false;
                r.EngineFallbackReason = createReason ?? "Nao foi possivel confirmar a criacao do motor de carga de GPU dentro do prazo.";
                s.Gpu = r;
                renderThread.Join(5000);
                return;
            }

            ctx.Log.Security(Name, "Teste de carga de GPU AUTORIZADO pelo operador: " + stressSeconds + "s via " +
                (engine.RenderDevice ?? "dispositivo nao identificado") + ".");

            r.RenderVendor = engine.RenderVendor;
            r.RenderDevice = engine.RenderDevice;
            r.HardwareAccelerated = engine.HardwareAccelerated;

            bool stopped = renderThread.Join((stressSeconds + 30) * 1000);
            if (!stopped)
                ctx.Log.Error(Name, "SEGURANCA: a thread de carga de GPU nao terminou apos o prazo de espera.");

            r.Executed = true;
            r.AbortedAtTempC = abortedAtTemp;
            r.FramesRendered = Interlocked.Read(ref _totalGpuFrames);
            if (stressSeconds > 0) r.AverageFps = Math.Round(r.FramesRendered / (double)stressSeconds, 1);

            ApplyGpuThroughputWindows(r, _monitor.Samples);
            s.Gpu = r;
        }

        // Compara o fps do primeiro terco da carga de GPU com o do ultimo -
        // mesmo principio do ApplyThroughputWindows da CPU, so que a
        // "vazao" aqui e quadros por segundo em vez de GFLOP/s.
        private static void ApplyGpuThroughputWindows(GpuStressResult r, List<TelemetrySample> samples)
        {
            double? loadStartSecond = null;
            foreach (TelemetrySample sample in samples)
            {
                if (sample.Phase == "carga_gpu") { loadStartSecond = sample.AtSecond; break; }
            }

            double loadEndCutoff = loadStartSecond.HasValue
                ? loadStartSecond.Value + r.DurationSeconds + 2.0
                : double.MaxValue;

            List<double> fps = new List<double>();
            foreach (TelemetrySample sample in samples)
            {
                if (sample.Phase != "carga_gpu" || !sample.GpuFramesPerSecond.HasValue) continue;
                if (sample.AtSecond > loadEndCutoff) continue;
                fps.Add(sample.GpuFramesPerSecond.Value);
            }

            if (fps.Count < 6) return;

            // A primeira amostra pega o arranque da janela/contexto; descartada.
            fps.RemoveAt(0);
            int window = fps.Count / 3;
            if (window < 2) return;

            double first = 0, last = 0;
            for (int i = 0; i < window; i++) first += fps[i];
            for (int i = fps.Count - window; i < fps.Count; i++) last += fps[i];

            r.FirstWindowFps = Math.Round(first / window, 1);
            r.LastWindowFps = Math.Round(last / window, 1);

            if (r.FirstWindowFps.Value > 0)
                r.SustainPercent = Math.Round(r.LastWindowFps.Value / r.FirstWindowFps.Value * 100.0, 1);
        }

        // ---------------- linha de base em repouso ----------------

        // Um Sleep fixo de BaselineSeconds (6s) logo apos toda a coleta em
        // repouso ja ter rodado (WMI, sensores, enumeracao de inventario)
        // nao seria tempo suficiente para o calor residual dessa atividade
        // (e de qualquer uso do equipamento minutos antes do --stress)
        // dissipar - um IdleTempC inflado reduz artificialmente
        // RampRateCPerMinute (base do achado de pasta termica ressecada) e
        // a diferenca contra o pico sob carga. Por isso espera-se a
        // temperatura ESTABILIZAR (menos de 0.5 C de variacao em 5 amostras
        // seguidas), com o mesmo padrao ja usado em RunCooldown,
        // respeitando ainda um piso de BaselineSeconds e um teto de
        // MaxBaselineSeconds. O resultado (se estabilizou ou bateu no teto)
        // fica registrado no laudo via PhasesExecuted, em vez de a linha de
        // base ficar silenciosamente suspeita.
        private bool RunBaseline(ScanContext ctx)
        {
            if (!ctx.SensorsAvailable)
            {
                // Sem sensor nao ha o que estabilizar - so preserva o piso
                // historico, sem prender o tecnico esperando um numero que
                // nunca vai aparecer.
                Sleep(BaselineSeconds * 1000);
                return false;
            }

            double? last = null;
            int stable = 0;

            for (int elapsed = 0; elapsed < MaxBaselineSeconds; elapsed++)
            {
                Sleep(1000);
                double? now = _monitor.LastCpuTemp;
                if (!now.HasValue) continue;

                if (last.HasValue && Math.Abs(last.Value - now.Value) < 0.5) stable++;
                else stable = 0;

                last = now;
                if (stable >= 5 && elapsed + 1 >= BaselineSeconds) return true;
            }
            return false;
        }

        // ---------------- resfriamento ----------------

        // Para assim que a temperatura para de cair de verdade: um equipamento
        // sadio volta ao patamar de repouso em poucos segundos, e nao ha
        // motivo para prender o tecnico esperando o tempo cheio.
        private void RunCooldown(StressResults s)
        {
            double? last = null;
            int stable = 0;

            for (int elapsed = 0; elapsed < MaxCooldownSeconds; elapsed++)
            {
                Sleep(1000);

                // _monitor.LastCpuTemp e uma leitura "grudenta" - uma vez
                // setada, continua devolvendo o ultimo valor conhecido mesmo
                // se o sensor parar de responder (driver travado, contencao
                // de CPU sob carga maxima). Um simples "if (!now.HasValue)
                // continue" nao pega esse cenario, porque HasValue continua
                // true - 5 leituras identicas so porque o sensor PAROU
                // seriam lidas como "estabilizou", encerrando o resfriamento
                // cedo demais quando na verdade so faltou leitura fresca.
                // FreshCpuTemp devolve null (tratado como AUSENTE, nao como
                // estabilidade) quando a ultima amostra e mais velha que
                // ~2s.
                double? now = _monitor.FreshCpuTemp();
                if (!now.HasValue) { stable = 0; continue; }

                if (last.HasValue && Math.Abs(last.Value - now.Value) < 0.5) stable++;
                else stable = 0;

                last = now;
                if (stable >= 5) break;
            }
        }

        // ---------------- memoria ----------------

        private void RunMemoryStress(ScanContext ctx, StressResults s, LowLevelEngine engine)
        {
            MemoryStressResult m = new MemoryStressResult();
            s.Memory = m;

            long requested = (long)ctx.Options.MemoryTestMegabytes * 1024L * 1024L;
            long budget = MemoryBudget(requested);

            if (budget < 32L * 1024L * 1024L)
            {
                m.Executed = false;
                m.SkipReason = "Memoria livre insuficiente para testar com seguranca sem empurrar o sistema para o arquivo de paginacao.";
                return;
            }

            ctx.Log.Security(Name, "Teste de memoria AUTORIZADO: " + (budget / 1048576) + " MB, 2 passagens.");

            // RunMemoryPatterns le m.Passes como limite do proprio laco -
            // precisa estar setado ANTES da chamada, diferente de
            // Executed/BytesTested (que sao RESULTADO, nao parametro).
            m.Passes = 2;

            // Executed/BytesTested precisam ser gravados DEPOIS da
            // execucao, verificando o retorno de Try.Do (que captura
            // QUALQUER excecao, inclusive OutOfMemoryException de uma
            // alocacao de ate 1,5 GB - real em processo x86 ou quando a
            // memoria livre encolhe entre a medicao e a alocacao) - gravar
            // Executed=true incondicionalmente deixaria PatternsRun vazio e
            // ErrorCount==0 parecer "0 divergencias em 0 padroes", como se
            // fosse memoria saudavel. Executed so vira true DEPOIS que
            // RunMemoryPatterns realmente terminou.
            bool ok = Try.Do(ctx, Name, "teste de integridade de memoria", delegate
            {
                RunMemoryPatterns(m, budget);
            });

            if (!ok)
            {
                m.Executed = false;
                m.Passes = 0; // nenhuma passagem real aconteceu
                m.SkipReason = "O teste de integridade de memoria falhou durante a execucao (ver errors.log) - memoria livre pode ter encolhido entre a medicao e a alocacao do buffer de teste.";
            }
            else
            {
                m.Executed = true;
                m.BytesTested = budget;
            }

            MeasureMemoryBandwidth(ctx, m, engine);
            MeasureMemoryLatency(ctx, m);
        }

        private void RunMemoryBandwidthOnly(ScanContext ctx, StressResults s, LowLevelEngine engine)
        {
            MeasureMemoryBandwidth(ctx, s.Memory, engine);
            MeasureMemoryLatency(ctx, s.Memory);
            s.MemoryBandwidthMbPerSec = s.Memory.WriteBandwidthMbPerSec;
        }

        // Fracao da memoria LIVRE, nunca um tamanho fixo: empurrar para swap
        // justamente a maquina com RAM cheia inverteria o diagnostico.
        private static long MemoryBudget(long requested)
        {
            Native.MemoryStatus mem = Native.GetMemoryStatus();
            if (mem == null) return Math.Min(requested, 256L * 1024L * 1024L);

            long safe = (long)(mem.AvailablePhysicalBytes * 0.50);
            long budget = Math.Min(requested, safe);

            // long[] de mais de 2 GB exige configuracao especial do runtime.
            if (budget > 1536L * 1024L * 1024L) budget = 1536L * 1024L * 1024L;
            return budget - (budget % 8);
        }

        // Padroes classicos de memtest. Cada um pega uma familia diferente de
        // defeito: bit preso, acoplamento entre linhas vizinhas e - o mais
        // comum em pente com defeito real - erro de enderecamento, em que a
        // escrita vai parar em outro endereco.
        private void RunMemoryPatterns(MemoryStressResult m, long bytes)
        {
            int words = (int)(bytes / 8);
            long[] buffer = new long[words];

            ulong[] patterns = new ulong[]
            {
                0x0000000000000000UL,
                0xFFFFFFFFFFFFFFFFUL,
                0xAAAAAAAAAAAAAAAAUL,
                0x5555555555555555UL,
                0x0F0F0F0F0F0F0F0FUL,
                0xF0F0F0F0F0F0F0F0UL
            };

            string[] names = new string[]
            {
                "todos zeros", "todos uns", "xadrez 0xAA", "xadrez 0x55", "nibble 0x0F", "nibble 0xF0"
            };

            for (int pass = 0; pass < m.Passes; pass++)
            {
                for (int p = 0; p < patterns.Length; p++)
                {
                    long value = unchecked((long)patterns[p]);
                    for (int i = 0; i < words; i++) buffer[i] = value;
                    for (int i = 0; i < words; i++)
                    {
                        if (buffer[i] == value) continue;
                        RecordMemoryError(m, i, value, buffer[i], names[p]);
                    }
                    if (pass == 0) m.PatternsRun.Add(names[p]);
                }

                // Endereco no proprio endereco: cada palavra guarda o seu
                // indice. Se a linha de endereco falhar, a leitura devolve o
                // conteudo de outra posicao e a divergencia aponta qual.
                for (int i = 0; i < words; i++) buffer[i] = i;
                for (int i = 0; i < words; i++)
                {
                    if (buffer[i] == i) continue;
                    RecordMemoryError(m, i, i, buffer[i], "endereco no endereco");
                }

                // Uns caminhantes: exercita cada bit da palavra isoladamente.
                for (int i = 0; i < words; i++) buffer[i] = 1L << (i & 63);
                for (int i = 0; i < words; i++)
                {
                    long expected = 1L << (i & 63);
                    if (buffer[i] == expected) continue;
                    RecordMemoryError(m, i, expected, buffer[i], "uns caminhantes");
                }

                if (pass == 0)
                {
                    m.PatternsRun.Add("endereco no endereco");
                    m.PatternsRun.Add("uns caminhantes");
                }
            }
        }

        private static void RecordMemoryError(MemoryStressResult m, long index, long expected, long actual, string pattern)
        {
            m.ErrorCount++;
            if (m.FirstErrorDetail != null) return;

            m.FirstErrorDetail = "padrao '" + pattern + "', palavra " + index.ToString(CultureInfo.InvariantCulture) +
                " (offset 0x" + (index * 8).ToString("X") + "): esperado 0x" + expected.ToString("X16") +
                ", lido 0x" + actual.ToString("X16");
        }

        private void MeasureMemoryBandwidth(ScanContext ctx, MemoryStressResult m, LowLevelEngine engine)
        {
            if (m == null) return;

            if (engine == null || !engine.StreamingAvailable)
            {
                MeasureMemoryBandwidthManaged(ctx, m);
                return;
            }

            Try.Do(ctx, Name, "banda de memoria (armazenamento nao-temporal)", delegate
            {
                int bytes = 64 * 1024 * 1024;

                // As duas alocacoes de 64 MB precisam ficar protegidas pelo
                // try - se a primeira (rawSource) tiver sucesso e a segunda
                // (rawTarget) lancar (OutOfMemoryException, cenario tipico
                // de maquina com pouca memoria - o alvo comum do
                // atendimento) fora do try, o finally nunca chegaria a
                // existir e rawSource vazaria 64 MB sem nenhum aviso (a
                // excecao e engolida pelo Try.Do que envolve este delegate).
                // rawTarget e alocado DENTRO do try (com rawSource ja
                // protegido) e o finally so libera o que de fato foi
                // alocado (checagem de IntPtr.Zero).
                IntPtr rawSource = Marshal.AllocHGlobal(bytes + 64);
                IntPtr rawTarget = IntPtr.Zero;
                try
                {
                    rawTarget = Marshal.AllocHGlobal(bytes + 64);
                    IntPtr source = Align64(rawSource);
                    IntPtr target = Align64(rawTarget);

                    engine.StreamWrite(target, source, (ulong)bytes);   // aquece TLB e cache

                    const int repetitions = 6;
                    double megabytes = (bytes / 1048576.0) * repetitions;

                    Stopwatch sw = Stopwatch.StartNew();
                    for (int i = 0; i < repetitions; i++) engine.StreamWrite(target, source, (ulong)bytes);
                    sw.Stop();
                    if (sw.Elapsed.TotalSeconds > 0)
                        m.WriteBandwidthMbPerSec = Math.Round(megabytes / sw.Elapsed.TotalSeconds, 0);

                    sw = Stopwatch.StartNew();
                    for (int i = 0; i < repetitions; i++) engine.StreamRead(source, (ulong)bytes);
                    sw.Stop();
                    if (sw.Elapsed.TotalSeconds > 0)
                        m.ReadBandwidthMbPerSec = Math.Round(megabytes / sw.Elapsed.TotalSeconds, 0);

                    m.BandwidthMethod = "AVX2 com armazenamento nao-temporal (vmovntdq), fora do cache";
                }
                finally
                {
                    if (rawSource != IntPtr.Zero) Marshal.FreeHGlobal(rawSource);
                    if (rawTarget != IntPtr.Zero) Marshal.FreeHGlobal(rawTarget);
                }
            });
        }

        private void MeasureMemoryBandwidthManaged(ScanContext ctx, MemoryStressResult m)
        {
            Try.Do(ctx, Name, "banda de memoria (copia gerenciada)", delegate
            {
                int size = 64 * 1024 * 1024;
                byte[] source = new byte[size];
                byte[] target = new byte[size];
                new Random(12345).NextBytes(source);

                const int repetitions = 6;
                Stopwatch sw = Stopwatch.StartNew();
                for (int i = 0; i < repetitions; i++) Buffer.BlockCopy(source, 0, target, 0, size);
                sw.Stop();

                double megabytes = (size / 1048576.0) * repetitions;
                if (sw.Elapsed.TotalSeconds > 0)
                    m.WriteBandwidthMbPerSec = Math.Round(megabytes / sw.Elapsed.TotalSeconds, 0);

                m.BandwidthMethod = "copia em bloco gerenciada; parte do trafego e absorvida pelo cache, entao o valor e otimista";
            });
        }

        // Latencia de acesso aleatorio: percurso em ciclo unico sobre um bloco
        // maior que o cache. O prefetcher nao consegue adivinhar o proximo
        // endereco, entao o que se mede e a latencia real da DRAM.
        private void MeasureMemoryLatency(ScanContext ctx, MemoryStressResult m)
        {
            if (m == null) return;

            Try.Do(ctx, Name, "latencia de memoria", delegate
            {
                int count = 16 * 1024 * 1024;          // 64 MB de indices
                int[] chain = new int[count];
                for (int i = 0; i < count; i++) chain[i] = i;

                // Embaralha e transforma em ciclo unico, para que o percurso
                // nunca reencontre uma posicao antes de passar por todas.
                Random random = new Random(9973);
                for (int i = count - 1; i > 0; i--)
                {
                    int j = random.Next(i + 1);
                    int tmp = chain[i]; chain[i] = chain[j]; chain[j] = tmp;
                }

                int[] next = new int[count];
                for (int i = 0; i < count - 1; i++) next[chain[i]] = chain[i + 1];
                next[chain[count - 1]] = chain[0];

                int steps = 4 * 1024 * 1024;
                int index = 0;
                for (int i = 0; i < 262144; i++) index = next[index];   // aquece

                Stopwatch sw = Stopwatch.StartNew();
                for (int i = 0; i < steps; i++) index = next[index];
                sw.Stop();

                // Sem esta leitura o compilador poderia eliminar o laco.
                if (index < 0) throw new InvalidOperationException("percurso invalido");

                if (steps > 0)
                    m.RandomAccessLatencyNs = Math.Round(sw.Elapsed.TotalMilliseconds * 1000000.0 / steps, 1);
            });
        }

        private static IntPtr Align64(IntPtr pointer)
        {
            return new IntPtr((pointer.ToInt64() + 63) & ~63L);
        }

        // ---------------- disco ----------------

        private static DiskBenchmark NoteOnly(string note)
        {
            DiskBenchmark b = new DiskBenchmark();
            b.Note = note;
            return b;
        }

        private void RunDiskBenchmark(ScanContext ctx, SourceSet src, Inventory inv, StressResults s)
        {
            int requestedMegabytes = ctx.Options.DiskTestMegabytes;
            ctx.Log.Security(Name, "Benchmark de disco AUTORIZADO: escrita de ate " + requestedMegabytes + " MB por volume elegivel.");

            foreach (VolumeInfo v in inv.Volumes)
            {
                if (v.DriveLetter == null) continue;
                SweepOrphanedBenchmarkDirs(ctx, v.DriveLetter);

                DiskBenchmark b = new DiskBenchmark();
                b.DriveLetter = v.DriveLetter;
                b.PhysicalDiskIndex = v.PhysicalDiskIndex;
                b.MediaType = MediaTypeForVolume(inv, v);

                // O portao de espaco livre precisa ser proporcional ao que
                // o teste realmente vai escrever (ate 8192 MB = 8 GB,
                // aceito por --disk-benchmark-mb), nao um piso fixo
                // desvinculado do pedido - senao um pedido grande poderia
                // escrever mais do que o disco tem de sobra. Alem disso
                // v.FreeBytes vem do WMI coletado minutos antes, no inicio
                // do scan; aqui le-se o espaco livre REAL no instante do
                // teste com DriveInfo (GetDiskFreeSpaceEx por baixo).
                long freeNow;
                try { freeNow = new DriveInfo(v.DriveLetter).AvailableFreeSpace; }
                catch (Exception ex)
                {
                    b.Note = "Pulado: nao foi possivel confirmar o espaco livre atual (" + ex.Message + ").";
                    s.DiskBenchmarks.Add(b);
                    continue;
                }

                const long safetyMarginBytes = 2L * 1024L * 1024L * 1024L; // nunca deixar o volume com menos que isto de sobra
                long requestedBytes = (long)requestedMegabytes * 1024L * 1024L;
                long requiredBytes = requestedBytes + safetyMarginBytes;

                // Por volume - nunca reaproveitar uma reducao feita para o
                // volume anterior (cada disco tem seu proprio espaco livre).
                int megabytesForThisVolume = requestedMegabytes;

                if (freeNow < requiredBytes)
                {
                    // Nao cancela o teste - reduz o tamanho para caber com
                    // margem, em vez de pular o volume inteiro so porque o
                    // pedido do operador nao coube.
                    long affordableBytes = freeNow - safetyMarginBytes;
                    if (affordableBytes < 64L * 1024L * 1024L) // menos de 64 MB nao vale o teste
                    {
                        b.Note = "Pulado: apenas " + FormatBytes(freeNow) + " livres no volume - insuficiente para escrever com seguranca (margem minima de 2 GB).";
                        s.DiskBenchmarks.Add(b);
                        continue;
                    }

                    megabytesForThisVolume = (int)Math.Min(requestedMegabytes, affordableBytes / (1024L * 1024L));
                    b.Note = "Tamanho reduzido de " + requestedMegabytes + " MB para " + megabytesForThisVolume +
                        " MB - " + FormatBytes(freeNow) + " livres no volume, margem de seguranca de 2 GB preservada.";
                }

                b.TempBeforeC = _monitor != null ? _monitor.LastStorageTemp : null;
                RunSingleVolumeBenchmark(ctx, v, b, megabytesForThisVolume);
                b.TempAfterC = _monitor != null ? _monitor.LastStorageTemp : null;

                s.DiskBenchmarks.Add(b);
            }

            ApplyToDisks(inv, s);
        }

        // Ctrl+C, kill pelo gerenciador de tarefas, BSOD ou desligamento
        // por temperatura DURANTE a escrita pulam o finally de
        // RunSingleVolumeBenchmark (que so roda em saida normal/excecao
        // .NET) e podem deixar ate 8 GB orfaos na raiz do disco do cliente.
        // FileOptions.DeleteOnClose no FileStream de escrita nao
        // resolve isso sozinho aqui: o arquivo precisa ser reaberto para
        // leitura/verificacao/IO aleatorio DEPOIS que a escrita fecha, e um
        // handle com DeleteOnClose apaga o arquivo assim que fecha (a
        // verificacao nunca conseguiria ler); alem disso, BSOD/queda de
        // energia nunca dao ao SO a chance de processar DeleteOnClose de
        // qualquer forma. A defesa que cobre TODOS os tipos de interrupcao,
        // inclusive os que nao rodam finally nenhum, e varrer e remover
        // diretorios orfaos de execucoes anteriores no INICIO do modulo,
        // antes de criar um novo.
        private static void SweepOrphanedBenchmarkDirs(ScanContext ctx, string driveLetter)
        {
            try
            {
                string root = driveLetter + "\\";
                if (!Directory.Exists(root)) return;

                foreach (string dir in Directory.GetDirectories(root, "PcDiag_bench_*"))
                {
                    try
                    {
                        Directory.Delete(dir, true);
                        ctx.Log.Warn("Stress", "Removido diretorio orfao de benchmark de uma execucao anterior interrompida: " + dir);
                    }
                    catch { /* pode estar em uso por outro processo, ou sem permissao - nao interrompe o scan por isso */ }
                }
            }
            catch { }
        }

        private static string FormatBytes(long bytes)
        {
            return Math.Round(bytes / 1073741824.0, 1).ToString(CultureInfo.InvariantCulture) + " GB";
        }

        // Cada volume e avaliado contra o tipo do SEU disco fisico. O coletor
        // antigo usava "existe algum SSD na maquina?" e por isso julgava um HD
        // com o limiar de SSD, gerando falso alerta de disco degradado.
        public static string MediaTypeForVolume(Inventory inv, VolumeInfo v)
        {
            if (!v.PhysicalDiskIndex.HasValue) return null;
            foreach (DiskInfo d in inv.Disks)
            {
                if (d.Index.HasValue && d.Index.Value == v.PhysicalDiskIndex.Value) return d.MediaType;
            }
            return null;
        }

        private void RunSingleVolumeBenchmark(ScanContext ctx, VolumeInfo v, DiskBenchmark b, int megabytes)
        {
            string dir = Path.Combine(v.DriveLetter + "\\", "PcDiag_bench_" + Guid.NewGuid().ToString("N").Substring(0, 10));
            string file = Path.Combine(dir, "bench.tmp");
            FileStream stream = null;

            try
            {
                Directory.CreateDirectory(dir);

                byte[] block = new byte[1048576];
                new Random(4242).NextBytes(block);

                // WriteThrough evita medir o cache do sistema de arquivos em
                // vez do disco.
                stream = new FileStream(file, FileMode.Create, FileAccess.Write, FileShare.None, 1048576, FileOptions.WriteThrough);

                Stopwatch sw = Stopwatch.StartNew();
                double firstQuarterSeconds = 0, lastQuarterStart = 0;
                int quarter = Math.Max(1, megabytes / 4);

                for (int i = 0; i < megabytes; i++)
                {
                    // Marca o numero do bloco no inicio de cada MB: se a
                    // escrita for parar em outro lugar, a releitura acusa
                    // exatamente qual bloco se perdeu.
                    WriteInt32(block, 0, i);
                    stream.Write(block, 0, block.Length);

                    if (i == quarter - 1) firstQuarterSeconds = sw.Elapsed.TotalSeconds;
                    if (i == megabytes - quarter) lastQuarterStart = sw.Elapsed.TotalSeconds;
                }

                stream.Flush(true);
                stream.Close();
                stream = null;
                sw.Stop();

                double totalSeconds = sw.Elapsed.TotalSeconds;
                if (totalSeconds > 0) b.WriteMbPerSec = Math.Round(megabytes / totalSeconds, 1);

                // SSD barato escreve rapido enquanto o cache SLC aguenta e
                // despenca depois. Uma medida unica esconde exatamente isso.
                double lastQuarterSeconds = totalSeconds - lastQuarterStart;
                if (firstQuarterSeconds > 0 && lastQuarterSeconds > 0 && megabytes >= 64)
                {
                    double firstRate = quarter / firstQuarterSeconds;
                    double lastRate = quarter / lastQuarterSeconds;
                    b.SustainedWriteMbPerSec = Math.Round(lastRate, 1);
                    if (firstRate > 0)
                        b.WriteDropPercent = Math.Round((1.0 - (lastRate / firstRate)) * 100.0, 1);
                }

                VerifyAndTimeRead(file, block, megabytes, b);
                MeasureRandomIo(file, megabytes, b);

                b.Note = "Escrita medida com WriteThrough. A leitura confere byte a byte o que foi gravado, entao vale como teste de integridade; " +
                         "parte da velocidade de leitura vem do cache do sistema.";
            }
            catch (Exception ex)
            {
                b.Note = "Falhou: " + ex.GetType().Name + " - " + ex.Message;
                ctx.Log.Error(Name, "Benchmark em " + v.DriveLetter + " falhou: " + ex.Message);
            }
            finally
            {
                if (stream != null) { try { stream.Close(); } catch { } }
                try { if (File.Exists(file)) File.Delete(file); } catch { }
                try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
            }
        }

        private static void VerifyAndTimeRead(string file, byte[] expected, int megabytes, DiskBenchmark b)
        {
            byte[] readBuffer = new byte[1048576];
            long mismatches = 0;

            Stopwatch sw = Stopwatch.StartNew();
            using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None, 1048576, FileOptions.SequentialScan))
            {
                for (int i = 0; i < megabytes; i++)
                {
                    int read = 0;
                    while (read < readBuffer.Length)
                    {
                        int got = stream.Read(readBuffer, read, readBuffer.Length - read);
                        if (got <= 0) break;
                        read += got;
                    }
                    if (read < readBuffer.Length) { mismatches++; continue; }

                    WriteInt32(expected, 0, i);
                    if (!SameBytes(expected, readBuffer)) mismatches++;
                }
            }
            sw.Stop();

            if (sw.Elapsed.TotalSeconds > 0)
                b.ReadMbPerSec = Math.Round(megabytes / sw.Elapsed.TotalSeconds, 1);

            b.IntegrityChecked = true;
            b.IntegrityErrors = mismatches;
        }

        // IOPS de 4 KB. Para uso real - abrir programa, iniciar o Windows -
        // este numero pesa muito mais que a velocidade sequencial, e e onde o
        // disco mecanico velho realmente aparece.
        private static void MeasureRandomIo(string file, int megabytes, DiskBenchmark b)
        {
            long length = (long)megabytes * 1048576L;
            if (length < 16 * 1048576L) return;

            byte[] buffer = new byte[4096];
            Random random = new Random(1337);
            long maxOffset = length - buffer.Length;

            using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None, 4096, FileOptions.RandomAccess))
            {
                int operations = 0;
                Stopwatch sw = Stopwatch.StartNew();
                while (sw.Elapsed.TotalSeconds < 3.0)
                {
                    for (int i = 0; i < 64; i++)
                    {
                        stream.Position = (long)(random.NextDouble() * maxOffset) & ~4095L;
                        stream.Read(buffer, 0, buffer.Length);
                        operations++;
                    }
                }
                sw.Stop();
                if (sw.Elapsed.TotalSeconds > 0)
                    b.Random4kReadIops = Math.Round(operations / sw.Elapsed.TotalSeconds, 0);
            }

            using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                int operations = 0;
                Stopwatch sw = Stopwatch.StartNew();
                while (sw.Elapsed.TotalSeconds < 3.0)
                {
                    for (int i = 0; i < 16; i++)
                    {
                        stream.Position = (long)(random.NextDouble() * maxOffset) & ~4095L;
                        stream.Write(buffer, 0, buffer.Length);
                        operations++;
                    }
                    stream.Flush(true);
                }
                sw.Stop();
                if (sw.Elapsed.TotalSeconds > 0)
                    b.Random4kWriteIops = Math.Round(operations / sw.Elapsed.TotalSeconds, 0);
            }
        }

        private static void WriteInt32(byte[] buffer, int offset, int value)
        {
            buffer[offset + 0] = (byte)(value & 0xFF);
            buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
            buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
            buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        private static bool SameBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        private static void ApplyToDisks(Inventory inv, StressResults s)
        {
            foreach (DiskBenchmark b in s.DiskBenchmarks)
            {
                if (!b.PhysicalDiskIndex.HasValue) continue;
                foreach (DiskInfo d in inv.Disks)
                {
                    if (!d.Index.HasValue || d.Index.Value != b.PhysicalDiskIndex.Value) continue;
                    if (b.WriteMbPerSec.HasValue) d.WriteMbPerSec = b.WriteMbPerSec;
                    if (b.ReadMbPerSec.HasValue) d.ReadMbPerSec = b.ReadMbPerSec;
                }
            }
        }

        // ---------------- perfil termico ----------------

        private static ThermalProfile BuildThermalProfile(StressResults s, Inventory inv)
        {
            ThermalProfile p = new ThermalProfile();

            double idleSum = 0; int idleCount = 0;
            double loadSum = 0; int loadCount = 0;
            double? maxTemp = null, maxWatts = null, minClock = null, maxClock = null;
            double? maxFan = null, idleFan = null, maxGpu = null, maxBoard = null, maxStorage = null;
            double? peakAtSecond = null, loadStartSecond = null;
            double? lastCooldownTemp = null, cooldownStart = null, cooldownEnd = null;
            double? maxGpuLoad = null;

            foreach (TelemetrySample t in s.Timeline)
            {
                if (t.Phase == "repouso")
                {
                    if (t.CpuTempC.HasValue) { idleSum += t.CpuTempC.Value; idleCount++; }
                    if (t.MaxFanRpm.HasValue && (!idleFan.HasValue || t.MaxFanRpm.Value > idleFan.Value)) idleFan = t.MaxFanRpm;
                }
                else if (t.Phase == "carga")
                {
                    if (!loadStartSecond.HasValue) loadStartSecond = t.AtSecond;
                    if (t.CpuTempC.HasValue)
                    {
                        loadSum += t.CpuTempC.Value; loadCount++;
                        if (!maxTemp.HasValue || t.CpuTempC.Value > maxTemp.Value)
                        {
                            maxTemp = t.CpuTempC;
                            peakAtSecond = t.AtSecond;
                        }
                    }
                    if (t.CpuPackageWatts.HasValue && (!maxWatts.HasValue || t.CpuPackageWatts.Value > maxWatts.Value)) maxWatts = t.CpuPackageWatts;
                    if (t.CpuClockMhz.HasValue)
                    {
                        if (!minClock.HasValue || t.CpuClockMhz.Value < minClock.Value) minClock = t.CpuClockMhz;
                        if (!maxClock.HasValue || t.CpuClockMhz.Value > maxClock.Value) maxClock = t.CpuClockMhz;
                    }
                    if (t.MaxFanRpm.HasValue && (!maxFan.HasValue || t.MaxFanRpm.Value > maxFan.Value)) maxFan = t.MaxFanRpm;
                }
                else if (t.Phase == "resfriamento")
                {
                    if (!cooldownStart.HasValue) cooldownStart = t.AtSecond;
                    if (t.CpuTempC.HasValue) { lastCooldownTemp = t.CpuTempC; cooldownEnd = t.AtSecond; }
                }
                else if (t.Phase == "carga_gpu")
                {
                    // Utilizacao so tem sentido dentro da propria fase de
                    // carga de GPU - fora dela nao ha carga aplicada.
                    if (t.GpuLoadPercent.HasValue && (!maxGpuLoad.HasValue || t.GpuLoadPercent.Value > maxGpuLoad.Value))
                        maxGpuLoad = t.GpuLoadPercent;
                }

                if (t.GpuTempC.HasValue && (!maxGpu.HasValue || t.GpuTempC.Value > maxGpu.Value)) maxGpu = t.GpuTempC;
                if (t.BoardTempC.HasValue && (!maxBoard.HasValue || t.BoardTempC.Value > maxBoard.Value)) maxBoard = t.BoardTempC;
                if (t.StorageMaxTempC.HasValue && (!maxStorage.HasValue || t.StorageMaxTempC.Value > maxStorage.Value)) maxStorage = t.StorageMaxTempC;
            }

            if (idleCount > 0) p.IdleTempC = Math.Round(idleSum / idleCount, 1);
            else p.IdleTempC = s.CpuIdleTempC;

            if (loadCount > 0) p.AverageUnderLoadC = Math.Round(loadSum / loadCount, 1);

            p.MaxTempC = Round(maxTemp);
            p.MaxPackageWatts = Round(maxWatts);
            p.MinClockUnderLoadMhz = Round(minClock);
            p.MaxClockUnderLoadMhz = Round(maxClock);
            p.IdleFanRpm = Round(idleFan);
            p.MaxFanRpm = Round(maxFan);
            p.MaxGpuTempC = Round(maxGpu);
            p.MaxBoardTempC = Round(maxBoard);
            p.MaxStorageTempC = Round(maxStorage);
            p.MaxGpuLoadPercent = Round(maxGpuLoad);

            // Velocidade de subida: dissipador entupido ou pasta seca aquece
            // muito mais rapido que um conjunto em ordem.
            if (p.IdleTempC.HasValue && maxTemp.HasValue && peakAtSecond.HasValue && loadStartSecond.HasValue)
            {
                double seconds = peakAtSecond.Value - loadStartSecond.Value;
                p.SecondsToPeak = Math.Round(seconds, 1);
                if (seconds >= 2)
                    p.RampRateCPerMinute = Math.Round((maxTemp.Value - p.IdleTempC.Value) / seconds * 60.0, 1);
            }

            // Recuperacao: um conjunto sadio volta perto do repouso rapido.
            if (lastCooldownTemp.HasValue && maxTemp.HasValue && cooldownStart.HasValue && cooldownEnd.HasValue)
            {
                p.RecoveryTempC = Round(lastCooldownTemp);
                double seconds = cooldownEnd.Value - cooldownStart.Value;
                p.RecoverySeconds = Math.Round(seconds, 1);
                if (seconds >= 2)
                    p.CooldownRateCPerMinute = Math.Round((maxTemp.Value - lastCooldownTemp.Value) / seconds * 60.0, 1);
            }

            return p;
        }

        private static double? Round(double? v)
        {
            return v.HasValue ? (double?)Math.Round(v.Value, 1) : null;
        }

        private static string BuildGpuNote(StressResults s)
        {
            double? maxGpu = s.Thermal != null ? s.Thermal.MaxGpuTempC : null;

            if (s.Gpu != null && s.Gpu.Executed)
            {
                string device = s.Gpu.RenderDevice ?? "renderizador nao identificado";

                if (s.Gpu.HardwareAccelerated != true)
                    return "A fase de carga de GPU rodou, mas o contexto grafico obtido (" + device +
                           ") nao usa aceleracao de hardware real - provavelmente sessao remota ou GPU hibrida " +
                           "mal configurada. A temperatura observada NAO reflete a placa de video sob carga.";

                if (!maxGpu.HasValue)
                    return "Carga 3D real foi aplicada via " + device +
                           ", mas nenhum sensor de temperatura de GPU respondeu.";

                return "Carga 3D real foi aplicada via " + device + " (maximo observado: " +
                       maxGpu.Value.ToString("F1", CultureInfo.InvariantCulture) + " C).";
            }

            if (!maxGpu.HasValue)
                return "A GPU foi monitorada durante toda a carga, mas nenhum sensor de temperatura de GPU respondeu. " +
                       "Esta execucao nao aplicou carga 3D (use --gpu-stress): o valor observado e o da GPU no uso corrente do sistema.";

            return "A GPU foi monitorada durante toda a carga (maximo observado: " +
                   maxGpu.Value.ToString("F1", CultureInfo.InvariantCulture) + " C). " +
                   "Esta execucao nao aplicou carga 3D dedicada (use --gpu-stress), entao este valor reflete o uso corrente do sistema, " +
                   "nao o pior caso da placa de video.";
        }

        private static void Sleep(int ms)
        {
            try { Thread.Sleep(ms); }
            catch (ThreadInterruptedException) { }
        }

        // ================================================================
        //  Amostragem continua de sensores.
        //
        //  Roda numa thread propria com prioridade acima do normal: durante a
        //  carga todos os nucleos estao ocupados, e uma thread de prioridade
        //  normal ficaria sem CPU justamente no momento em que a medicao mais
        //  importa - deixando buracos na curva de temperatura.
        // ================================================================
        private sealed class TelemetryMonitor
        {
            private readonly ScanContext _ctx;
            private readonly SourceSet _src;
            private readonly StressCollector _owner;
            private readonly List<TelemetrySample> _samples = new List<TelemetrySample>();
            private readonly object _samplesLock = new object();
            private readonly Stopwatch _clock = new Stopwatch();

            private Thread _thread;
            private volatile bool _stop;
            private long _lastOperations;
            private double _lastThroughputAt;
            private long _lastGpuFrames;
            private double _lastGpuFramesAt;

            public volatile string Phase = "inicio";

            // LastCpuTemp/LastStorageTemp sao escritos pela thread de
            // amostragem e lidos por outras (supervisora de RunCpuStress,
            // RunCooldown), entao nao podem ser propriedades automaticas de
            // double? (Nullable<double>) sem lock nem volatile: Nullable<T>
            // e um struct de dois campos (bool HasValue + T Value), e sem
            // sincronizacao o leitor pode observar o HasValue de UMA
            // escrita e o Value de OUTRA (tearing), ou um valor obsoleto
            // por ausencia de barreira de memoria - justamente durante a
            // carga maxima de CPU, quando a leitura termica mais importa.
            // Por isso usam um long que guarda os bits de um double
            // (sentinela NaN = "sem valor"), lido/escrito atomicamente com
            // Interlocked.Exchange/Read - sem tearing possivel, e com a
            // barreira de memoria implicita das operacoes Interlocked.
            //
            // O timestamp da amostra (tambem via Interlocked) e o que
            // permite a RunCooldown distinguir "sensor respondeu ha pouco"
            // de "sensor parou de responder, isto e so o ultimo valor
            // conhecido".
            private static readonly long NoTempBits = BitConverter.DoubleToInt64Bits(double.NaN);
            private long _lastCpuTempBits = NoTempBits;
            private long _lastCpuTempAtBits = NoTempBits;
            private long _lastStorageTempBits = NoTempBits;
            private long _lastGpuTempBits = NoTempBits;

            private const double StaleReadingSeconds = 2.0;

            public double? LastCpuTemp
            {
                get
                {
                    double v = BitConverter.Int64BitsToDouble(Interlocked.Read(ref _lastCpuTempBits));
                    return double.IsNaN(v) ? (double?)null : v;
                }
            }

            // Mesmo mecanismo bit-a-bit de LastCpuTemp (ver comentario
            // acima) - evita tearing entre a thread de amostragem (escreve)
            // e a thread de carga de GPU (le, no corte de seguranca termico
            // de RunGpuStress).
            public double? LastGpuTemp
            {
                get
                {
                    double v = BitConverter.Int64BitsToDouble(Interlocked.Read(ref _lastGpuTempBits));
                    return double.IsNaN(v) ? (double?)null : v;
                }
            }

            private void SetLastGpuTemp(double value)
            {
                Interlocked.Exchange(ref _lastGpuTempBits, BitConverter.DoubleToInt64Bits(value));
            }

            public double? LastStorageTemp
            {
                get
                {
                    double v = BitConverter.Int64BitsToDouble(Interlocked.Read(ref _lastStorageTempBits));
                    return double.IsNaN(v) ? (double?)null : v;
                }
            }

            // Tempo decorrido desde o inicio da amostragem, para quem
            // precisa avaliar frescor de uma leitura (ver FreshCpuTemp).
            public double ElapsedSeconds { get { return _clock.Elapsed.TotalSeconds; } }

            // Diferente de LastCpuTemp (que fica "grudado" no ultimo valor
            // conhecido para sempre), esta versao devolve null quando a
            // ultima amostra valida e mais velha que StaleReadingSeconds -
            // ausencia de leitura fresca e tratada como AUSENCIA, nao como
            // estabilidade.
            public double? FreshCpuTemp()
            {
                double v = BitConverter.Int64BitsToDouble(Interlocked.Read(ref _lastCpuTempBits));
                double at = BitConverter.Int64BitsToDouble(Interlocked.Read(ref _lastCpuTempAtBits));
                if (double.IsNaN(v) || double.IsNaN(at)) return null;
                if (ElapsedSeconds - at > StaleReadingSeconds) return null;
                return v;
            }

            private void SetLastCpuTemp(double value, double atSecond)
            {
                Interlocked.Exchange(ref _lastCpuTempBits, BitConverter.DoubleToInt64Bits(value));
                Interlocked.Exchange(ref _lastCpuTempAtBits, BitConverter.DoubleToInt64Bits(atSecond));
            }

            private void SetLastStorageTemp(double value)
            {
                Interlocked.Exchange(ref _lastStorageTempBits, BitConverter.DoubleToInt64Bits(value));
            }

            // Stop() desiste do Join apos 5000ms sem garantia de que a
            // thread de fato terminou - se a leitura de sensores travar
            // (driver ruim, contencao), a thread de amostragem pode
            // continuar dando .Add() em _samples enquanto RunAllPhases
            // (chamador de Stop) ja fez
            // s.Timeline.AddRange(_monitor.Samples), um foreach sobre a
            // MESMA List<T> mutavel. Um lock em torno de toda
            // escrita/leitura de _samples fecha a janela; devolver uma
            // COPIA (nao a lista interna) impede que o chamador itere sobre
            // algo que ainda pode mudar depois do lock liberado.
            public List<TelemetrySample> Samples
            {
                get { lock (_samplesLock) { return new List<TelemetrySample>(_samples); } }
            }

            public TelemetryMonitor(ScanContext ctx, SourceSet src, StressCollector owner)
            {
                _ctx = ctx;
                _src = src;
                _owner = owner;
            }

            public void Start()
            {
                _clock.Start();
                _thread = new Thread(Loop);
                _thread.IsBackground = true;
                _thread.Name = "telemetria";
                try { _thread.Priority = ThreadPriority.AboveNormal; }
                catch { }
                _thread.Start();
            }

            public void MarkThroughputStart()
            {
                _lastOperations = Interlocked.Read(ref _owner._totalOperations);
                _lastThroughputAt = _clock.Elapsed.TotalSeconds;
            }

            public void MarkGpuThroughputStart()
            {
                _lastGpuFrames = Interlocked.Read(ref _owner._totalGpuFrames);
                _lastGpuFramesAt = _clock.Elapsed.TotalSeconds;
            }

            public void Stop()
            {
                _stop = true;
                if (_thread != null) _thread.Join(5000);
                _clock.Stop();
            }

            private void Loop()
            {
                while (!_stop)
                {
                    try { Sample(); }
                    catch (Exception ex)
                    {
                        _ctx.Log.Write(LogLevel.Warn, LogChannel.Errors, "Stress",
                            "Falha amostrando telemetria: " + ex.GetType().Name + ": " + ex.Message);
                    }

                    for (int i = 0; i < 10 && !_stop; i++) Thread.Sleep(100);
                }
            }

            private void Sample()
            {
                TelemetrySample t = new TelemetrySample();
                t.AtSecond = Math.Round(_clock.Elapsed.TotalSeconds, 1);
                t.Phase = Phase;

                double now = _clock.Elapsed.TotalSeconds;
                long operations = Interlocked.Read(ref _owner._totalOperations);
                double window = now - _lastThroughputAt;
                if (window > 0.2 && operations >= _lastOperations)
                    t.ThroughputGflops = Math.Round((operations - _lastOperations) / window / 1e9, 2);
                _lastOperations = operations;
                _lastThroughputAt = now;

                long gpuFrames = Interlocked.Read(ref _owner._totalGpuFrames);
                double gpuWindow = now - _lastGpuFramesAt;
                if (gpuWindow > 0.2 && gpuFrames >= _lastGpuFrames)
                    t.GpuFramesPerSecond = Math.Round((gpuFrames - _lastGpuFrames) / gpuWindow, 1);
                _lastGpuFrames = gpuFrames;
                _lastGpuFramesAt = now;

                if (_src.Sensors != null && _src.Sensors.Available)
                {
                    IList<SensorReading> readings = _src.Sensors.Read();

                    t.CpuTempC = SensorSource.Find(readings, "Cpu", "Temperature",
                        new string[] { "Package", "Tctl", "Average", "Core" });
                    t.CpuPackageWatts = SensorSource.Find(readings, "Cpu", "Power",
                        new string[] { "Package", "CPU Package", "Cores" });
                    t.CpuClockMhz = MaxOf(readings, "Cpu", "Clock", "Core");
                    t.GpuTempC = SensorSource.Find(readings, "Gpu", "Temperature", new string[] { "Core", "GPU" });
                    t.GpuLoadPercent = SensorSource.Find(readings, "Gpu", "Load", new string[] { "Core", "GPU" });
                    t.BoardTempC = SensorSource.Find(readings, "Motherboard", "Temperature", null);
                    if (!t.BoardTempC.HasValue) t.BoardTempC = SensorSource.Find(readings, "SuperIO", "Temperature", null);
                    t.StorageMaxTempC = MaxOf(readings, "Storage", "Temperature", null);
                    t.MaxFanRpm = MaxOfAnyHardware(readings, "Fan");

                    if (t.CpuTempC.HasValue) SetLastCpuTemp(t.CpuTempC.Value, now);
                    if (t.StorageMaxTempC.HasValue) SetLastStorageTemp(t.StorageMaxTempC.Value);
                    if (t.GpuTempC.HasValue) SetLastGpuTemp(t.GpuTempC.Value);
                }

                lock (_samplesLock) { _samples.Add(t); }
            }

            private static double? MaxOf(IList<SensorReading> readings, string hardwareTypeContains, string sensorType, string nameContains)
            {
                double? best = null;
                foreach (SensorReading r in readings)
                {
                    if (r.HardwareType == null || r.SensorType == null) continue;
                    if (r.HardwareType.IndexOf(hardwareTypeContains, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    if (!string.Equals(r.SensorType, sensorType, StringComparison.OrdinalIgnoreCase)) continue;

                    // "Distance to TjMax" nao e temperatura, e quantos graus
                    // faltam para o limite. Ler como temperatura inverteria o
                    // diagnostico.
                    if (r.Name != null && r.Name.IndexOf("Distance", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    if (nameContains != null && (r.Name == null || r.Name.IndexOf(nameContains, StringComparison.OrdinalIgnoreCase) < 0)) continue;

                    if (!best.HasValue || r.Value > best.Value) best = r.Value;
                }
                return best;
            }

            private static double? MaxOfAnyHardware(IList<SensorReading> readings, string sensorType)
            {
                double? best = null;
                foreach (SensorReading r in readings)
                {
                    if (r.SensorType == null) continue;
                    if (!string.Equals(r.SensorType, sensorType, StringComparison.OrdinalIgnoreCase)) continue;
                    if (!best.HasValue || r.Value > best.Value) best = r.Value;
                }
                return best;
            }
        }
    }
}
