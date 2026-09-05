using System;
using System.Collections.Generic;
using System.Globalization;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Analysis
{
    public sealed class StressTests : IDiagnosticTest
    {
        public string Category { get { return "Carga"; } }

        public IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv)
        {
            List<TestResult> list = new List<TestResult>();

            // A identificacao pelo CPUID vale mesmo sem carga: e leitura pura
            // do processador, entao entra na categoria do componente.
            TestResult identity = CpuIdentity(inv);
            if (identity != null) list.Add(identity);

            StressResults s = inv.Stress;
            if (s == null || !s.Executed)
            {
                TestResult skipped = T.Make("STR-001", "Teste de carga", Category,
                    "Carga real de CPU para revelar superaquecimento que nao aparece em repouso.");
                skipped.Requires = Requirement.StressConsent;
                list.Add(T.NotTested(skipped, s == null
                    ? "Modulo de carga nao executado."
                    : T.Name(s.SkipReason, "Teste de carga nao autorizado nesta execucao.")));
                return list;
            }

            list.Add(ThermalUnderLoad(ctx, s));
            list.Add(ArithmeticStability(s));
            list.Add(PerformanceSustain(s));
            list.Add(FanUnderLoad(s));
            list.Add(HeatRampRate(ctx, s));
            list.Add(ThermalRecovery(s));
            list.Add(PackagePower(s));
            list.Add(GpuDuringLoad(ctx, s));
            list.Add(GpuPerformanceSustain(s));
            list.Add(StorageTemperature(s));

            list.Add(MemoryIntegrity(s));
            list.Add(MemoryBandwidth(inv, s));
            list.Add(MemoryLatency(s));

            foreach (DiskBenchmark b in s.DiskBenchmarks)
            {
                TestResult speed = DiskSpeed(b);
                if (speed != null) list.Add(speed);

                TestResult random = DiskRandomIo(b);
                if (random != null) list.Add(random);
            }

            return list;
        }

        // ---------------- identidade ----------------

        private static TestResult CpuIdentity(Inventory inv)
        {
            CpuLowLevelInfo low = inv.Cpu != null ? inv.Cpu.LowLevel : null;
            if (low == null) return null;

            TestResult r = T.Make("STR-000", "Identificacao do processador pelo silicio", "Processador",
                "Modelo, familia e extensoes lidos pela instrucao CPUID, sem intermediario do sistema.");

            T.Ev(r, "CPUID", "fabricante", T.Name(low.Vendor, "nao identificado"));
            T.Ev(r, "CPUID", "modelo", T.Name(low.BrandString, "nao identificado"));
            T.Ev(r, "CPUID", "familia/modelo/stepping",
                T.Num(low.Family) + "/" + T.Num(low.ModelId) + "/" + T.Num(low.Stepping));
            T.Ev(r, "CPUID", "extensoes", T.Name(low.Features, "nao disponivel"));
            if (low.TscMhz.HasValue) T.Ev(r, "RDTSC", "frequencia base do contador", T.Num(low.TscMhz, 0) + " MHz");
            foreach (string c in low.Caches) T.Ev(r, "CPUID", "cache", c);

            if (low.HypervisorPresent.HasValue && low.HypervisorPresent.Value)
            {
                return T.Info(r, "Processador " + T.Name(low.BrandString, "nao identificado") +
                    " rodando sob virtualizacao (" + T.Name(low.HypervisorVendor, "hipervisor nao identificado") +
                    "). Temperatura e sensores fisicos nao sao confiaveis dentro de maquina virtual.",
                    Confidence.Build().Authoritative().Value);
            }

            // Unica fonte (CPUID) - sem segunda fonte independente
            // concordando, nao ha AgreeingSource() a reivindicar.
            return T.Pass(r, "Processador identificado diretamente no silicio: " +
                T.Name(low.BrandString, "modelo nao exposto") + ".",
                Confidence.Build().Authoritative().Value);
        }

        // ---------------- termico ----------------

        // Este e o teste que o diagnostico estatico nao consegue fazer: muita
        // CPU passa em repouso e so falha quando exigida de verdade.
        private static TestResult ThermalUnderLoad(ScanContext ctx, StressResults s)
        {
            TestResult r = T.Make("STR-001", "Temperatura da CPU sob carga total", "Carga",
                "Temperatura maxima atingida com todos os nucleos carregados.");
            r.Requires = Requirement.StressConsent;

            ThermalProfile p = s.Thermal;

            T.Ev(r, "Carga", "duracao", s.DurationSeconds + " s");
            T.Ev(r, "Carga", "motor", T.Name(s.Engine, "nao informado"));
            if (s.Cpu != null)
            {
                T.Ev(r, "Carga", "threads", s.Cpu.ThreadCount +
                    (s.Cpu.ThreadsPinned ? " (uma por processador logico, fixadas)" : " (sem fixacao)"));
                if (s.Cpu.MaxLoadPercent.HasValue)
                    T.Ev(r, "Carga", "carga de CPU atingida", T.Num(s.Cpu.MaxLoadPercent, 0) + "%");
                if (s.Cpu.PeakGflops.HasValue)
                    T.Ev(r, "Carga", "vazao de pico", T.Num(s.Cpu.PeakGflops, 2) + " GFLOP/s");
                if (!s.Cpu.ThermalProtectionActive)
                    T.Ev(r, "Seguranca", "protecao termica automatica", "INDISPONIVEL (sem sensor de temperatura)");
                if (s.Cpu.AbortedAtTempC.HasValue)
                    T.Ev(r, "Seguranca", "carga interrompida automaticamente", T.Num(s.Cpu.AbortedAtTempC, 1) + " C");
            }

            if (p == null || !p.MaxTempC.HasValue)
                return T.NotTested(r, "A carga foi aplicada, mas nenhum sensor de temperatura de CPU respondeu para medir o resultado. " +
                    "Sem sensor nao ha como afirmar nada sobre a refrigeracao - e um teste nao executado, nao um teste aprovado.");

            double max = p.MaxTempC.Value;

            // Um valor fisicamente impossivel (ex.: -40 C, ou 300 C) nao
            // prova nada sobre a refrigeracao - e sensor quebrado, nao
            // dado, entao nao deve conceder PlausibleRange() nem produzir
            // um veredito.
            if (!Collectors.Helpers.IsPlausibleTemperature(max))
                return T.NotTested(r, "O sensor reportou " + T.Num(max, 1) +
                    " C sob carga - fora da faixa fisicamente plausivel para um processador. Provavelmente o sensor esta com defeito ou o driver reportou um valor invalido; o resultado nao pode ser usado para avaliar a refrigeracao.");

            T.Ev(r, "Sensor", "temperatura maxima sob carga", T.Num(max, 1) + " C");
            if (p.AverageUnderLoadC.HasValue) T.Ev(r, "Sensor", "media sob carga", T.Num(p.AverageUnderLoadC, 1) + " C");
            if (p.IdleTempC.HasValue)
            {
                T.Ev(r, "Sensor", "temperatura em repouso", T.Num(p.IdleTempC, 1) + " C");
                T.Ev(r, "Analise", "variacao sob carga", T.Num(max - p.IdleTempC.Value, 1) + " C");
            }

            // E uma unica leitura de um unico sensor de terceiro (a
            // biblioteca de sensores) - sem segunda fonte independente
            // concordando, a confianca honesta fica em
            // Authoritative()+PlausibleRange() = 80, nao 90.
            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (max >= ctx.Options.CpuCritC)
            {
                bool aborted = s.Cpu != null && s.Cpu.AbortedAtTempC.HasValue;
                string prefix = aborted ? "Carga interrompida automaticamente por seguranca: a " : "A ";
                return T.Error(r, Severity.High,
                    prefix + "CPU atingiu " + T.Num(max, 1) + " C sob carga total, acima do limiar critico de " + ctx.Options.CpuCritC + " C.",
                    "Refrigeracao insuficiente - risco real de dano ao equipamento sob carga sustentada. Limpar dissipador e ventoinhas, reaplicar pasta termica e conferir o fluxo de ar antes de repetir este teste.",
                    confidence);
            }

            if (max >= ctx.Options.CpuWarnC)
                return T.Warn(r, Severity.Medium,
                    "CPU atingiu " + T.Num(max, 1) + " C sob carga total (limiar de atencao: " + ctx.Options.CpuWarnC + " C).",
                    "Ainda dentro do tolerado, mas com pouca margem. Em notebook fino esse patamar e comum por projeto; em desktop, indica que a refrigeracao merece revisao.",
                    confidence);

            // Carga baixa invalida a conclusao: o teste nao provou o pior caso.
            if (s.Cpu != null && s.Cpu.MaxLoadPercent.HasValue && s.Cpu.MaxLoadPercent.Value < 70)
                return T.Unknown(r, "A carga atingiu apenas " + T.Num(s.Cpu.MaxLoadPercent, 0) +
                    "%, insuficiente para concluir sobre o comportamento termico no pior caso.");

            // Quando o motor nativo (FMA de 256 bits em codigo de maquina)
            // nao carrega - processo 32 bits, pagina executavel barrada por
            // politica/EDR - BurnManaged assume com um laco escalar que NAO
            // satura unidade vetorial nenhuma (o proprio comentario ao lado
            // da declaracao admite "aquece menos"). ArithmeticStability ja
            // recusa aprovar nesse caso (checa s.EngineFallbackReason); este
            // teste faz o mesmo, para nao aprovar refrigeracao com uma
            // carga sabidamente fraca demais para provar o pior caso.
            // Vereditos NEGATIVOS acima (Error/Warn) continuam validos - se
            // esquentou ate com carga fraca, esquentaria mais com a forte;
            // so o "esfriou" abaixo fica sem prova.
            if (!string.IsNullOrEmpty(s.EngineFallbackReason))
                return T.Unknown(r, "Carga aplicada pelo laco gerenciado (motor nativo indisponivel: " + s.EngineFallbackReason +
                    ") - aquece bem menos que o motor nativo com FMA vetorial, entao " + T.Num(max, 1) +
                    " C nao prova refrigeracao adequada sob o pior caso real.");

            return T.Pass(r, "CPU estabilizou em " + T.Num(max, 1) + " C sob carga total - refrigeracao adequada.", confidence);
        }

        // A CPU errar conta antes de travar e o sintoma classico de
        // instabilidade: overclock alem do que o silicio aguenta, tensao
        // insuficiente, memoria com XMP instavel ou degradacao por idade.
        // Nenhuma dessas aparece em diagnostico de leitura.
        private static TestResult ArithmeticStability(StressResults s)
        {
            TestResult r = T.Make("STR-002", "Estabilidade aritmetica da CPU sob carga", "Carga",
                "Conferencia do resultado de cada lote de calculo contra o valor exato esperado.");
            r.Requires = Requirement.StressConsent;

            CpuStressResult c = s.Cpu;
            if (c == null)
                return T.NotTested(r, "A fase de carga de CPU nao produziu resultado.");

            if (!string.IsNullOrEmpty(s.EngineFallbackReason))
                return T.NotTested(r, "A verificacao aritmetica exige o motor de codigo nativo, que nao pode ser carregado nesta maquina (" +
                    s.EngineFallbackReason + "). A carga foi aplicada pelo caminho gerenciado, que aquece menos e nao confere resultado.");

            T.Ev(r, "Carga", "operacoes verificadas", c.TotalOperations.ToString("N0", CultureInfo.InvariantCulture));
            T.Ev(r, "Carga", "threads", c.ThreadCount.ToString(CultureInfo.InvariantCulture));
            T.Ev(r, "Carga", "erros de calculo", c.ArithmeticErrors.ToString(CultureInfo.InvariantCulture));

            if (c.ArithmeticErrors > 0)
            {
                string onde = c.FaultyProcessors.Count > 0
                    ? " Processadores logicos envolvidos: " + string.Join(", ", c.FaultyProcessors.ConvertAll<string>(ToText).ToArray()) + "."
                    : "";

                if (c.FirstErrorDetail != null) T.Ev(r, "Carga", "primeira divergencia", c.FirstErrorDetail);

                return T.Critical(r,
                    "A CPU produziu " + c.ArithmeticErrors.ToString("N0", CultureInfo.InvariantCulture) +
                    " resultado(s) incorreto(s) sob carga." + onde +
                    " O calculo conferido tem resultado exato conhecido, entao isto nao e arredondamento: e erro de processamento real.",
                    "Nao entregar o equipamento neste estado. Verificar, nesta ordem: perfil de overclock ou XMP ativo na BIOS (voltar ao padrao e repetir), " +
                    "temperatura e refrigeracao, tensao da fonte, e por fim a propria memoria. Se o erro persistir com tudo no padrao e temperatura normal, " +
                    "o processador esta degradado.",
                    // A conferencia aritmetica e a UNICA fonte deste
                    // achado - nao ha segunda fonte independente
                    // concordando.
                    Confidence.Build().Authoritative().Value);
            }

            if (c.TotalOperations <= 0)
                return T.NotTested(r, "Nenhuma operacao de calculo foi concluida durante a carga.");

            return T.Pass(r,
                "Nenhum erro de calculo em " + c.TotalOperations.ToString("N0", CultureInfo.InvariantCulture) +
                " operacoes de ponto flutuante conferidas, em " + c.ThreadCount + " thread(s) simultaneas.",
                Confidence.Build().Authoritative().PlausibleRange().Value);
        }

        private static string ToText(int value)
        {
            return value.ToString(CultureInfo.InvariantCulture);
        }

        // Throttling medido pelo desempenho realmente entregue: se a maquina
        // termina a carga mais lenta do que comecou, ela nao aguenta o proprio
        // calor. Nao depende de MSR nem de driver.
        private static TestResult PerformanceSustain(StressResults s)
        {
            TestResult r = T.Make("STR-004", "Sustentacao de desempenho sob carga prolongada", "Carga",
                "Comparacao entre a vazao do inicio e a do fim da carga - queda indica reducao termica de frequencia.");
            r.Requires = Requirement.StressConsent;

            CpuStressResult c = s.Cpu;
            if (c == null || !c.SustainPercent.HasValue)
                return T.NotTested(r, "Carga curta demais para comparar inicio e fim. Use --stress-seconds 120 ou mais para avaliar sustentacao.");

            double sustain = c.SustainPercent.Value;
            T.Ev(r, "Carga", "vazao no inicio", T.Num(c.FirstWindowGflops, 2) + " GFLOP/s");
            T.Ev(r, "Carga", "vazao no fim", T.Num(c.LastWindowGflops, 2) + " GFLOP/s");
            T.Ev(r, "Analise", "desempenho mantido", T.Num(sustain, 1) + "%");

            ThermalProfile p = s.Thermal;
            if (p != null && p.MinClockUnderLoadMhz.HasValue && p.MaxClockUnderLoadMhz.HasValue)
            {
                T.Ev(r, "Sensor", "frequencia sob carga",
                    T.Num(p.MinClockUnderLoadMhz, 0) + " a " + T.Num(p.MaxClockUnderLoadMhz, 0) + " MHz");
            }

            string thermalContext = (p != null && p.MaxTempC.HasValue)
                ? " Temperatura maxima no periodo: " + T.Num(p.MaxTempC, 1) + " C."
                : "";

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (sustain < 70)
                return T.Error(r, Severity.High,
                    "O equipamento entregou apenas " + T.Num(sustain, 1) +
                    "% do desempenho inicial ao fim da carga - perda de " + T.Num(100 - sustain, 1) + "%." + thermalContext,
                    "Reducao termica severa: a maquina nao sustenta o proprio desempenho. Limpar dissipador e ventoinhas, reaplicar pasta termica " +
                    "e verificar o fluxo de ar do gabinete. Em notebook, conferir se as saidas de ar nao estao obstruidas.",
                    confidence);

            if (sustain < 85)
                return T.Warn(r, Severity.Medium,
                    "Desempenho caiu para " + T.Num(sustain, 1) + "% do inicial ao longo da carga." + thermalContext,
                    "Perda mensuravel de desempenho sob uso prolongado. Comum em notebook fino por projeto; em desktop, indica refrigeracao no limite.",
                    confidence);

            if (sustain < 95)
                return T.Info(r, "Desempenho manteve-se em " + T.Num(sustain, 1) +
                    "% do inicial - variacao pequena, dentro do esperado." + thermalContext, confidence);

            return T.Pass(r, "Desempenho mantido em " + T.Num(sustain, 1) +
                "% do inicial ate o fim da carga - sem reducao termica relevante." + thermalContext, confidence);
        }

        // Ventoinha parada com a CPU quente e das poucas falhas que o cliente
        // sente e o diagnostico de leitura nunca pega: em repouso a ventoinha
        // legitimamente nao gira.
        private static TestResult FanUnderLoad(StressResults s)
        {
            TestResult r = T.Make("STR-005", "Resposta da ventoinha a carga", "Carga",
                "Rotacao das ventoinhas em repouso e sob carga total.");
            r.Requires = Requirement.StressConsent;

            ThermalProfile p = s.Thermal;
            if (p == null || !p.MaxFanRpm.HasValue)
                return T.NotTested(r, "Nenhum sensor de rotacao de ventoinha respondeu nesta maquina. " +
                    "Muitos notebooks e placas-mae nao expoem essa leitura - a ausencia nao indica defeito, apenas que nao foi possivel verificar.");

            double maxFan = p.MaxFanRpm.Value;
            T.Ev(r, "Sensor", "rotacao maxima sob carga", T.Num(maxFan, 0) + " RPM");
            if (p.IdleFanRpm.HasValue) T.Ev(r, "Sensor", "rotacao em repouso", T.Num(p.IdleFanRpm, 0) + " RPM");
            if (p.MaxTempC.HasValue) T.Ev(r, "Sensor", "temperatura maxima", T.Num(p.MaxTempC, 1) + " C");

            int confidence = Confidence.Build().Authoritative().Value;
            bool gotHot = p.MaxTempC.HasValue && p.MaxTempC.Value >= 60;

            if (maxFan <= 0)
            {
                if (!gotHot)
                    return T.Unknown(r, "Nenhuma ventoinha girou, mas a CPU tambem nao passou de " +
                        T.Num(p.MaxTempC, 1) + " C - pode ser controle semi-passivo funcionando corretamente.");

                return T.Critical(r,
                    "Nenhuma ventoinha girou durante toda a carga, com a CPU chegando a " + T.Num(p.MaxTempC, 1) + " C.",
                    "Verificar imediatamente: cabo da ventoinha desconectado, conector errado na placa-mae, rolamento travado ou curva de ventoinha " +
                    "desativada na BIOS. Rodar o equipamento neste estado leva a desligamento por temperatura e desgaste do processador.",
                    confidence);
            }

            if (p.IdleFanRpm.HasValue && gotHot && maxFan <= p.IdleFanRpm.Value * 1.05)
                return T.Warn(r, Severity.Medium,
                    "A ventoinha ficou em " + T.Num(maxFan, 0) + " RPM sob carga, praticamente a mesma rotacao do repouso (" +
                    T.Num(p.IdleFanRpm, 0) + " RPM), mesmo com a CPU a " + T.Num(p.MaxTempC, 1) + " C.",
                    "A ventoinha gira mas nao acelera com o calor. Conferir a curva de ventoinha na BIOS e se o sensor de temperatura usado como " +
                    "referencia pelo controlador esta funcionando.",
                    confidence);

            return T.Pass(r, "Ventoinha respondeu a carga, chegando a " + T.Num(maxFan, 0) + " RPM.", confidence);
        }

        // Dissipador entupido ou pasta termica seca esquentam muito mais
        // rapido que um conjunto em ordem, mesmo quando a temperatura final
        // acaba dentro do limite.
        private static TestResult HeatRampRate(ScanContext ctx, StressResults s)
        {
            TestResult r = T.Make("STR-006", "Velocidade de aquecimento", "Carga",
                "Quanto tempo a CPU levou do repouso ate a temperatura maxima.");
            r.Requires = Requirement.StressConsent;

            ThermalProfile p = s.Thermal;
            if (p == null || !p.RampRateCPerMinute.HasValue || !p.SecondsToPeak.HasValue)
                return T.NotTested(r, "Nao houve amostras de temperatura suficientes para medir a velocidade de aquecimento.");

            T.Ev(r, "Analise", "taxa de subida", T.Num(p.RampRateCPerMinute, 1) + " C por minuto");
            T.Ev(r, "Analise", "tempo ate o pico", T.Num(p.SecondsToPeak, 1) + " s");
            if (p.IdleTempC.HasValue && p.MaxTempC.HasValue)
                T.Ev(r, "Sensor", "de/para", T.Num(p.IdleTempC, 1) + " C para " + T.Num(p.MaxTempC, 1) + " C");

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;
            bool reachedWarning = p.MaxTempC.HasValue && p.MaxTempC.Value >= ctx.Options.CpuWarnC;

            if (p.SecondsToPeak.Value <= 20 && reachedWarning)
                return T.Warn(r, Severity.Medium,
                    "A CPU foi de " + T.Num(p.IdleTempC, 1) + " C a " + T.Num(p.MaxTempC, 1) + " C em apenas " +
                    T.Num(p.SecondsToPeak, 1) + " s (" + T.Num(p.RampRateCPerMinute, 1) + " C/min).",
                    "Subida muito rapida ate patamar alto indica que o calor nao esta sendo transferido para o dissipador: pasta termica ressecada, " +
                    "dissipador mal assentado ou aletas obstruidas por poeira. E um sinal precoce - vale corrigir antes que vire desligamento por temperatura.",
                    confidence);

            return T.Info(r, "Aquecimento de " + T.Num(p.RampRateCPerMinute, 1) + " C por minuto, atingindo o pico em " +
                T.Num(p.SecondsToPeak, 1) + " s. Serve de referencia para comparar este mesmo equipamento apos a manutencao.",
                confidence);
        }

        // O par subida/descida separa "projeto apertado" de "precisa de
        // limpeza": um notebook fino esquenta rapido mas tambem esfria; um
        // dissipador entupido esquenta rapido e nao esfria.
        private static TestResult ThermalRecovery(StressResults s)
        {
            TestResult r = T.Make("STR-007", "Recuperacao termica apos a carga", "Carga",
                "Quanto o equipamento esfria sozinho depois que a carga termina.");
            r.Requires = Requirement.StressConsent;

            ThermalProfile p = s.Thermal;
            if (p == null || !p.RecoveryTempC.HasValue || !p.MaxTempC.HasValue || !p.RecoverySeconds.HasValue)
                return T.NotTested(r, "Nao houve amostras suficientes na fase de resfriamento para avaliar a recuperacao.");

            double recovered = p.MaxTempC.Value - p.RecoveryTempC.Value;
            T.Ev(r, "Sensor", "temperatura ao fim da carga", T.Num(p.MaxTempC, 1) + " C");
            T.Ev(r, "Sensor", "temperatura apos resfriamento", T.Num(p.RecoveryTempC, 1) + " C");
            T.Ev(r, "Analise", "tempo de resfriamento", T.Num(p.RecoverySeconds, 1) + " s");
            T.Ev(r, "Analise", "queda", T.Num(recovered, 1) + " C");
            if (p.CooldownRateCPerMinute.HasValue)
                T.Ev(r, "Analise", "taxa de resfriamento", T.Num(p.CooldownRateCPerMinute, 1) + " C por minuto");

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (!p.IdleTempC.HasValue)
                return T.Info(r, "Caiu " + T.Num(recovered, 1) + " C em " + T.Num(p.RecoverySeconds, 1) +
                    " s apos o fim da carga.", confidence);

            double aboveIdle = p.RecoveryTempC.Value - p.IdleTempC.Value;
            T.Ev(r, "Analise", "acima do repouso inicial", T.Num(aboveIdle, 1) + " C");

            if (aboveIdle >= 25)
                return T.Warn(r, Severity.Medium,
                    "Passados " + T.Num(p.RecoverySeconds, 1) + " s sem carga, a CPU ainda estava " + T.Num(aboveIdle, 1) +
                    " C acima da temperatura de repouso inicial.",
                    "O calor nao esta saindo do gabinete. Verificar fluxo de ar - ventoinhas de entrada e saida, cabos obstruindo o caminho do ar, " +
                    "filtros de poeira saturados - e o assentamento do dissipador.",
                    confidence);

            if (aboveIdle >= 12)
                return T.Info(r, "Esfriou " + T.Num(recovered, 1) + " C em " + T.Num(p.RecoverySeconds, 1) +
                    " s, terminando " + T.Num(aboveIdle, 1) + " C acima do repouso inicial - recuperacao parcial, dentro do razoavel.",
                    confidence);

            return T.Pass(r, "Voltou a " + T.Num(p.RecoveryTempC, 1) + " C em " + T.Num(p.RecoverySeconds, 1) +
                " s apos a carga, praticamente no patamar de repouso - dissipacao funcionando.", confidence);
        }

        private static TestResult PackagePower(StressResults s)
        {
            TestResult r = T.Make("STR-011", "Consumo do processador sob carga", "Carga",
                "Potencia do pacote da CPU no pico da carga.");
            r.Requires = Requirement.StressConsent;

            ThermalProfile p = s.Thermal;
            if (p == null || !p.MaxPackageWatts.HasValue)
                return T.NotTested(r, "O sensor de potencia do pacote nao esta disponivel nesta plataforma.");

            T.Ev(r, "Sensor", "potencia maxima do pacote", T.Num(p.MaxPackageWatts, 1) + " W");

            return T.Info(r, "O processador chegou a " + T.Num(p.MaxPackageWatts, 1) +
                " W sob carga total. Comparar com o TDP do modelo indica se a plataforma esta liberando ou limitando o processador.",
                Confidence.Build().Authoritative().SingleVolatileSample().Value);
        }

        // Com --gpu-stress, uma carga 3D real foi aplicada (ver GpuLoadEngine
        // e StressCollector.RunGpuStress) e este teste pode aprovar a
        // refrigeracao de verdade. Sem a flag (comportamento padrao), a GPU
        // continua so monitorada enquanto a CPU esta sob carga - nenhuma
        // carga 3D dedicada - e temperatura baixa nesse cenario NAO vale
        // como aprovacao, so como ausencia de problema em repouso.
        //
        // Mesmo quando a fase de carga roda mas o contexto obtido cai no
        // renderizador de SOFTWARE (GpuLoadEngine.HardwareAccelerated ==
        // false - GPU hibrida mal configurada, sessao remota sem 3D), o
        // teste trata o resultado como se nenhuma carga real tivesse sido
        // aplicada: uma carga em software nao aquece hardware nenhum, e
        // aprovar a placa de video nesse caso seria uma aprovacao vazia.
        private static TestResult GpuDuringLoad(ScanContext ctx, StressResults s)
        {
            bool realLoad = s.Gpu != null && s.Gpu.Executed && s.Gpu.HardwareAccelerated == true;

            TestResult r = T.Make("STR-013",
                realLoad ? "Temperatura da GPU sob carga 3D real" : "Temperatura da GPU durante a carga",
                "Carga",
                realLoad
                    ? "Temperatura de video observada enquanto uma carga grafica real (OpenGL) estava aplicada."
                    : "Temperatura de video observada enquanto o processador estava sob carga total.");
            r.Requires = Requirement.StressConsent;

            ThermalProfile p = s.Thermal;
            if (p == null || !p.MaxGpuTempC.HasValue)
                return T.NotTested(r, T.Name(s.GpuNote, "Nenhum sensor de temperatura de GPU respondeu."));

            double max = p.MaxGpuTempC.Value;
            T.Ev(r, "Sensor", "temperatura maxima de GPU", T.Num(max, 1) + " C");

            if (realLoad)
            {
                T.Ev(r, "Escopo", "tipo de carga aplicada", "carga 3D real (" + T.Name(s.Gpu.RenderDevice, "GPU nao identificada") + ")");
                if (p.MaxGpuLoadPercent.HasValue) T.Ev(r, "Sensor", "utilizacao maxima de GPU", T.Num(p.MaxGpuLoadPercent, 0) + "%");
            }
            else
            {
                T.Ev(r, "Escopo", "tipo de carga aplicada", "nenhuma carga 3D dedicada - apenas o uso corrente do sistema");
            }

            // Unica fonte (sensor de hardware), sem segunda fonte
            // independente concordando.
            int confidence = Confidence.Build().Authoritative().Value;

            if (max >= ctx.Options.GpuCritC)
                return T.Error(r, Severity.High,
                    (realLoad ? "Sob carga 3D real, a GPU atingiu " : "GPU atingiu ") + T.Num(max, 1) + " C" +
                    (realLoad ? "" : " mesmo SEM carga 3D aplicada") + ", acima do limiar critico de " + ctx.Options.GpuCritC + " C.",
                    "Temperatura alta e sinal forte de refrigeracao comprometida na placa de video: ventoinha parada, dissipador " +
                    "entupido ou pasta termica ressecada." + (realLoad ? "" : " Sob jogo ou renderizacao seria bem pior."),
                    confidence);

            if (max >= ctx.Options.GpuWarnC)
                return T.Warn(r, Severity.Medium,
                    "GPU chegou a " + T.Num(max, 1) + (realLoad ? " C sob carga 3D real" : " C sem carga 3D aplicada") +
                    " (limiar de atencao: " + ctx.Options.GpuWarnC + " C).",
                    realLoad
                        ? "Verificar ventoinha e limpeza da placa de video."
                        : "Verificar ventoinha e limpeza da placa de video. Para conclusao definitiva sobre a GPU, rodar um teste grafico dedicado (--gpu-stress).",
                    confidence);

            if (realLoad)
                return T.Pass(r, "GPU estabilizou em ate " + T.Num(max, 1) +
                    " C sob carga 3D real - refrigeracao adequada.", confidence);

            return T.Info(r, "GPU permaneceu em ate " + T.Num(max, 1) + " C durante a carga de processador. " +
                "Como nenhuma carga 3D real foi aplicada (use --gpu-stress para testar de verdade), este valor NAO aprova a refrigeracao da placa de video - apenas mostra que ela nao esta quente em repouso.",
                Confidence.Build().Authoritative().SingleVolatileSample().Value);
        }

        // Throttling grafico medido pelo fps realmente entregue - mesmo
        // principio do PerformanceSustain da CPU (STR-004), so que a
        // "vazao" aqui e quadros por segundo em vez de GFLOP/s. So produz
        // resultado quando --gpu-stress rodou com aceleracao de hardware
        // real; sem isso o fps medido nao significaria nada sobre a GPU.
        private static TestResult GpuPerformanceSustain(StressResults s)
        {
            TestResult r = T.Make("STR-014", "Sustentacao de desempenho grafico sob carga", "Carga",
                "Comparacao entre o fps do inicio e do fim da carga de GPU - queda indica reducao termica de clock.");
            r.Requires = Requirement.StressConsent;

            GpuStressResult g = s.Gpu;
            if (g == null || !g.Executed)
                return T.NotTested(r, "Teste de carga de GPU nao executado. Use --gpu-stress para aplicar carga grafica real.");

            if (g.HardwareAccelerated != true)
                return T.NotTested(r, "O contexto grafico obtido (" + T.Name(g.RenderDevice, "renderizador nao identificado") +
                    ") nao usa aceleracao de hardware real - o fps medido nao reflete a GPU.");

            if (!g.SustainPercent.HasValue)
                return T.NotTested(r, "Carga curta demais para comparar inicio e fim. Use --stress-seconds 60 ou mais para avaliar sustentacao.");

            double sustain = g.SustainPercent.Value;
            T.Ev(r, "Carga", "fps no inicio", T.Num(g.FirstWindowFps, 1));
            T.Ev(r, "Carga", "fps no fim", T.Num(g.LastWindowFps, 1));
            T.Ev(r, "Analise", "desempenho mantido", T.Num(sustain, 1) + "%");

            ThermalProfile p = s.Thermal;
            string thermalContext = (p != null && p.MaxGpuTempC.HasValue)
                ? " Temperatura maxima no periodo: " + T.Num(p.MaxGpuTempC, 1) + " C."
                : "";

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (sustain < 70)
                return T.Error(r, Severity.High,
                    "A GPU entregou apenas " + T.Num(sustain, 1) + "% do fps inicial ao fim da carga - perda de " +
                    T.Num(100 - sustain, 1) + "%." + thermalContext,
                    "Reducao termica severa na placa de video. Limpar dissipador e ventoinha da GPU, reaplicar pasta termica " +
                    "e verificar o fluxo de ar do gabinete.",
                    confidence);

            if (sustain < 85)
                return T.Warn(r, Severity.Medium,
                    "Fps caiu para " + T.Num(sustain, 1) + "% do inicial ao longo da carga de GPU." + thermalContext,
                    "Perda mensuravel de desempenho grafico sob uso prolongado. Verificar refrigeracao da placa de video.",
                    confidence);

            if (sustain < 95)
                return T.Info(r, "Fps manteve-se em " + T.Num(sustain, 1) +
                    "% do inicial - variacao pequena, dentro do esperado." + thermalContext, confidence);

            return T.Pass(r, "Fps mantido em " + T.Num(sustain, 1) +
                "% do inicial ate o fim da carga - sem reducao termica relevante na GPU." + thermalContext, confidence);
        }

        // SSD NVMe reduz desempenho por conta propria acima de ~70 C, e e
        // comum passar disso dentro de notebook sem dissipador no slot M.2.
        private static TestResult StorageTemperature(StressResults s)
        {
            TestResult r = T.Make("STR-012", "Temperatura do armazenamento sob carga", "Carga",
                "Temperatura maxima dos discos durante o teste.");
            r.Requires = Requirement.StressConsent;

            ThermalProfile p = s.Thermal;
            if (p == null || !p.MaxStorageTempC.HasValue)
                return T.NotTested(r, "Nenhum disco reportou temperatura durante o teste.");

            double max = p.MaxStorageTempC.Value;
            T.Ev(r, "Sensor", "temperatura maxima de disco", T.Num(max, 1) + " C");

            // MaxStorageTempC vem do MONITORAMENTO continuo (mesmo sem
            // --disk-benchmark, os sensores sao lidos a cada segundo
            // durante toda a carga de CPU) - nao exige que o disco tenha
            // sido de fato submetido a I/O. Por isso o resultado abaixo
            // distingue se houve benchmark de disco de fato, para nao
            // aprovar "temperatura sob carga" sem carga nenhuma no disco.
            bool diskWasBenchmarked = false;
            foreach (DiskBenchmark b in s.DiskBenchmarks)
                if (b.WriteMbPerSec.HasValue) { diskWasBenchmarked = true; break; }

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (max >= 80)
                return T.Error(r, Severity.High,
                    "Disco atingiu " + T.Num(max, 1) + " C durante o teste.",
                    "Acima de 80 C o SSD reduz desempenho para se proteger e a vida util cai. Instalar dissipador no slot M.2, melhorar o fluxo de ar " +
                    "ou reposicionar o disco para longe da placa de video.",
                    confidence);

            if (max >= 70)
                return T.Warn(r, Severity.Medium,
                    "Disco chegou a " + T.Num(max, 1) + " C durante o teste.",
                    "Faixa em que o SSD NVMe comeca a reduzir desempenho por temperatura. Considerar dissipador no slot M.2 e revisar a ventilacao.",
                    confidence);

            if (!diskWasBenchmarked)
                return T.Info(r, "Armazenamento permaneceu em ate " + T.Num(max, 1) +
                    " C durante a carga de CPU, mas nenhum benchmark de disco foi executado (use --disk-benchmark) - este valor e a temperatura em repouso/uso corrente do disco, nao sob carga de I/O real, e NAO aprova a refrigeracao do disco sob uso pesado.",
                    confidence);

            return T.Pass(r, "Armazenamento permaneceu em ate " + T.Num(max, 1) + " C sob carga.", confidence);
        }

        // ---------------- memoria ----------------

        private static TestResult MemoryIntegrity(StressResults s)
        {
            TestResult r = T.Make("STR-008", "Integridade da memoria RAM", "Carga",
                "Escrita e releitura conferida da memoria com padroes de teste classicos.");
            r.Requires = Requirement.StressConsent;

            MemoryStressResult m = s.Memory;
            if (m == null || !m.Executed)
                return T.NotTested(r, m == null
                    ? "Modulo de memoria nao executado."
                    : T.Name(m.SkipReason, "Teste de memoria nao autorizado nesta execucao."));

            // Defesa em profundidade: mesmo que Executed venha true por
            // algum caminho que nao tenha sido previsto, nenhum padrao
            // realmente testado (PatternsRun vazio) pode terminar em Pass.
            if (m.PatternsRun.Count == 0)
                return T.NotTested(r, "Executed=true mas nenhum padrao de teste foi de fato concluido - resultado nao confiavel.");

            T.Ev(r, "Carga", "memoria testada", T.Bytes((ulong)m.BytesTested));
            T.Ev(r, "Carga", "passagens", m.Passes.ToString(CultureInfo.InvariantCulture));
            T.Ev(r, "Carga", "padroes", string.Join(", ", m.PatternsRun.ToArray()));
            T.Ev(r, "Carga", "divergencias", m.ErrorCount.ToString(CultureInfo.InvariantCulture));

            if (m.ErrorCount > 0)
            {
                if (m.FirstErrorDetail != null) T.Ev(r, "Carga", "primeira divergencia", m.FirstErrorDetail);

                return T.Critical(r,
                    "A memoria devolveu " + m.ErrorCount.ToString("N0", CultureInfo.InvariantCulture) +
                    " valor(es) diferente(s) do que foi gravado.",
                    "Memoria com defeito ou instavel. Desligar perfil XMP/DOCP na BIOS e repetir; se o erro sumir, o perfil e agressivo demais para este conjunto. " +
                    "Se persistir, testar um pente por vez para identificar qual esta com defeito, e conferir o assentamento nos slots. " +
                    "Nao entregar o equipamento com este achado em aberto - e causa direta de tela azul e corrupcao de arquivo.",
                    // Escrita+releitura do mesmo buffer e uma unica fonte,
                    // nao duas concordando.
                    Confidence.Build().Authoritative().Value);
            }

            return T.Pass(r,
                "Nenhuma divergencia em " + T.Bytes((ulong)m.BytesTested) + " de memoria, " + m.Passes +
                " passagens sobre " + m.PatternsRun.Count + " padroes. " +
                "Cobre a memoria livre no momento do teste - a parte ocupada pelo sistema nao pode ser testada sem inicializar por fora do Windows.",
                Confidence.Build().Authoritative().PlausibleRange().Value);
        }

        private static TestResult MemoryBandwidth(Inventory inv, StressResults s)
        {
            TestResult r = T.Make("STR-009", "Banda de memoria", "Carga",
                "Velocidade de leitura e escrita em memoria principal.");
            r.Requires = Requirement.StressConsent;

            MemoryStressResult m = s.Memory;
            if (m == null || !m.WriteBandwidthMbPerSec.HasValue)
                return T.NotTested(r, "O benchmark de memoria nao pode ser executado (memoria livre insuficiente ou motor indisponivel).");

            T.Ev(r, "Carga", "escrita", T.Num(m.WriteBandwidthMbPerSec, 0) + " MB/s");
            if (m.ReadBandwidthMbPerSec.HasValue) T.Ev(r, "Carga", "leitura", T.Num(m.ReadBandwidthMbPerSec, 0) + " MB/s");
            T.Ev(r, "Metodo", "como foi medido", T.Name(m.BandwidthMethod, "nao informado"));

            double? theoretical = TheoreticalBandwidthMbPerSec(inv);
            if (theoretical.HasValue)
                T.Ev(r, "Analise", "pico teorico do conjunto instalado", T.Num(theoretical, 0) + " MB/s");

            // Medida de referencia, nao de aprovacao: nao existe limiar
            // universal de banda que sirva para todo tipo de memoria.
            return T.Info(r, "Leitura de " + T.Num(m.ReadBandwidthMbPerSec, 0) + " MB/s e escrita de " +
                T.Num(m.WriteBandwidthMbPerSec, 0) + " MB/s. Serve como referencia para comparar esta mesma maquina em atendimentos futuros" +
                (theoretical.HasValue ? " e para conferir contra o pico teorico do conjunto instalado." : "."),
                Confidence.Build().Authoritative().SingleVolatileSample().Value);
        }

        // Pico teorico = frequencia efetiva x 8 bytes x numero de canais.
        private static double? TheoreticalBandwidthMbPerSec(Inventory inv)
        {
            if (inv.Memory == null || inv.Memory.Modules == null || inv.Memory.Modules.Count == 0) return null;

            int? speed = null;
            foreach (MemoryModule module in inv.Memory.Modules)
            {
                if (!module.SpeedMhz.HasValue) continue;
                if (!speed.HasValue || module.SpeedMhz.Value < speed.Value) speed = module.SpeedMhz;
            }
            if (!speed.HasValue || speed.Value <= 0) return null;

            int channels = 1;
            string config = inv.Memory.ChannelConfiguration;
            if (config != null)
            {
                if (config.IndexOf("Quad", StringComparison.OrdinalIgnoreCase) >= 0) channels = 4;
                else if (config.IndexOf("Dual", StringComparison.OrdinalIgnoreCase) >= 0) channels = 2;
            }

            return Math.Round(speed.Value * 8.0 * channels, 0);
        }

        private static TestResult MemoryLatency(StressResults s)
        {
            TestResult r = T.Make("STR-010", "Latencia de acesso a memoria", "Carga",
                "Tempo medio de um acesso aleatorio que o cache nao consegue prever.");
            r.Requires = Requirement.StressConsent;

            MemoryStressResult m = s.Memory;
            if (m == null || !m.RandomAccessLatencyNs.HasValue)
                return T.NotTested(r, "A medicao de latencia nao pode ser executada nesta maquina.");

            double ns = m.RandomAccessLatencyNs.Value;
            T.Ev(r, "Carga", "latencia de acesso aleatorio", T.Num(ns, 1) + " ns");
            T.Ev(r, "Metodo", "como foi medido", "percurso em ciclo unico sobre bloco maior que o cache, sem padrao previsivel");

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (ns > 200)
                return T.Warn(r, Severity.Low,
                    "Latencia de " + T.Num(ns, 1) + " ns por acesso aleatorio, bem acima do usual (70 a 130 ns em DDR4/DDR5 saudavel).",
                    "Pode indicar memoria operando abaixo da frequencia nominal, configuracao de canal unico, ou o sistema recorrendo ao arquivo de " +
                    "paginacao por falta de RAM livre. Conferir a frequencia efetiva na BIOS e a distribuicao dos pentes nos slots.",
                    confidence);

            return T.Info(r, "Latencia de " + T.Num(ns, 1) +
                " ns por acesso aleatorio a memoria principal.", confidence);
        }

        // ---------------- disco ----------------

        private static TestResult DiskSpeed(DiskBenchmark b)
        {
            if (b.DriveLetter == null) return null;

            TestResult r = T.Make("STR-003-" + b.DriveLetter.Replace(":", ""),
                "Velocidade de escrita em " + b.DriveLetter, "Carga",
                "Escrita real de arquivo, avaliada contra o limiar do tipo de disco correspondente.");
            r.Requires = Requirement.StressConsent;

            if (!b.WriteMbPerSec.HasValue)
                return T.NotTested(r, T.Name(b.Note, "Benchmark nao executado neste volume."));

            double write = b.WriteMbPerSec.Value;
            T.Ev(r, "Carga", "escrita medida", T.Num(write, 1) + " MB/s");
            if (b.ReadMbPerSec.HasValue) T.Ev(r, "Carga", "leitura medida", T.Num(b.ReadMbPerSec, 1) + " MB/s");
            if (b.SustainedWriteMbPerSec.HasValue)
                T.Ev(r, "Carga", "escrita no ultimo quarto do arquivo", T.Num(b.SustainedWriteMbPerSec, 1) + " MB/s");
            if (b.WriteDropPercent.HasValue)
                T.Ev(r, "Analise", "queda da escrita do inicio ao fim", T.Num(b.WriteDropPercent, 1) + "%");
            T.Ev(r, "Analise", "tipo do disco fisico deste volume", T.Name(b.MediaType, "nao determinado"));
            if (b.IntegrityChecked.HasValue && b.IntegrityChecked.Value)
                T.Ev(r, "Carga", "blocos com divergencia na releitura", b.IntegrityErrors.ToString(CultureInfo.InvariantCulture));
            if (b.TempBeforeC.HasValue && b.TempAfterC.HasValue)
                T.Ev(r, "Sensor", "temperatura antes/depois", T.Num(b.TempBeforeC, 1) + " C / " + T.Num(b.TempAfterC, 1) + " C");

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            // Dado que volta diferente do que foi gravado supera qualquer
            // consideracao de velocidade.
            if (b.IntegrityChecked.HasValue && b.IntegrityChecked.Value && b.IntegrityErrors > 0)
                return T.Critical(r,
                    "A releitura de " + b.DriveLetter + " devolveu " + b.IntegrityErrors.ToString(CultureInfo.InvariantCulture) +
                    " bloco(s) diferentes do que foi gravado.",
                    "Corrupcao de dados na gravacao. Fazer backup imediato do que estiver neste volume. Conferir cabo SATA e alimentacao, ler os " +
                    "atributos SMART do disco e considerar substituicao. Este achado tem prioridade sobre qualquer medida de velocidade.",
                    // Mesmo raciocinio de MemoryIntegrity acima - escrever e
                    // reler o MESMO arquivo e uma unica fonte (o benchmark
                    // de disco), nao duas fontes independentes concordando.
                    Confidence.Build().Authoritative().Value);

            string cliff = "";
            if (b.WriteDropPercent.HasValue && b.WriteDropPercent.Value >= 50 && b.MediaType == "SSD")
                cliff = " A escrita caiu " + T.Num(b.WriteDropPercent, 1) +
                        "% do inicio ao fim do arquivo, comportamento tipico de SSD com cache SLC: rapido nos primeiros gigabytes, lento depois.";

            if (b.MediaType == null)
                return T.Info(r, "Escrita de " + T.Num(write, 1) +
                    " MB/s. O tipo do disco fisico deste volume nao foi determinado, entao nao ha limiar aplicavel para julgar o valor." + cliff,
                    Confidence.Build().SingleVolatileSample().Value);

            if (b.MediaType == "SSD")
            {
                if (write < 80)
                    return T.Warn(r, Severity.Medium,
                        "SSD escrevendo a apenas " + T.Num(write, 1) + " MB/s." + cliff,
                        "Muito abaixo do esperado para SSD. Verificar se o TRIM esta ativo, se o disco esta quase cheio (SSD perde desempenho acima de 90% de ocupacao) e se ha throttling termico.",
                        confidence);

                return T.Pass(r, "SSD escrevendo a " + T.Num(write, 1) + " MB/s." + cliff, confidence);
            }

            if (b.MediaType == "HDD")
            {
                if (write < 25)
                    return T.Warn(r, Severity.Medium,
                        "Disco mecanico escrevendo a apenas " + T.Num(write, 1) + " MB/s.",
                        "Abaixo do esperado ate para HDD. Pode indicar fragmentacao severa, setores em realocacao ou cabo com mau contato.",
                        confidence);

                return T.Pass(r, "Disco mecanico escrevendo a " + T.Num(write, 1) + " MB/s, dentro do esperado para HDD.", confidence);
            }

            return T.Info(r, "Escrita de " + T.Num(write, 1) + " MB/s em disco do tipo " + b.MediaType + "." + cliff, confidence);
        }

        // Para a sensacao de "computador lento" o acesso aleatorio de 4 KB
        // pesa muito mais que a velocidade sequencial: e o padrao de quem
        // abre programa e inicia o Windows.
        private static TestResult DiskRandomIo(DiskBenchmark b)
        {
            if (b.DriveLetter == null) return null;
            if (!b.Random4kReadIops.HasValue) return null;

            TestResult r = T.Make("STR-015-" + b.DriveLetter.Replace(":", ""),
                "Acesso aleatorio de 4 KB em " + b.DriveLetter, "Carga",
                "Operacoes por segundo em blocos pequenos e posicoes aleatorias - o padrao que determina a fluidez do sistema.");
            r.Requires = Requirement.StressConsent;

            double read = b.Random4kReadIops.Value;
            T.Ev(r, "Carga", "leitura aleatoria 4 KB", T.Num(read, 0) + " IOPS");
            if (b.Random4kWriteIops.HasValue) T.Ev(r, "Carga", "escrita aleatoria 4 KB", T.Num(b.Random4kWriteIops, 0) + " IOPS");
            T.Ev(r, "Analise", "tipo do disco fisico deste volume", T.Name(b.MediaType, "nao determinado"));

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (b.MediaType == "SSD")
            {
                if (read < 1500)
                    return T.Warn(r, Severity.Medium,
                        "SSD entregando apenas " + T.Num(read, 0) + " IOPS em leitura aleatoria de 4 KB.",
                        "Muito baixo para SSD - um disco saudavel entrega dezenas de milhares. Verificar TRIM, ocupacao acima de 90%, modo do controlador " +
                        "(AHCI x IDE na BIOS) e saude SMART. E a causa mais provavel de o cliente reclamar de lentidao mesmo com SSD.",
                        confidence);

                return T.Pass(r, "SSD entregando " + T.Num(read, 0) + " IOPS em leitura aleatoria de 4 KB.", confidence);
            }

            if (b.MediaType == "HDD")
            {
                if (read < 50)
                    return T.Warn(r, Severity.Medium,
                        "Disco mecanico entregando apenas " + T.Num(read, 0) + " IOPS em leitura aleatoria de 4 KB.",
                        "Baixo mesmo para HD. Conferir setores realocados no SMART e ruido de cabecote. Trocar por SSD resolve a lentidao percebida.",
                        confidence);

                return T.Info(r, "Disco mecanico entregando " + T.Num(read, 0) +
                    " IOPS em leitura aleatoria de 4 KB - normal para a tecnologia, e a razao pela qual o sistema parece lento comparado a um SSD.",
                    confidence);
            }

            return T.Info(r, T.Num(read, 0) + " IOPS em leitura aleatoria de 4 KB.", confidence);
        }
    }
}
