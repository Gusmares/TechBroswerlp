using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Analysis
{
    // Objeto completo de saida. E ele que vira report.json e alimenta o HTML.
    public sealed class DiagnosticReport
    {
        public DiagnosticReport()
        {
            Tests = new List<TestResult>();
            Correlations = new List<Correlation>();
            ComponentHealth = new List<ComponentHealth>();
        }

        public ReportMetadata Metadata { get; set; }
        public ExecutiveSummary Summary { get; set; }
        public List<ComponentHealth> ComponentHealth { get; set; }
        public List<Correlation> Correlations { get; set; }
        public List<TestResult> Tests { get; set; }
        public List<Inconsistency> Inconsistencies { get; set; }
        public List<ModuleOutcome> Modules { get; set; }
        public Inventory Inventory { get; set; }

        // Ver comentario em CompatibilityReference.cs sobre por que isto NAO
        // mora dentro de Inventory (dado medido) apesar de derivar de
        // Inventory.Chipset.
        public CompatibilityReference CompatibilityReference { get; set; }
    }

    // Metadados de reprodutibilidade (item 60): permitem comparar duas
    // execucoes na mesma maquina e saber exatamente o que foi ou nao medido.
    public sealed class ReportMetadata
    {
        public string ScanId { get; set; }
        public DateTime StartedAt { get; set; }
        public double DurationSeconds { get; set; }
        public string ToolVersion { get; set; }
        public int SchemaVersion { get; set; }
        public string RulesVersion { get; set; }
        public string OsVersion { get; set; }
        public string ProcessArchitecture { get; set; }
        public bool ElevatedPrivileges { get; set; }
        public string PrivilegeLevel { get; set; }
        public string SupportLevel { get; set; }
        public string SupportReason { get; set; }
        public string Mode { get; set; }
        public bool PrivacySafe { get; set; }
        public bool StressExecuted { get; set; }
        public int ModulesExecuted { get; set; }
        public int ModulesFailed { get; set; }
        public int TestsExecuted { get; set; }
        public int TestsSkipped { get; set; }
    }

    public sealed class ExecutiveSummary
    {
        public int HealthScore { get; set; }
        public string Status { get; set; }
        public string Headline { get; set; }
        public int CriticalIssues { get; set; }
        public int HighIssues { get; set; }
        public int MediumIssues { get; set; }
        public int LowIssues { get; set; }
        public int TestsPassed { get; set; }
        public int TestsWithFindings { get; set; }
        public int TestsNotExecuted { get; set; }

        // NotApplicable (ex.: bateria em equipamento de mesa, disco Ethernet
        // sem link) nao e "teste que nao pode ser executado" - e um teste
        // que nao FAZ SENTIDO neste equipamento, por isso fica de fora do
        // denominador de CoveragePercent, na mesma formula que
        // BuildComponentHealth ja usa.
        public int TestsNotApplicable { get; set; }

        public int InconsistenciesFound { get; set; }
        public double CoveragePercent { get; set; }

        // Uma area inteira que nunca rodou (modulo com TIMEOUT, ou suite que
        // lancou excecao) pode representar poucos testes perto do total da
        // maquina - a cobertura agregada nao cai o suficiente para acionar o
        // gate de MinCoverageForVerdict, o que deixaria o laudo SAUDAVEL com,
        // por exemplo, o disco inteiro nunca examinado. Esta lista torna
        // essas areas visiveis independentemente da matematica da cobertura
        // agregada.
        public List<string> DegradedAreas { get; set; }
    }

    public static class DiagnosticEngine
    {
        public static DiagnosticReport Analyze(ScanContext ctx, Inventory inv, List<IDiagnosticTest> suites)
        {
            // Um modulo que estourou o timeout continua rodando em thread de
            // fundo (ModuleRunner nao tem como cancela-la com seguranca) e
            // pode estar, neste exato instante, dando .Add() nas listas de
            // inv enquanto as suites e o Correlate abaixo fazem foreach
            // nelas - um cenario real de modificacao concorrente que pode
            // derrubar o processo. Tirar uma copia das listas AQUI, antes de
            // qualquer leitura, garante que a analise inteira trabalha sobre
            // uma fotografia estavel: List<T>.CopyTo (usado pelo construtor
            // de copia) le _items/_size uma vez e nao participa do contador
            // de versao que o foreach verifica, entao nao lanca mesmo que o
            // coletor abandonado continue escrevendo.
            inv = inv.SnapshotForAnalysis();

            DiagnosticReport report = new DiagnosticReport();
            List<string> failedSuites = new List<string>();

            foreach (IDiagnosticTest suite in suites)
            {
                string suiteName = suite.GetType().Name;
                Stopwatch sw = Stopwatch.StartNew();

                IEnumerable<TestResult> results = Try.Get<IEnumerable<TestResult>>(ctx, suiteName, "execucao da suite", delegate
                {
                    return suite.Run(ctx, inv);
                });

                sw.Stop();

                if (results == null)
                {
                    // Uma suite que falha nao pode desaparecer silenciosamente:
                    // vira um resultado NotTested explicito. Um NotTested SO
                    // nao representa proporcionalmente quantos testes essa
                    // suite normalmente produziria - isso poderia inflar a
                    // cobertura agregada, entao o nome tambem entra em
                    // failedSuites, que BuildSummary usa para forcar um
                    // veredito honesto independente da matematica de %.
                    TestResult failed = T.Make(suiteName.ToUpperInvariant() + "-FAIL", "Suite " + suiteName, suite.Category,
                        "Conjunto de testes que nao pode ser executado.");
                    report.Tests.Add(T.NotTested(failed, "A suite de testes lancou excecao durante a execucao - ver errors.log."));
                    failedSuites.Add(suite.Category + " (suite " + suiteName + " lancou excecao)");
                    continue;
                }

                // A suite inteira roda dentro de UM Stopwatch. Sem medir cada
                // teste individualmente (o que exigiria reescrever toda suite
                // para produzir resultados um a um), o unico numero honesto
                // por TestResult e o da suite quando ela devolve UM unico
                // resultado; com mais de um, atribuir o mesmo total a cada um
                // fingiria uma precisao que nao existe - por isso fica 0
                // (mesmo sentinela de "nao medido" que Log.cs ja usa para
                // DurationMs).
                int resultCount = 0;
                foreach (TestResult r in results) if (r != null) resultCount++;
                long perTestDurationMs = resultCount == 1 ? sw.ElapsedMilliseconds : 0;

                foreach (TestResult r in results)
                {
                    if (r == null) continue;
                    r.DurationMs = perTestDurationMs;
                    report.Tests.Add(r);
                    ctx.Log.Write(LogLevel.Debug, LogChannel.Diagnostic, r.Id,
                        r.Status + "/" + r.Severity + " conf=" + r.Confidence + " :: " + r.Result);
                }
            }

            report.Inconsistencies = ctx.Inconsistencies;
            report.Modules = ctx.ModuleOutcomes;
            report.Correlations = Correlate(ctx, inv, report.Tests);
            report.ComponentHealth = BuildComponentHealth(report.Tests);
            report.Summary = BuildSummary(ctx, report, failedSuites);
            report.Metadata = BuildMetadata(ctx, inv, report);
            report.Inventory = inv;
            report.CompatibilityReference = CompatibilityReference.Build(inv);

            return report;
        }

        // ---------- pontuacao ----------

        // Penalidade deterministica por resultado. Documentada aqui e coberta
        // por teste unitario: o score nunca e um numero arbitrario.
        public static int Penalty(TestResult r)
        {
            if (r == null) return 0;

            switch (r.Status)
            {
                case TestStatus.Critical:
                    return 40;

                case TestStatus.Error:
                    if (r.Severity == Severity.Critical) return 30;
                    if (r.Severity == Severity.High) return 22;
                    if (r.Severity == Severity.Medium) return 12;
                    return 6;

                case TestStatus.Warning:
                    if (r.Severity == Severity.High) return 12;
                    if (r.Severity == Severity.Medium) return 7;
                    return 3;

                default:
                    // Info, Pass, NotTested, NotApplicable, RequiresAdmin e
                    // Unknown NAO penalizam. Nao ter conseguido medir nao e
                    // defeito do equipamento.
                    return 0;
            }
        }

        public static int ComputeScore(List<TestResult> tests)
        {
            return ComputeScore(tests, null);
        }

        // Penalidade por divergencia entre fontes ainda sem um TestResult
        // proprio que ja a reflita. Documentada e coberta por teste, igual a
        // Penalty(TestResult).
        public static int InconsistencyPenalty(Inconsistency inc)
        {
            if (inc == null) return 0;
            switch (inc.Severity)
            {
                case Severity.Critical: return 15;
                case Severity.High: return 8;
                case Severity.Medium: return 4;
                default: return 0;
            }
        }

        // ARQUITETURA.md:232-233 e o comentario em Model.cs:150-151 documentam
        // que uma divergencia entre fontes "derruba a confianca do fato" e
        // "vira INCONSISTENCY no relatorio". Para honrar esse contrato, cada
        // Inconsistency com Severity >= Medium desconta pontos aqui, na
        // mesma escala de Penalty.
        public static int ComputeScore(List<TestResult> tests, List<Inconsistency> inconsistencies)
        {
            int score = 100;
            foreach (TestResult r in tests) score -= Penalty(r);
            if (inconsistencies != null)
                foreach (Inconsistency inc in inconsistencies) score -= InconsistencyPenalty(inc);
            if (score < 0) score = 0;
            if (score > 100) score = 100;
            return score;
        }

        // Limiar de cobertura abaixo do qual o score deixa de significar
        // qualquer coisa. Documentado aqui porque e testado e versionado
        // junto com RULES_VERSION.
        public const double MinCoverageForVerdict = 60.0;

        // O score sozinho nao basta: NotTested/RequiresAdmin/NotApplicable/
        // Unknown nunca descontam pontos (por design correto: ausencia de
        // dado nao e defeito do equipamento), entao uma maquina pouco testada
        // pode manter o score em 100 sem ter achado nada. Por isso o
        // veredito tambem depende da cobertura, e nao so do score. Uma
        // severidade Critical ainda vence o gate: um achado real e critico
        // nao pode ficar escondido atras de "inconclusivo" so porque o
        // RESTO da maquina nao foi medido.
        public static string ScoreStatus(int score, bool hasCritical, double coveragePercent)
        {
            return ScoreStatus(score, hasCritical, false, coveragePercent);
        }

        // Um score agregado favoravel pode esconder um achado individual de
        // severidade Alta (Warning/High so desconta 12 pontos, o que pode
        // manter o score acima do limiar de 85). hasHigh forca no minimo
        // ATENCAO, no mesmo espirito de hasCritical - um achado de verdade
        // nao pode ficar escondido atras de um score agregado favoravel.
        // Checado ANTES do gate de cobertura (mesma prioridade de
        // hasCritical): um achado concreto vale mais que a incerteza sobre
        // o resto da maquina. score < 50 ainda vence hasHigh, para nao
        // rebaixar CRITICO genuino (varios achados High+Critical somados)
        // para ATENCAO so porque nenhum resultado individual tinha
        // TestStatus.Critical.
        public static string ScoreStatus(int score, bool hasCritical, bool hasHigh, double coveragePercent)
        {
            if (hasCritical) return "CRITICO";
            if (score < 50) return "CRITICO";
            if (hasHigh) return "ATENCAO";
            if (coveragePercent < MinCoverageForVerdict) return "INCONCLUSIVO";
            if (score < 85) return "ATENCAO";
            return "SAUDAVEL";
        }

        private static List<ComponentHealth> BuildComponentHealth(List<TestResult> tests)
        {
            Dictionary<string, ComponentHealth> byCategory = new Dictionary<string, ComponentHealth>(StringComparer.Ordinal);
            List<string> order = new List<string>();

            foreach (TestResult r in tests)
            {
                string cat = T.Name(r.Category, "Outros");
                ComponentHealth c;
                if (!byCategory.TryGetValue(cat, out c))
                {
                    c = new ComponentHealth();
                    c.Component = cat;
                    c.Score = 100;
                    c.Status = TestStatus.Pass;
                    byCategory[cat] = c;
                    order.Add(cat);
                }

                c.Score -= Penalty(r);

                if (r.Status == TestStatus.Pass || r.Status == TestStatus.Info) c.TestsPassed++;
                else if (r.IsProblem) c.TestsProblem++;
                else if (r.Status == TestStatus.NotApplicable) c.TestsNotApplicable++;
                else c.TestsNotExecuted++;

                // NotApplicable nao representa nem aprovacao nem problema,
                // entao fica de fora do ranking de agregacao do badge da
                // categoria - caso contrario um unico teste NotApplicable
                // (ex.: NET-003 sem link Ethernet conectado) poderia
                // sobrescrever o badge de uma categoria inteira aprovada
                // (Pass, Pass, ...), escondendo os achados reais dos demais
                // testes. O caso de a categoria inteira ser NotApplicable ja
                // e tratado a parte por EntirelyNotApplicable.
                if (r.Status != TestStatus.NotApplicable && StatusRank(r.Status) > StatusRank(c.Status))
                    c.Status = r.Status;
            }

            List<ComponentHealth> list = new List<ComponentHealth>();
            foreach (string cat in order)
            {
                ComponentHealth c = byCategory[cat];
                if (c.Score < 0) c.Score = 0;

                int measured = c.TestsPassed + c.TestsProblem;
                int applicable = measured + c.TestsNotExecuted;

                c.EntirelyNotApplicable = applicable == 0 && c.TestsNotApplicable > 0;
                c.CoveragePercent = applicable == 0 ? 0 : (int)Math.Round((double)measured / applicable * 100.0);

                if (c.EntirelyNotApplicable)
                    c.Summary = "Nao se aplica a este equipamento.";
                else if (measured == 0)
                    c.Summary = "Nada pode ser verificado nesta area - o resultado nao diz nada sobre a saude dela.";
                else if (c.TestsProblem == 0)
                    c.Summary = c.TestsPassed + " verificacao(oes) sem achados.";
                else
                    c.Summary = c.TestsProblem + " achado(s) em " + measured + " verificacao(oes).";

                if (c.TestsNotExecuted > 0 && measured > 0)
                    c.Summary += " " + c.TestsNotExecuted + " nao executada(s) - cobertura de " + c.CoveragePercent + "%.";

                list.Add(c);
            }

            return list;
        }

        private static int StatusRank(TestStatus s)
        {
            switch (s)
            {
                case TestStatus.Pass: return 0;
                case TestStatus.NotApplicable: return 1;
                case TestStatus.Info: return 2;
                case TestStatus.NotTested: return 3;
                case TestStatus.RequiresAdmin: return 3;
                case TestStatus.Unknown: return 3;
                case TestStatus.Warning: return 4;
                case TestStatus.Error: return 5;
                case TestStatus.Critical: return 6;
                default: return 0;
            }
        }

        private static ExecutiveSummary BuildSummary(ScanContext ctx, DiagnosticReport report, List<string> failedSuites)
        {
            ExecutiveSummary s = new ExecutiveSummary();
            bool hasCritical = false;

            foreach (TestResult r in report.Tests)
            {
                if (r.Status == TestStatus.Critical) { hasCritical = true; s.CriticalIssues++; }
                else if (r.IsProblem)
                {
                    if (r.Severity == Severity.High) s.HighIssues++;
                    else if (r.Severity == Severity.Medium) s.MediumIssues++;
                    else s.LowIssues++;
                }

                if (r.Status == TestStatus.Pass || r.Status == TestStatus.Info) s.TestsPassed++;
                else if (r.IsProblem) s.TestsWithFindings++;
                else if (r.Status == TestStatus.NotApplicable) s.TestsNotApplicable++;
                else s.TestsNotExecuted++;
            }

            s.HealthScore = ComputeScore(report.Tests, report.Inconsistencies);
            s.InconsistenciesFound = report.Inconsistencies == null ? 0 : report.Inconsistencies.Count;

            // Excluir NotApplicable do denominador - a mesma formula que
            // BuildComponentHealth ja usa (medido / (medido + naoExecutado)) -
            // tambem no sumario executivo global, para as duas paginas do
            // laudo (cabecalho e HTML por categoria) nunca divergirem sobre
            // quantos testes "realmente contam".
            int applicable = report.Tests.Count - s.TestsNotApplicable;
            s.CoveragePercent = applicable <= 0 ? 0 : Math.Round((double)(applicable - s.TestsNotExecuted) / applicable * 100.0, 1);

            // Um modulo inteiro com TIMEOUT (ex.: Storage) ou uma suite que
            // lancou excecao pode pesar pouco na cobertura AGREGADA (poucos
            // testes NotTested contra dezenas de outros que passaram em
            // outras areas), o que poderia deixar o gate de
            // MinCoverageForVerdict sem disparar e o laudo SAUDAVEL/100 com
            // uma area inteira nunca examinada. Aqui a area entra
            // visivelmente no laudo independente da matematica.
            s.DegradedAreas = new List<string>();
            if (failedSuites != null) s.DegradedAreas.AddRange(failedSuites);
            foreach (ModuleOutcome o in ctx.ModuleOutcomes)
                if (o.TimedOut) s.DegradedAreas.Add("Modulo " + o.Module + " (timeout)");

            bool hasHigh = s.HighIssues > 0;

            // A cobertura precisa estar calculada ANTES do status - e o gate
            // que decide entre um veredito de verdade e INCONCLUSIVO.
            s.Status = ScoreStatus(s.HealthScore, hasCritical, hasHigh, s.CoveragePercent);
            if (s.DegradedAreas.Count > 0 && s.Status == "SAUDAVEL") s.Status = "ATENCAO";
            s.Headline = BuildHeadline(s);
            return s;
        }

        public static string BuildHeadline(ExecutiveSummary s)
        {
            // A nota de area degradada entra em TODO headline, nao so no
            // caso "limpo" - mesmo um laudo com achado critico precisa
            // deixar claro que outra area inteira nao pode ser avaliada.
            string degradedNote = "";
            if (s.DegradedAreas != null && s.DegradedAreas.Count > 0)
                degradedNote = " ATENCAO: " + string.Join(", ", s.DegradedAreas.ToArray()) +
                    " nao puderam ser executados (timeout ou falha) - os resultados dessas areas nao entraram neste laudo.";

            // Achado critico ou de alta severidade e acionavel por si so, e
            // vem na frente de qualquer outra consideracao.
            if (s.CriticalIssues > 0)
                return s.CriticalIssues + " problema(s) critico(s) exigem acao imediata." + degradedNote;
            if (s.HighIssues > 0)
                return s.HighIssues + " problema(s) de alta severidade encontrados." + degradedNote;

            // Usa o MESMO limiar percentual que rebaixa o Status para
            // INCONCLUSIVO em ScoreStatus, entao os dois nunca divergem
            // sobre quando a cobertura e baixa demais para um veredito
            // confiavel.
            if (s.CoveragePercent < MinCoverageForVerdict)
            {
                string extra = (s.MediumIssues + s.LowIssues) > 0
                    ? " Foram encontrados " + (s.MediumIssues + s.LowIssues) + " ponto(s) de atencao no pouco que pode ser medido."
                    : "";
                return "Cobertura insuficiente (" + s.CoveragePercent.ToString("F0", CultureInfo.InvariantCulture) +
                    "% dos testes puderam rodar): o resultado nao permite concluir sobre a saude da maquina." + extra + degradedNote;
            }

            // Cobertura razoavel mas nao total: a ressalva nao pode ficar
            // escondida num paragrafo separado depois dos contadores (o
            // mesmo defeito do gate acima, so que mais brando) - entra como
            // prefixo do proprio headline, que e a primeira coisa lida.
            string coveragePrefix = s.CoveragePercent < 100.0
                ? "Cobertura de " + s.CoveragePercent.ToString("F0", CultureInfo.InvariantCulture) + "%. "
                : "";

            if (s.MediumIssues > 0)
                return coveragePrefix + s.MediumIssues + " ponto(s) de atencao que valem correcao." + degradedNote;
            if (s.LowIssues > 0)
                return coveragePrefix + "Apenas recomendacoes de baixa severidade." + degradedNote;

            return coveragePrefix + "Nenhum problema identificado nas areas verificadas." + degradedNote;
        }

        private static ReportMetadata BuildMetadata(ScanContext ctx, Inventory inv, DiagnosticReport report)
        {
            ReportMetadata m = new ReportMetadata();
            m.ScanId = ctx.ScanId;
            m.StartedAt = ctx.StartedAt;
            m.DurationSeconds = Math.Round((DateTime.Now - ctx.StartedAt).TotalSeconds, 1);
            m.ToolVersion = ScanContext.ToolVersion;
            m.SchemaVersion = ScanContext.SchemaVersion;
            m.RulesVersion = ScanContext.RulesVersion;
            m.OsVersion = T.Name(inv.Os.Caption, "desconhecido") + " build " + T.Num(inv.Os.BuildNumber);
            m.ProcessArchitecture = ctx.ProcessArchitecture;
            m.ElevatedPrivileges = ctx.IsElevated;
            m.PrivilegeLevel = ctx.IsElevated ? "Administrador" : "Usuario padrao";
            m.SupportLevel = ctx.Support.ToString();
            m.SupportReason = ctx.SupportReason;
            m.Mode = ctx.Options.Mode.ToString();
            m.PrivacySafe = ctx.Options.PrivacySafe;
            m.StressExecuted = inv.Stress != null && inv.Stress.Executed;

            int failed = 0;
            foreach (ModuleOutcome o in ctx.ModuleOutcomes) if (!o.Succeeded) failed++;
            m.ModulesExecuted = ctx.ModuleOutcomes.Count;
            m.ModulesFailed = failed;

            m.TestsExecuted = report.Summary.TestsPassed + report.Summary.TestsWithFindings;
            m.TestsSkipped = report.Summary.TestsNotExecuted;
            return m;
        }

        // ---------- correlacao (item 56) ----------
        //
        // Uma correlacao so e emitida quando TODAS as condicoes tem evidencia.
        // Nunca ha causa provavel sem lastro, e a confianca e sempre a do elo
        // mais fraco entre as evidencias que a sustentam.
        public static List<Correlation> Correlate(ScanContext ctx, Inventory inv, List<TestResult> tests)
        {
            List<Correlation> list = new List<Correlation>();

            // Indexar os testes por Id aqui permite que cada correlacao pegue
            // a confianca REAL dos testes que ela cita em RelatedTestIds,
            // honrando a regra documentada logo acima ("a confianca e sempre
            // a do elo mais fraco entre as evidencias").
            Dictionary<string, TestResult> byId = new Dictionary<string, TestResult>(StringComparer.Ordinal);
            if (tests != null)
                foreach (TestResult r in tests)
                    if (r != null && r.Id != null && !byId.ContainsKey(r.Id)) byId[r.Id] = r;

            ThermalOrPower(inv, list, byId);
            StorageCausingCrashes(inv, list, byId);
            HardwareErrorsWithCrashes(inv, list, byId);
            SlowMachineExplanation(inv, list, byId);
            UpdateChainBroken(ctx, inv, list, byId);

            return list;
        }

        // Confianca real dos testes relacionados (elo mais fraco entre eles,
        // via Confidence.Combine), caindo para 'fallback' so quando nenhum
        // dos RelatedTestIds tem um TestResult correspondente (teste nao
        // executado, ou suite que nao rodou nesta maquina).
        private static int ConfidenceFromRelated(Dictionary<string, TestResult> byId, List<string> relatedIds, int fallback)
        {
            List<int> found = new List<int>();
            if (relatedIds != null)
                foreach (string id in relatedIds)
                {
                    TestResult r;
                    if (byId.TryGetValue(id, out r)) found.Add(r.Confidence);
                }
            return found.Count == 0 ? fallback : Confidence.Combine(found.ToArray());
        }

        // StorageCausingCrashes e HardwareErrorsWithCrashes nao podem emitir
        // DUAS causas Critical mutuamente exclusivas para o MESMO conjunto
        // de bugchecks (uma culpando o disco, outra culpando CPU/RAM/PCIe).
        // A regra NAO e exigir que todo bugcheck tenha um StopCode conhecido
        // da categoria (HardwareErrorsWithCrashes ja usa WHEA como evidencia
        // primaria - um bugcheck concorrente de codigo desconhecido ainda e
        // corroboracao legitima de instabilidade, com ou sem codigo
        // extraido). A regra e so impedir que um bugcheck com StopCode
        // CONHECIDO da OUTRA categoria seja reivindicado: 0x7A/0xF4/0x50
        // (armazenamento) e 0x124/0x101 (hardware/WHEA) sao mutuamente
        // exclusivos por definicao, entao um bugcheck 0x124 nunca pode virar
        // evidencia de que o DISCO causou o crash, e vice-versa. Codigo
        // desconhecido ou nao extraido conta para as duas (nao foi excluido
        // de nenhuma).
        private static int CountBugChecksByCategory(Inventory inv, bool storage)
        {
            string[] storageCodes = { "0x7a", "0xf4", "0x50" };
            string[] hardwareCodes = { "0x124", "0x101" };
            string[] excludeIfKnownAs = storage ? hardwareCodes : storageCodes;

            int count = 0;
            foreach (BugCheckEvent bc in inv.Events.BugChecks)
            {
                string normalized = bc.StopCode == null ? null : NormalizeStopCode(bc.StopCode);
                bool excluded = false;
                if (normalized != null)
                    foreach (string c in excludeIfKnownAs)
                        if (normalized == c) { excluded = true; break; }
                if (!excluded) count++;
            }
            return count;
        }

        // "0x0000007a" e "0x7a" precisam comparar iguais - remove zeros a
        // esquerda depois do prefixo 0x.
        private static string NormalizeStopCode(string stopCode)
        {
            if (stopCode == null || stopCode.Length < 2) return stopCode;
            string digits = stopCode.Substring(2).TrimStart('0');
            if (digits.Length == 0) digits = "0";
            return "0x" + digits;
        }

        private static void ThermalOrPower(Inventory inv, List<Correlation> list, Dictionary<string, TestResult> byId)
        {
            int shutdowns = inv.Events.UnexpectedShutdowns.HasValue ? inv.Events.UnexpectedShutdowns.Value : 0;
            if (shutdowns < 2) return;

            Correlation c = new Correlation();
            c.Symptom = "Desligamentos inesperados recorrentes (" + shutdowns + " nos ultimos " + inv.Events.WindowDays + " dias)";
            c.RelatedTestIds.Add("EVT-002");
            c.Evidence.Add(Evidence.Of("EventLog", "Kernel-Power 41 / EventLog 6008", shutdowns));

            bool hot = inv.Cpu.TemperatureC.HasValue && inv.Cpu.TemperatureC.Value >= 85;
            int whea = inv.Events.WheaUncorrectedCount.HasValue ? inv.Events.WheaUncorrectedCount.Value : 0;

            if (hot)
            {
                c.Evidence.Add(Evidence.Of("Sensor", "temperatura de CPU", T.Num(inv.Cpu.TemperatureC, 1) + " C"));
                c.RelatedTestIds.Add("CPU-002");
                c.LikelyCause = "Protecao termica: a CPU esta operando quente e o desligamento abrupto e o comportamento esperado quando o limite e atingido.";
                c.Recommendation = "Limpar dissipador e ventoinhas, reaplicar pasta termica e conferir o fluxo de ar do gabinete. Repetir o diagnostico com o teste de estresse depois da limpeza para confirmar.";
                c.Severity = Severity.High;
                c.Confidence = ConfidenceFromRelated(byId, c.RelatedTestIds, Confidence.Combine(85, 80));
            }
            else if (whea > 0)
            {
                c.Evidence.Add(Evidence.Of("EventLog", "WHEA nao corrigidos", whea));
                c.RelatedTestIds.Add("MEM-005");
                c.LikelyCause = "Falha de hardware: ha erros nao corrigidos registrados pelo WHEA junto com os desligamentos.";
                c.Recommendation = "Identificar o componente acusado na mensagem do evento WHEA e testar memoria e alimentacao. WHEA cobre CPU, RAM e PCIe.";
                c.Severity = Severity.High;
                c.Confidence = ConfidenceFromRelated(byId, c.RelatedTestIds, Confidence.Combine(80, 75));
            }
            else
            {
                // Ausencia de dado (sensor indisponivel, sem elevacao) nao
                // pode virar uma afirmacao positiva de causa: medir versus
                // nao medir TemperatureC/WheaUncorrectedCount produz texto e
                // confianca distintos abaixo.
                bool tempMeasured = inv.Cpu.TemperatureC.HasValue;
                bool wheaMeasured = inv.Events.WheaUncorrectedCount.HasValue;

                if (!tempMeasured || !wheaMeasured)
                {
                    List<string> unmeasured = new List<string>();
                    if (!tempMeasured) unmeasured.Add("a temperatura da CPU");
                    if (!wheaMeasured) unmeasured.Add("os erros WHEA");
                    c.LikelyCause = "Nao foi possivel medir " + string.Join(" nem ", unmeasured.ToArray()) +
                        " para confirmar ou descartar causa termica/de hardware. Entre o que resta, a causa mais comum e alimentacao/energia externa, mas essa hipotese nao pode ser confirmada com o que foi medido.";
                    c.Recommendation = "Repetir o diagnostico com elevacao de Administrador (e com o pendrive de sensores presente, se aplicavel) para medir temperatura e eventos WHEA antes de concluir. Enquanto isso, verificar se ha nobreak e testar a fonte.";
                    c.Severity = Severity.Medium;
                    c.Confidence = ConfidenceFromRelated(byId, c.RelatedTestIds, 40);
                }
                else
                {
                    // Sem evidencia termica nem de hardware, a causa mais
                    // provavel e alimentacao/energia externa - e as duas
                    // fontes FORAM medidas, entao a hipotese remanescente
                    // merece mais confianca que o ramo "nao medido" acima.
                    c.LikelyCause = "Sem evidencia termica nem de erro de hardware no periodo (temperatura e WHEA foram medidos). As causas remanescentes mais comuns sao queda de energia externa e fonte de alimentacao instavel.";
                    c.Recommendation = "Verificar se ha nobreak e testar a fonte. Se os desligamentos ocorrem sob carga, a fonte e a suspeita principal.";
                    c.Severity = Severity.Medium;
                    c.Confidence = ConfidenceFromRelated(byId, c.RelatedTestIds, 55);
                }
            }

            list.Add(c);
        }

        private static void StorageCausingCrashes(Inventory inv, List<Correlation> list, Dictionary<string, TestResult> byId)
        {
            bool diskBad = false;
            string diskName = null;
            // StorageTests numera STO-001 por disco (STO-001-01, STO-001-02,
            // ...) - o ID "STO-001" sem sufixo nunca existe em report.Tests.
            // HtmlReport.cs itera RelatedTestIds para mostrar ao tecnico
            // quais testes sustentam a correlacao, entao o sufixo correto e
            // necessario para essa referencia funcionar.
            string diskTestId = null;

            int diskIndex = 0;
            foreach (DiskInfo d in inv.Disks)
            {
                diskIndex++;
                bool unhealthy = d.HealthStatus != null &&
                    !string.Equals(d.HealthStatus, "Healthy", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(d.HealthStatus, "Unknown", StringComparison.OrdinalIgnoreCase);
                if (unhealthy || d.SmartPredictFailure == true)
                {
                    diskBad = true;
                    diskName = T.Name(d.Model, "disco");
                    diskTestId = "STO-001-" + diskIndex.ToString("D2", CultureInfo.InvariantCulture);
                    break;
                }
            }

            int diskErrors = inv.Events.DiskControllerErrors.HasValue ? inv.Events.DiskControllerErrors.Value : 0;
            if (!diskBad && diskErrors < 5) return;

            Correlation c = new Correlation();
            c.RelatedTestIds.Add("STO-007");

            if (diskBad)
            {
                c.Symptom = "Disco '" + diskName + "' com saude comprometida";
                c.Evidence.Add(Evidence.Of("WMI", "MSFT_PhysicalDisk.HealthStatus", "diferente de Healthy"));
                if (diskTestId != null) c.RelatedTestIds.Add(diskTestId);
            }
            else
            {
                c.Symptom = diskErrors + " erros de disco/controlador no log do sistema";
            }

            if (diskErrors > 0) c.Evidence.Add(Evidence.Of("EventLog", "erros de disco/NTFS/controlador", diskErrors));

            // Usa SO os bugchecks cujo StopCode e tipicamente de
            // armazenamento (0x7A KERNEL_DATA_INPAGE_ERROR, 0xF4
            // CRITICAL_OBJECT_TERMINATION, 0x50 PAGE_FAULT_IN_NONPAGED_AREA)
            // - nao todos os bugchecks da janela. Sem essa distincao, o
            // mesmo conjunto de telas azuis poderia virar evidencia AQUI e
            // em HardwareErrorsWithCrashes ao mesmo tempo, produzindo duas
            // causas Critical contraditorias ("trocar o disco" e "testar
            // CPU/memoria") para o mesmo sintoma.
            int bugchecks = CountBugChecksByCategory(inv, true);
            if (bugchecks > 0)
            {
                c.Evidence.Add(Evidence.Of("EventLog", "telas azuis com codigo de armazenamento no periodo", bugchecks));
                c.RelatedTestIds.Add("EVT-001");
                c.Symptom += ", acompanhado de " + bugchecks + " tela(s) azul(is)";
                c.LikelyCause = "Armazenamento como causa provavel dos travamentos: erro de leitura no volume do sistema derruba o kernel.";
                c.Recommendation = "Backup imediato antes de qualquer teste adicional. Depois do backup, verificar cabo/conector do disco e substituir a unidade.";
                c.Severity = Severity.Critical;
                c.Confidence = ConfidenceFromRelated(byId, c.RelatedTestIds, Confidence.Combine(85, 80, 75));
            }
            else
            {
                c.LikelyCause = "Degradacao do subsistema de armazenamento: disco, cabo de dados ou controlador.";
                c.Recommendation = "Backup preventivo. Em disco SATA, trocar o cabo e a porta antes de condenar a unidade - cabo com mau contato produz exatamente esse padrao de erro.";
                c.Severity = diskBad ? Severity.High : Severity.Medium;
                c.Confidence = ConfidenceFromRelated(byId, c.RelatedTestIds, diskBad ? 80 : 65);
            }

            list.Add(c);
        }

        private static void HardwareErrorsWithCrashes(Inventory inv, List<Correlation> list, Dictionary<string, TestResult> byId)
        {
            int whea = inv.Events.WheaUncorrectedCount.HasValue ? inv.Events.WheaUncorrectedCount.Value : 0;
            // Simetrico a StorageCausingCrashes acima - so bugchecks com
            // StopCode tipico de hardware/WHEA (0x124 WHEA_UNCORRECTABLE_ERROR,
            // 0x101 CLOCK_WATCHDOG_TIMEOUT) contam aqui.
            int bugchecks = CountBugChecksByCategory(inv, false);
            if (whea == 0 || bugchecks == 0) return;

            Correlation c = new Correlation();
            c.Symptom = "Telas azuis (" + bugchecks + ") coincidindo com erros de hardware nao corrigidos (" + whea + ")";
            c.Evidence.Add(Evidence.Of("EventLog", "WHEA-Logger nivel 1-2", whea));
            c.Evidence.Add(Evidence.Of("EventLog", "bugchecks com codigo de hardware/WHEA", bugchecks));
            c.RelatedTestIds.Add("MEM-005");
            c.RelatedTestIds.Add("EVT-001");
            // As duas evidencias acima (WHEA-Logger e o bugcheck) vem do
            // MESMO log de eventos - chama-las de "fontes independentes"
            // seria uma alegacao mais forte do que os dados sustentam.
            // "Independente" fica reservado para quando a evidencia inclui
            // algo fora do EventLog (ex.: arquivo de minidump).
            c.LikelyCause = "Falha de hardware provavel: dois sinais no log de eventos concordam - o hardware reportou erro nao corrigivel (WHEA) e o kernel parou logo em seguida.";
            c.Recommendation = "Ler a mensagem dos eventos WHEA para identificar o componente (CPU, memoria ou PCIe) e testar esse componente especificamente. Rodar mdsched.exe ou MemTest86 se a acusacao for de memoria.";
            c.Severity = Severity.Critical;
            c.Confidence = ConfidenceFromRelated(byId, c.RelatedTestIds, Confidence.Combine(90, 85));
            list.Add(c);
        }

        // Explica lentidao com causas objetivas, em vez de deixar o tecnico
        // adivinhar.
        private static void SlowMachineExplanation(Inventory inv, List<Correlation> list, Dictionary<string, TestResult> byId)
        {
            List<Evidence> reasons = new List<Evidence>();
            List<string> causes = new List<string>();

            foreach (DiskInfo d in inv.Disks)
            {
                if (d.IsBootDisk == true && d.MediaType == "HDD")
                {
                    reasons.Add(Evidence.Of("WMI", "disco de boot MediaType", "HDD"));
                    causes.Add("o Windows esta instalado em disco mecanico (HDD), que e a maior causa isolada de lentidao em maquina moderna");
                    break;
                }
            }

            // StorageTests.FreeSpace numera STO-005 pela LETRA do volume
            // (ex.: "STO-005-C"), nunca "STO-005" sem sufixo - guardar a
            // letra do volume achado aqui para montar o ID real, em vez de
            // um literal que nunca existe em report.Tests.
            string lowSpaceVolumeTestId = null;
            foreach (VolumeInfo v in inv.Volumes)
            {
                if (v.IsBootVolume == true && v.FreePercent.HasValue && v.FreePercent.Value <= 10)
                {
                    reasons.Add(Evidence.Of("WMI", "espaco livre no volume do sistema", T.Num(v.FreePercent, 1) + "%"));
                    causes.Add("o volume do sistema esta com apenas " + T.Num(v.FreePercent, 1) + "% livres");
                    lowSpaceVolumeTestId = "STO-005-" + T.Name(v.DriveLetter, "?").Replace(":", "");
                    break;
                }
            }

            if (inv.Memory.UsagePercent.HasValue && inv.Memory.UsagePercent.Value >= 92)
            {
                reasons.Add(Evidence.Of("Native", "uso de memoria", T.Num(inv.Memory.UsagePercent, 0) + "%"));
                causes.Add("a memoria esta em " + T.Num(inv.Memory.UsagePercent, 0) + "% de uso, forcando paginacao em disco");
            }

            if (causes.Count == 0) return;

            Correlation c = new Correlation();
            c.Symptom = "Fatores objetivos de lentidao presentes nesta maquina";
            c.Evidence.AddRange(reasons);
            c.LikelyCause = "Desempenho limitado por: " + string.Join("; ", causes.ToArray()) + ".";
            c.Recommendation = causes.Count > 1
                ? "Tratar na ordem: liberar espaco no volume do sistema, depois avaliar upgrade de SSD e de memoria."
                : "Corrigir o fator acima deve produzir ganho perceptivel para o usuario.";
            c.Severity = causes.Count > 1 ? Severity.Medium : Severity.Low;
            if (lowSpaceVolumeTestId != null) c.RelatedTestIds.Add(lowSpaceVolumeTestId);
            c.RelatedTestIds.Add("MEM-001");
            c.Confidence = ConfidenceFromRelated(byId, c.RelatedTestIds, 80);
            list.Add(c);
        }

        private static void UpdateChainBroken(ScanContext ctx, Inventory inv, List<Correlation> list, Dictionary<string, TestResult> byId)
        {
            if (!inv.Os.LastUpdateInstalled.HasValue) return;

            // Usa ctx.StartedAt (o instante do scan) em vez de DateTime.Now
            // (relogio do SO no instante da analise), para que
            // UpdateChainBroken seja reprodutivel ao reanalisar um laudo
            // salvo - mesmo principio de SYS-007.
            double days = (ctx.StartedAt - inv.Os.LastUpdateInstalled.Value).TotalDays;
            if (days < 90) return;

            Correlation c = new Correlation();
            c.Symptom = "Windows sem atualizacoes ha " + T.Num(days, 0) + " dias";
            c.Evidence.Add(Evidence.Of("WMI", "ultima atualizacao instalada", T.Date(inv.Os.LastUpdateInstalled)));
            c.RelatedTestIds.Add("SYS-007");

            // Ausencia de dado (consulta MSFT_MpComputerStatus falhou, comum
            // sem elevacao) nao pode virar "0 dias" - o valor mais favoravel
            // possivel - a ponto de afirmar "definicoes de antivirus estao
            // em dia" sem ter lido o dado. Os tres casos abaixo (sem dado,
            // dado antigo, dado recente) ficam distintos.
            if (!inv.Security.DefenderSignatureAgeDays.HasValue)
            {
                c.LikelyCause = "Windows sem atualizacoes ha tempo - nao foi possivel avaliar as definicoes de antivirus (dado nao coletado, comum sem privilegio de Administrador) para confirmar se e a mesma cadeia de atualizacao ou algo isolado.";
                c.Recommendation = "Verificar manualmente o estado do Windows Update e, com uma execucao elevada, o estado das definicoes de antivirus.";
                c.Severity = Severity.Medium;
                c.Confidence = ConfidenceFromRelated(byId, c.RelatedTestIds, 60);
            }
            else
            {
                double sigDays = inv.Security.DefenderSignatureAgeDays.Value;
                c.Evidence.Add(Evidence.Of("WMI", "idade das definicoes do Defender", T.Num(sigDays, 0) + " dias"));
                c.RelatedTestIds.Add("SEC-002");

                if (sigDays >= 7)
                {
                    c.LikelyCause = "Servico de atualizacao provavelmente quebrado: tanto as atualizacoes do Windows quanto as definicoes de antivirus estao paradas, e as duas dependem da mesma cadeia.";
                    c.Recommendation = "Verificar os servicos wuauserv e BITS, e o espaco livre no volume do sistema. Se persistir, executar 'DISM /Online /Cleanup-Image /RestoreHealth' seguido de 'sfc /scannow' - ambos sao acoes de reparo e devem ser autorizados pelo cliente.";
                    c.Severity = Severity.High;
                    c.Confidence = ConfidenceFromRelated(byId, c.RelatedTestIds, Confidence.Combine(85, 80));
                }
                else
                {
                    c.LikelyCause = "Atualizacoes paradas, mas as definicoes de antivirus estao em dia - sugere pausa/adiamento configurado, e nao servico quebrado.";
                    c.Recommendation = "Verificar se ha pausa de atualizacoes configurada ou politica de adiamento aplicada.";
                    c.Severity = Severity.Medium;
                    c.Confidence = ConfidenceFromRelated(byId, c.RelatedTestIds, 70);
                }
            }

            list.Add(c);
        }
    }
}
