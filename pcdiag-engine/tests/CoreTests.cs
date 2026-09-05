using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Threading;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Testing
{
    public static class CoreTests
    {
        public static void Run(TestRunner t)
        {
            Json(t);
            JsonRoundTrip(t);
            Privacy(t);
            HtmlEscaping(t);
            ConfidenceRules(t);
            ArgumentQuoting(t);
            ProcessAllowlist(t);
            TimeoutIsolation(t);
            TimeoutDoesNotBlockButOrphanKeepsWriting(t);
            SafeGetSemantics(t);
            PathSanitization(t);
            SupportClassification(t);
        }

        // REGRESSAO: descoberto rodando a propria ferramenta. Sem manifesto de
        // compatibilidade o Windows devolve 6.2 para qualquer sistema moderno,
        // e um Windows 10 real era classificado como "nao suportado", abortando
        // a execucao.
        private static void SupportClassification(TestRunner t)
        {
            t.Suite("Regressao: classificacao de compatibilidade do SO");

            string reason;

            t.Equal("Windows 10 21H2 e suportado", SupportLevel.Supported,
                ScanContext.ClassifySupport(new Version(10, 0, 19044, 0), true, out reason));
            t.Contains("o motivo identifica o Windows 10", reason, "Windows 10");

            t.Equal("Windows 11 e suportado", SupportLevel.Supported,
                ScanContext.ClassifySupport(new Version(10, 0, 22631, 0), true, out reason));
            t.Contains("o motivo identifica o Windows 11", reason, "Windows 11");

            t.Equal("Windows 8.1 nao e suportado", SupportLevel.Unsupported,
                ScanContext.ClassifySupport(new Version(6, 3, 9600, 0), true, out reason));

            t.Equal("Windows 10 de 32 bits e parcialmente suportado", SupportLevel.PartiallySupported,
                ScanContext.ClassifySupport(new Version(10, 0, 19044, 0), false, out reason));
            t.Contains("o motivo cita a limitacao de sensores", reason, "sensores");

            t.Equal("build anterior ao 1809 e parcial", SupportLevel.PartiallySupported,
                ScanContext.ClassifySupport(new Version(10, 0, 17134, 0), true, out reason));

            t.Equal("versao desconhecida nao aborta a execucao", SupportLevel.PartiallySupported,
                ScanContext.ClassifySupport(null, true, out reason));

            // A API nativa precisa concordar com a realidade desta maquina.
            Version real = Sources.Native.GetRealOsVersion();
            t.NotNull("RtlGetVersion devolve a versao real do sistema", real);
            if (real != null)
            {
                t.True("a versao real e Windows 10 ou superior", real.Major >= 10);
                t.True("o numero de build e plausivel", real.Build > 10000);
            }
        }

        private sealed class Sample
        {
            public string Name { get; set; }
            public int? Count { get; set; }
            public double? Ratio { get; set; }
            public bool Flag { get; set; }
            public TestStatus Status { get; set; }
            public List<string> Items { get; set; }

            [Sensitive(DataClass.SensitiveSystem)]
            public string Serial { get; set; }
        }

        private static void Json(TestRunner t)
        {
            t.Suite("Serializacao JSON");

            Sample s = new Sample();
            s.Name = "teste";
            s.Count = null;
            s.Ratio = 0.5;
            s.Flag = true;
            s.Status = TestStatus.Warning;
            s.Items = new List<string>();
            s.Items.Add("a");
            s.Serial = "ABC123";

            string json = JsonWriter.Serialize(s, false, false);

            t.Contains("campo nulo sai como null (nunca como 0)", json, "\"count\":null");
            t.Contains("enum sai como nome legivel", json, "\"status\":\"Warning\"");
            t.Contains("booleano sai sem aspas", json, "\"flag\":true");
            t.Contains("array serializado", json, "\"items\":[\"a\"]");

            // Este e o teste que protege contra o bug classico de cultura: em
            // pt-BR, 0.5 sairia como "0,5" e quebraria o parse do outro lado.
            t.Contains("decimal usa ponto (cultura invariante)", json, "\"ratio\":0.5");
            t.DoesNotContain("decimal nao usa virgula", json, "0,5");

            string escaped = JsonWriter.Serialize(new Sample { Name = "a\"b\\c\nd" }, false, false);
            t.Contains("aspas escapadas", escaped, "a\\\"b");
            t.Contains("barra invertida escapada", escaped, "\\\\c");
            t.Contains("quebra de linha escapada", escaped, "\\nd");

            // REGRESSAO: um valor de REG_SZ de terceiro (o instalador do
            // Roblox e um exemplo conhecido) pode trazer um terminador nulo embutido
            // dentro do proprio valor. Escapa-lo como "\u0000" seria JSON
            // valido, mas o Postgres do dashboard se recusa a guardar esse
            // caractere em texto/JSON (erro 22P05) - e como a gravacao la e
            // uma unica transacao, isso derrubava o diagnostico inteiro sem
            // aviso nenhum (device criado, diagnostico nunca salvo). O
            // caractere nulo tem que sumir da saida, nunca virar "\u0000".
            string comNulo = JsonWriter.Serialize(new Sample { Name = "Roblox Player for JoaoTeste\0" }, false, false);
            t.DoesNotContain("caractere nulo nunca vira \\u0000 na saida", comNulo, "\\u0000");
            t.Contains("o resto da string sobrevive ao redor do nulo removido", comNulo, "Roblox Player for JoaoTeste");
        }

        private static void JsonRoundTrip(TestRunner t)
        {
            t.Suite("Parser JSON");

            string json = "{\"a\":1,\"b\":\"x\",\"c\":[1,2],\"d\":{\"e\":true},\"f\":null}";
            object parsed = JsonParser.Parse(json);

            Dictionary<string, object> root = parsed as Dictionary<string, object>;
            t.NotNull("objeto raiz parseado", root);
            t.Equal("numero", 1d, root["a"]);
            t.Equal("string", "x", root["b"]);
            t.Equal("array", 2, ((List<object>)root["c"]).Count);
            t.Equal("booleano aninhado", true, JsonParser.Path(parsed, "d.e"));
            t.Null("null preservado", root["f"]);
            t.Null("caminho inexistente devolve null em vez de lancar", JsonParser.Path(parsed, "x.y.z"));

            t.Throws<FormatException>("JSON truncado e rejeitado", delegate { JsonParser.Parse("{\"a\":"); });
            t.Throws<FormatException>("lixo apos o fim e rejeitado", delegate { JsonParser.Parse("{} extra"); });

            // Ida e volta: o que o escritor produz, o leitor consegue ler.
            Sample s = new Sample();
            s.Name = "acento a\\b \"c\"";
            s.Ratio = 1234.5678;
            string written = JsonWriter.Serialize(s, false, true);
            object reparsed = JsonParser.Parse(written);
            t.Equal("ida e volta preserva string", s.Name, JsonParser.Path(reparsed, "name"));
            t.Equal("ida e volta preserva numero", 1234.5678d, JsonParser.Path(reparsed, "ratio"));
        }

        private static void Privacy(TestRunner t)
        {
            t.Suite("Modo privacidade");

            Sample s = new Sample();
            s.Name = "publico";
            s.Serial = "SERIAL-SECRETO";

            string normal = JsonWriter.Serialize(s, false, false);
            string safe = JsonWriter.Serialize(s, true, false);

            t.Contains("laudo normal traz o serial", normal, "SERIAL-SECRETO");
            t.DoesNotContain("modo privacidade remove o serial", safe, "SERIAL-SECRETO");
            t.Contains("modo privacidade marca o campo como mascarado", safe, JsonWriter.Mask);
            t.Contains("modo privacidade mantem os campos publicos", safe, "publico");
            t.Contains("a chave continua presente (nao some do laudo)", safe, "\"serial\"");
        }

        private static void HtmlEscaping(TestRunner t)
        {
            t.Suite("Escape de HTML");

            // Cenario real: nome de dispositivo USB e mensagem de evento sao
            // conteudo que a ferramenta nao controla. No coletor antigo isso ia
            // cru para dentro de <td>.
            string hostile = "<script>alert(1)</script>";
            string escaped = Html.Text(hostile);

            t.DoesNotContain("tag de abertura neutralizada", escaped, "<script>");
            t.Contains("caractere < convertido em entidade", escaped, "&lt;script&gt;");
            t.Equal("ampersand escapado", "a &amp; b", Html.Text("a & b"));
            t.Equal("aspas escapadas", "&quot;x&quot;", Html.Text("\"x\""));
            t.Equal("apostrofo escapado", "&#39;x&#39;", Html.Text("'x'"));
            t.Equal("nulo vira string vazia", "", Html.Text(null));

            string control = Html.Text("a\u0007b");
            t.DoesNotContain("caractere de controle removido", control, "\u0007");

            // Ausencia precisa ser visivel no laudo, nao virar celula vazia.
            t.Contains("valor ausente e marcado explicitamente", Html.Value(null), "nao disponivel");
            t.Contains("string vazia tambem conta como ausente", Html.Value(""), "nao disponivel");
            t.Equal("valor presente sai limpo", "abc", Html.Value("abc"));
        }

        private static void ConfidenceRules(TestRunner t)
        {
            t.Suite("Calculo de confianca");

            t.Equal("base sozinha", 50, Confidence.Build().Value);
            t.Equal("fonte autoritativa soma 20", 70, Confidence.Build().Authoritative().Value);
            t.Equal("autoritativa + concordancia + faixa plausivel", 90,
                Confidence.Build().Authoritative().AgreeingSource().PlausibleRange().Value);

            // A terceira fonte concordante nao pode somar nada alem das duas
            // primeiras: confirmacao redundante nao aumenta certeza.
            int twoSources = Confidence.Build().Authoritative().AgreeingSource().AgreeingSource().Value;
            int fourSources = Confidence.Build().Authoritative()
                .AgreeingSource().AgreeingSource().AgreeingSource().AgreeingSource().Value;
            t.Equal("duas fontes concordantes somam 20", 90, twoSources);
            t.Equal("da terceira em diante nao soma mais nada", twoSources, fourSources);

            t.Equal("fonte declarativa nao confiavel derruba", 30, Confidence.Build().UnreliableSource().Value);
            t.Equal("divergencia entre fontes derruba mais", 20, Confidence.Build().Divergent().Value);
            t.Equal("amostra volatil unica reduz", 35, Confidence.Build().SingleVolatileSample().Value);
            t.Equal("heuristica textual reduz", 35, Confidence.Build().Heuristic().Value);

            // Nenhuma leitura de software sobre hardware de terceiro merece 100%.
            int maxed = Confidence.Build().Authoritative().AgreeingSource().AgreeingSource().PlausibleRange().Value;
            t.True("confianca nunca chega a 100", maxed <= Confidence.Max);
            t.True("confianca nunca fica abaixo do piso", Confidence.Build().Divergent().Divergent().Divergent().Value >= Confidence.Min);

            t.Equal("combinacao usa o elo mais fraco", 40, Confidence.Combine(90, 40, 75));
            t.Equal("combinacao sem partes cai no piso", Confidence.Min, Confidence.Combine());
        }

        private static void ArgumentQuoting(TestRunner t)
        {
            t.Suite("Montagem segura de linha de comando");

            t.Equal("argumento simples nao ganha aspas", "abc", ProcessRunner.QuoteArgument("abc"));
            t.Equal("espaco forca aspas", "\"a b\"", ProcessRunner.QuoteArgument("a b"));
            t.Equal("aspas internas sao escapadas", "\"a\\\"b\"", ProcessRunner.QuoteArgument("a\"b"));
            // Barra final so precisa ser duplicada quando o argumento vai entre
            // aspas; sem aspas, "C:\" ja volta correto do CommandLineToArgvW.
            t.Equal("barra final sem aspas fica como esta", "C:\\", ProcessRunner.QuoteArgument("C:\\"));
            t.Equal("barra final dentro de aspas e duplicada",
                "\"C:\\Arquivos de Programas\\\\\"", ProcessRunner.QuoteArgument("C:\\Arquivos de Programas\\"));
            t.Equal("argumento vazio vira par de aspas", "\"\"", ProcessRunner.QuoteArgument(""));

            // Caminho com espacos e o caso comum desta ferramenta (a propria
            // pasta do projeto tem espaco no nome).
            string args = ProcessRunner.BuildArguments(new string[] { "/output", @"C:\Users\Jose Silva\rel.xml", "/xml" });
            t.Contains("caminho com espaco vai entre aspas", args, "\"C:\\Users\\Jose Silva\\rel.xml\"");

            // Tentativa de injecao de argumento: o conteudo continua sendo UM
            // argumento, nao vira dois.
            string injected = ProcessRunner.QuoteArgument("valor\" /f \"outro");
            t.Contains("tentativa de quebrar o argumento e escapada", injected, "\\\"");
        }

        private static void ProcessAllowlist(TestRunner t)
        {
            t.Suite("Allowlist de executaveis");

            ProcessRunner runner = new ProcessRunner();

            ProcessResult blocked = runner.RunSystem32("cmd.exe", new string[] { "/c", "dir" }, 1000);
            t.False("executavel fora do allowlist nao e iniciado", blocked.Started);
            t.Contains("motivo do bloqueio e explicito", blocked.FailureReason, "allowlist");

            ProcessResult traversal = runner.RunSystem32(@"..\..\evil.exe", new string[0], 1000);
            t.False("tentativa de travessia de caminho e bloqueada", traversal.Started);

            ProcessResult empty = runner.RunSystem32("", new string[0], 1000);
            t.False("nome vazio e rejeitado", empty.Started);

            // XPath do log de eventos: o nome do provedor e validado antes de
            // ser interpolado na consulta.
            t.True("provedor legitimo e aceito", EventLogSource.IsSafeProviderName("Microsoft-Windows-WHEA-Logger"));
            t.True("provedor com barra e aceito", EventLogSource.IsSafeProviderName("Microsoft-Windows-Kernel/Power"));
            t.False("apostrofo no provedor e rejeitado", EventLogSource.IsSafeProviderName("x' or '1'='1"));
            t.False("colchete no provedor e rejeitado", EventLogSource.IsSafeProviderName("a[b]"));
            t.False("provedor vazio e rejeitado", EventLogSource.IsSafeProviderName(""));

            t.Throws<ArgumentException>("consulta com provedor hostil e recusada", delegate
            {
                EventLogSource.XPathProviderLevelsSince("evil'] | //*[1", new int[] { 2 }, TimeSpan.FromDays(1));
            });
        }

        private static void TimeoutIsolation(TestRunner t)
        {
            t.Suite("Timeout e isolamento de modulo");

            ScanContext ctx = Fixture.Context(false);

            ModuleOutcome ok = ModuleRunner.Run(ctx, "rapido", delegate { }, 5000);
            t.True("modulo rapido conclui", ok.Succeeded);
            t.False("modulo rapido nao marca timeout", ok.TimedOut);

            ModuleOutcome slow = ModuleRunner.Run(ctx, "travado", delegate { Thread.Sleep(4000); }, 300);
            t.False("modulo travado nao e reportado como sucesso", slow.Succeeded);
            t.True("modulo travado e marcado como timeout", slow.TimedOut);
            t.Contains("mensagem explica que a execucao continuou", slow.Error, "continuou");

            ModuleOutcome boom = ModuleRunner.Run(ctx, "quebrado", delegate
            {
                throw new InvalidOperationException("falha proposital");
            }, 5000);
            t.False("modulo com excecao nao e sucesso", boom.Succeeded);
            t.Contains("erro preserva a mensagem original", boom.Error, "falha proposital");

            // O ponto central: uma falha nao derruba o processo.
            t.DoesNotThrow("excecao dentro do modulo nao escapa para o chamador", delegate
            {
                ModuleRunner.Run(ctx, "outro", delegate { throw new Exception("x"); }, 1000);
            });

            t.Equal("todos os modulos ficam registrados", 4, ctx.ModuleOutcomes.Count);
        }

        // Regressao: quando um modulo estoura o timeout, ModuleRunner.Run
        // segue em frente sem esperar a thread abandonada terminar. Este
        // teste documenta esse comportamento (a chamada nao bloqueia, e a
        // thread orfa pode escrever no alvo compartilhado depois do
        // timeout ja ter sido reportado) para que qualquer mudanca futura
        // no runner precise continuar passando por ele conscientemente.
        private static void TimeoutDoesNotBlockButOrphanKeepsWriting(TestRunner t)
        {
            t.Suite("Timeout: modulo abandonado continua escrevendo no alvo compartilhado");

            ScanContext ctx = Fixture.Context(false);
            CpuInfo shared = new CpuInfo();

            Stopwatch sw = Stopwatch.StartNew();
            ModuleOutcome outcome = ModuleRunner.Run(ctx, "lento-e-abandonado", delegate
            {
                Thread.Sleep(600);
                shared.Name = "ESCRITO DEPOIS DO TIMEOUT";
                shared.TemperatureC = 42;
            }, 100);
            sw.Stop();

            t.True("Run() devolve no timeout, sem esperar a thread abandonada terminar", sw.ElapsedMilliseconds < 500);
            t.True("outcome marcado como timeout", outcome.TimedOut);
            t.Null("no instante do timeout o alvo compartilhado ainda esta intocado", shared.Name);

            // A thread orfa (IsBackground=true) ainda esta rodando em algum
            // lugar - da tempo dela terminar o Sleep(600) e escrever.
            Thread.Sleep(900);
            t.Equal("a escrita tardia da thread abandonada realmente acontece - o modulo dito TIMEOUT ainda contamina o alvo depois",
                "ESCRITO DEPOIS DO TIMEOUT", shared.Name);
        }

        private static void SafeGetSemantics(TestRunner t)
        {
            t.Suite("Semantica de falha (Try.Get)");

            ScanContext ctx = Fixture.Context(false);

            // A diferenca essencial em relacao ao Get-Safe do script antigo:
            // falha devolve null ("nao sei"), nunca um valor plausivel que
            // seria lido como diagnostico positivo.
            string value = Try.Get<string>(ctx, "mod", "leitura", delegate
            {
                throw new UnauthorizedAccessException("negado");
            });
            t.Null("falha devolve null, nao um texto de fallback", value);

            int? number = Try.Get<int?>(ctx, "mod", "numero", delegate
            {
                throw new Exception("falhou");
            });
            t.Null("tipo numerico anulavel devolve null, nao zero", number);

            t.True("a falha foi registrada no log", ctx.Log.Entries != null);

            int found = 0;
            foreach (LogEntry e in ctx.Log.Entries)
            {
                if (e.Message != null && e.Message.IndexOf("negado", StringComparison.OrdinalIgnoreCase) >= 0) found++;
            }
            t.True("o motivo da falha aparece no log", found > 0);

            string good = Try.Get<string>(ctx, "mod", "ok", delegate { return "valor"; });
            t.Equal("caminho feliz devolve o valor", "valor", good);
        }

        private static void PathSanitization(TestRunner t)
        {
            t.Suite("Sanitizacao de nome para caminho");

            t.Equal("nome normal preservado", "DESKTOP-ABC", Paths.SanitizeForFileName("DESKTOP-ABC"));
            t.Equal("travessia de diretorio neutralizada", "etc_passwd", Paths.SanitizeForFileName("../etc/passwd"));
            t.Equal("caracteres invalidos viram sublinhado", "a_b", Paths.SanitizeForFileName("a:b"));
            t.Equal("nome vazio tem fallback", "equipamento", Paths.SanitizeForFileName(""));
            t.Equal("nome nulo tem fallback", "equipamento", Paths.SanitizeForFileName(null));
            t.True("nome muito longo e truncado", Paths.SanitizeForFileName(new string('x', 200)).Length <= 40);
            t.DoesNotContain("nenhuma barra sobrevive", Paths.SanitizeForFileName("a\\b/c"), "\\");
        }
    }
}
