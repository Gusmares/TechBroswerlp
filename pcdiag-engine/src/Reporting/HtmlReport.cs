using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using PcDiag.Analysis;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Reporting
{
    // Gerador do laudo HTML.
    //
    // Regra absoluta: NENHUM valor entra no documento sem passar por
    // Html.Text() ou Html.Value(). Nome de dispositivo, modelo de disco,
    // hostname e mensagem de evento do Windows sao conteudo que a ferramenta
    // nao controla, e no coletor anterior iam crus para dentro de <td>.
    public static class HtmlReport
    {
        public static void Write(string path, ReportEnvelope env, bool technician)
        {
            StringBuilder sb = new StringBuilder(200000);

            Head(sb, env);
            Summary(sb, env);
            Components(sb, env);
            Correlations(sb, env);
            Findings(sb, env);
            ComparisonSection(sb, env);
            Inventory(sb, env);

            // No modo cliente (--user-report) a tabela de Modulos de coleta
            // (Coverage) fica escondida - e ela e o UNICO lugar do laudo
            // onde TIMEOUT/FALHA de um modulo aparecem. Mantemos um resumo
            // compacto e obrigatorio (so contagem + nomes, sem a
            // duracao/detalhe tecnico de cada modulo) mesmo quando a tabela
            // completa fica escondida, para que uma area nao verificada
            // nunca deixe de aparecer no laudo cliente.
            if (!technician) ModuleFailureSummary(sb, env);

            if (technician)
            {
                SecurityAndDevices(sb, env);
                Inconsistencies(sb, env);
                AllTests(sb, env);
                Coverage(sb, env);
            }

            Foot(sb, env);

            // UTF-8 COM BOM aqui, de proposito: e o unico caso em que o BOM
            // ajuda, porque o arquivo pode ser aberto por duplo clique em
            // navegadores e editores que nao respeitam o <meta charset>.
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
        }

        private static void Head(StringBuilder sb, ReportEnvelope env)
        {
            ReportMetadata m = env.Metadata;

            // O <title> nao pode carregar o hostname quando --privacy-safe
            // esta ativo: ele sobrevive a mascara do resto do documento
            // porque vira literalmente o nome do arquivo/PDF quando o
            // tecnico imprime ou salva a pagina. Em privacy-safe usamos o
            // ScanId, que ja e o identificador publico do atendimento.
            string host;
            if (m.PrivacySafe)
                host = "scan " + Html.Text(m.ScanId);
            else
                host = env.Inventory != null && env.Inventory.Machine != null
                    ? Html.Text(env.Inventory.Machine.Hostname) : "";

            sb.Append("<!DOCTYPE html><html lang=\"pt-br\"><head><meta charset=\"UTF-8\">");
            sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
            sb.Append("<title>Laudo tecnico - ").Append(host).Append(" - ")
              .Append(Html.Text(m.StartedAt.ToString("dd/MM/yyyy", CultureInfo.InvariantCulture))).Append("</title>");
            sb.Append("<style>");
            sb.Append(@"
*{box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,Arial,sans-serif;background:#eef1f5;color:#1b2733;margin:0;line-height:1.5}
.wrap{max-width:1080px;margin:0 auto;padding:20px}
header{background:#10263d;color:#fff;padding:26px 0}
header h1{margin:0;font-size:23px;letter-spacing:-.2px}
header .meta{color:#a9bed3;font-size:12.5px;margin-top:6px}
.card{background:#fff;border-radius:10px;padding:20px 24px;margin:16px 0;box-shadow:0 1px 3px rgba(16,38,61,.09)}
.card h2{font-size:16px;margin:0 0 14px;color:#10263d;border-bottom:2px solid #e6ebf1;padding-bottom:9px}
.card h3{font-size:13.5px;margin:18px 0 8px;color:#33475b}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #eef1f4;vertical-align:top}
th{background:#f7f9fb;font-weight:600;white-space:nowrap}
.na{color:#9aa7b4;font-style:italic}
.badge{display:inline-block;padding:2px 9px;border-radius:11px;font-size:10.5px;font-weight:700;white-space:nowrap;letter-spacing:.3px}
.b-pass{background:#dff5e6;color:#0a7038}
.b-info{background:#e3edf9;color:#1c4f88}
.b-warn{background:#fff1cf;color:#8a5a00}
.b-err{background:#ffe2e0;color:#a3160f}
.b-crit{background:#a3160f;color:#fff}
.b-skip{background:#eceff2;color:#5c6b7a}
.score{display:flex;align-items:center;gap:24px;flex-wrap:wrap}
.scorebox{min-width:140px;text-align:center;padding:16px 20px;border-radius:10px;background:#f7f9fb}
.scorenum{font-size:44px;font-weight:700;line-height:1}
.counts{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.count{background:#f7f9fb;border-radius:8px;padding:9px 14px;font-size:12px;min-width:96px}
.count b{display:block;font-size:19px;color:#10263d}
.bar{height:9px;background:#e9edf1;border-radius:5px;overflow:hidden;min-width:120px}
.bar span{display:block;height:100%;border-radius:5px}
.finding{border-left:4px solid #ccc;padding:11px 14px;margin:10px 0;background:#fbfcfd;border-radius:0 7px 7px 0}
.finding.crit{border-color:#a3160f}
.finding.err{border-color:#e0503f}
.finding.warn{border-color:#e5a90b}
.finding.info{border-color:#3d7fc1}
.finding .t{font-weight:600;font-size:13.5px}
.finding .r{font-size:13px;margin-top:4px}
.finding .rec{font-size:12.5px;margin-top:7px;color:#33475b;background:#fff;border:1px solid #e6ebf1;border-radius:6px;padding:8px 10px}
.finding .id{font-family:Consolas,monospace;font-size:11px;color:#7a8794}
details{margin-top:8px}
summary{cursor:pointer;font-size:12px;color:#4a6480;user-select:none}
.ev{font-family:Consolas,'Courier New',monospace;font-size:11.5px;background:#f6f8fa;border-radius:6px;padding:9px 11px;margin-top:7px;overflow-x:auto}
.ev div{padding:2px 0;border-bottom:1px solid #edf1f4;white-space:pre-wrap;word-break:break-word}
.ev div:last-child{border-bottom:none}
.muted{color:#7a8794;font-size:12.5px}
.tag{display:inline-block;background:#eef2f6;border-radius:5px;padding:1px 7px;font-size:11px;color:#4a6480;margin-right:5px}
.privacy{background:#fff8e6;border:1px solid #f0d78c;border-radius:8px;padding:12px 16px;margin:14px 0;font-size:12.5px}
.scroll{overflow-x:auto}
@media print{body{background:#fff}.card{box-shadow:none;border:1px solid #dde3e9;break-inside:avoid}header{background:#10263d !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
");
            sb.Append("</style></head><body>");

            // O <title> alguns paragrafos acima protege o acesso a
            // env.Inventory.Machine (guarda null-check completa). O fluxo
            // atual sempre constroi Inventory com Machine no construtor
            // (Program.cs), entao nao ha crash esperado aqui, mas a mesma
            // protecao e aplicada nesta linha para nao depender
            // silenciosamente desse invariante.
            string hostnameForHeader = env.Inventory != null && env.Inventory.Machine != null
                ? env.Inventory.Machine.Hostname : null;

            sb.Append("<header><div class=\"wrap\"><h1>Laudo Tecnico de Diagnostico</h1>");
            sb.Append("<div class=\"meta\">");
            sb.Append("Equipamento: <b>").Append(Html.Value(hostnameForHeader, "nao identificado")).Append("</b>");
            sb.Append(" &nbsp;|&nbsp; Scan <b>").Append(Html.Text(m.ScanId)).Append("</b>");
            sb.Append(" &nbsp;|&nbsp; ").Append(Html.Text(m.StartedAt.ToString("dd/MM/yyyy HH:mm:ss", CultureInfo.InvariantCulture)));
            sb.Append(" &nbsp;|&nbsp; ").Append(Html.Text(m.DurationSeconds.ToString("F1", CultureInfo.InvariantCulture))).Append("s");
            sb.Append("</div><div class=\"meta\">");
            sb.Append("Ferramenta v").Append(Html.Text(m.ToolVersion));
            sb.Append(" &nbsp;|&nbsp; regras ").Append(Html.Text(m.RulesVersion));
            sb.Append(" &nbsp;|&nbsp; privilegio: <b>").Append(Html.Text(m.PrivilegeLevel)).Append("</b>");
            sb.Append(" &nbsp;|&nbsp; suporte: ").Append(Html.Text(m.SupportLevel));
            sb.Append(" &nbsp;|&nbsp; modo: ").Append(Html.Text(m.Mode));
            sb.Append("</div></div></header><div class=\"wrap\">");

            if (m.PrivacySafe)
                sb.Append("<div class=\"privacy\"><b>Relatorio em modo privacidade.</b> Numero de serie, hostname, usuario, MAC e enderecos IP foram substituidos por <code>[REDACTED]</code>. Para o laudo completo, gere novamente sem <code>--privacy-safe</code>.</div>");

            if (!m.ElevatedPrivileges)
                sb.Append("<div class=\"privacy\"><b>Executado sem privilegio de Administrador.</b> Varios testes nao puderam rodar (SMART, temperatura, log de eventos, BitLocker, Defender). Eles aparecem como <b>REQUER ADMIN</b> e <b>nao</b> como aprovados. Para um laudo completo, execute novamente como Administrador.</div>");
        }

        private static void Summary(StringBuilder sb, ReportEnvelope env)
        {
            ExecutiveSummary s = env.Summary;

            // A cor do numero mais destacado do laudo (44px, .scorenum)
            // combina o Status vindo de ScoreStatus(score, hasCritical) com
            // a cobertura (ver MinCoverageForVerdict em Engine.cs): um
            // achado CRITICO/ATENCAO continua legitimamente
            // vermelho/laranja mesmo com cobertura parcial em OUTRAS areas,
            // pois e informacao real e ja sobrevive ao gate de cobertura em
            // ScoreStatus (hasCritical sempre vence). So o verde (a cor que
            // passa seguranca) precisa de cobertura de verdade para ser
            // exibido - cobertura insuficiente nunca deve ser pintada de
            // verde.
            string color;
            if (s.Status == "INCONCLUSIVO") color = "#5b6b7a";
            else if (s.Status == "CRITICO") color = "#a3160f";
            else if (s.Status == "ATENCAO") color = "#c98a00";
            else if (s.CoveragePercent < 80.0) color = "#5b6b7a"; // SAUDAVEL mas cobertura incompleta - nao e verde de verdade
            else color = "#0a7038";

            sb.Append("<div class=\"card\"><h2>Resumo executivo</h2><div class=\"score\">");
            sb.Append("<div class=\"scorebox\"><div class=\"scorenum\" style=\"color:").Append(color).Append("\">")
              .Append(s.HealthScore).Append("</div><div class=\"muted\">de 100");
            if (s.CoveragePercent < 100.0)
                sb.Append(" &middot; ").Append(s.CoveragePercent.ToString("F0", CultureInfo.InvariantCulture)).Append("% medido");
            sb.Append("</div></div>");
            sb.Append("<div style=\"flex:1;min-width:280px\">");
            sb.Append("<div style=\"font-size:17px;font-weight:600;color:").Append(color).Append("\">").Append(Html.Text(s.Status)).Append("</div>");
            sb.Append("<div style=\"margin-top:5px\">").Append(Html.Text(s.Headline)).Append("</div>");
            sb.Append("<div class=\"counts\">");
            Count(sb, "Criticos", s.CriticalIssues);
            Count(sb, "Alta", s.HighIssues);
            Count(sb, "Media", s.MediumIssues);
            Count(sb, "Baixa", s.LowIssues);
            Count(sb, "Sem achado", s.TestsPassed);
            Count(sb, "Nao executados", s.TestsNotExecuted);
            sb.Append("</div></div></div>");

            sb.Append("<p class=\"muted\" style=\"margin-top:14px\">Cobertura: <b>")
              .Append(Html.Text(s.CoveragePercent.ToString("F1", CultureInfo.InvariantCulture)))
              .Append("%</b> dos ").Append(env.Tests.Count).Append(" testes puderam ser executados. ");
            sb.Append("O score parte de 100 e desconta por achado conforme a severidade; testes que nao puderam ser executados <b>nao</b> descontam pontos, porque nao sao defeito do equipamento.</p>");
            sb.Append("</div>");
        }

        // A barra precisa refletir DUAS grandezas ao mesmo tempo: quanto foi
        // descontado por achados (o score) e quanto da area foi efetivamente
        // medida (a cobertura).
        //
        // Pintar a barra inteira de verde usando so o score fazia uma area onde
        // NADA rodou aparecer como perfeitamente saudavel - que e exatamente o
        // defeito que esta reengenharia existe para eliminar.
        private static string HealthBar(ComponentHealth c)
        {
            StringBuilder sb = new StringBuilder();

            if (c.EntirelyNotApplicable)
            {
                sb.Append("<div class=\"bar\"></div><span class=\"muted\">nao se aplica</span>");
                return sb.ToString();
            }

            if (c.CoveragePercent == 0)
            {
                sb.Append("<div class=\"bar\"></div><span class=\"muted\">sem medicao</span>");
                return sb.ToString();
            }

            string color = c.Score >= 85 ? "#2c9f5c" : (c.Score >= 60 ? "#e5a90b" : "#d0402f");
            int measuredWidth = (int)Math.Round(c.Score * (c.CoveragePercent / 100.0));
            if (measuredWidth < 0) measuredWidth = 0;
            if (measuredWidth > 100) measuredWidth = 100;

            sb.Append("<div class=\"bar\"><span style=\"width:").Append(measuredWidth)
              .Append("%;background:").Append(color).Append("\"></span></div>");
            sb.Append("<span class=\"muted\">").Append(c.Score).Append("/100");
            if (c.CoveragePercent < 100) sb.Append(" &middot; ").Append(c.CoveragePercent).Append("% medido");
            sb.Append("</span>");

            return sb.ToString();
        }

        private static void Count(StringBuilder sb, string label, int value)
        {
            sb.Append("<div class=\"count\"><b>").Append(value).Append("</b>").Append(Html.Text(label)).Append("</div>");
        }

        private static void Components(StringBuilder sb, ReportEnvelope env)
        {
            sb.Append("<div class=\"card\"><h2>Saude por area</h2><div class=\"scroll\"><table><thead><tr>");
            sb.Append("<th>Area</th><th style=\"width:180px\">Indice</th><th>Situacao</th><th>Resumo</th></tr></thead><tbody>");

            foreach (ComponentHealth c in env.ComponentHealth)
            {
                sb.Append("<tr><td><b>").Append(Html.Text(c.Component)).Append("</b></td>");
                sb.Append("<td>").Append(HealthBar(c)).Append("</td>");
                sb.Append("<td>").Append(Badge(c.Status)).Append("</td>");
                sb.Append("<td>").Append(Html.Text(c.Summary)).Append("</td></tr>");
            }

            sb.Append("</tbody></table></div>");
            sb.Append("<p class=\"muted\" style=\"margin-top:12px\">A parte colorida da barra representa o que foi <b>efetivamente verificado</b>; a parte cinza e o que nao pode ser medido nesta execucao. Uma area totalmente cinza nao significa que esta boa - significa que nao foi avaliada.</p>");
            sb.Append("</div>");
        }

        private static void Correlations(StringBuilder sb, ReportEnvelope env)
        {
            if (env.Correlations == null || env.Correlations.Count == 0) return;

            sb.Append("<div class=\"card\"><h2>Causas provaveis</h2>");
            sb.Append("<p class=\"muted\">Cada item abaixo cruza mais de uma evidencia independente. A confianca indicada reflete a forca dessas evidencias - nunca ha causa afirmada sem lastro.</p>");

            foreach (Correlation c in env.Correlations)
            {
                string cls = c.Severity == Severity.Critical ? "crit" : (c.Severity == Severity.High ? "err" : (c.Severity == Severity.Medium ? "warn" : "info"));
                sb.Append("<div class=\"finding ").Append(cls).Append("\">");
                sb.Append("<div class=\"t\">Sintoma: ").Append(Html.Text(c.Symptom)).Append("</div>");
                sb.Append("<div class=\"r\"><b>Causa provavel:</b> ").Append(Html.Text(c.LikelyCause)).Append("</div>");
                sb.Append("<div class=\"r\"><span class=\"tag\">confianca ").Append(c.Confidence).Append("%</span>");
                sb.Append("<span class=\"tag\">severidade ").Append(Html.Text(c.Severity.ToString())).Append("</span>");

                foreach (string id in c.RelatedTestIds)
                    sb.Append("<span class=\"tag\">").Append(Html.Text(id)).Append("</span>");

                sb.Append("</div>");
                if (!string.IsNullOrEmpty(c.Recommendation))
                    sb.Append("<div class=\"rec\"><b>Recomendacao:</b> ").Append(Html.Text(c.Recommendation)).Append("</div>");

                EvidenceBlock(sb, c.Evidence);
                sb.Append("</div>");
            }

            sb.Append("</div>");
        }

        private static void Findings(StringBuilder sb, ReportEnvelope env)
        {
            List<TestResult> problems = new List<TestResult>();
            foreach (TestResult t in env.Tests) if (t.IsProblem) problems.Add(t);

            problems.Sort(delegate(TestResult a, TestResult b)
            {
                int c = Rank(b).CompareTo(Rank(a));
                if (c != 0) return c;
                return string.CompareOrdinal(a.Id, b.Id);
            });

            sb.Append("<div class=\"card\"><h2>Achados</h2>");

            if (problems.Count == 0)
            {
                sb.Append("<p class=\"muted\">Nenhum achado nas areas verificadas. Isso nao significa que a maquina esta livre de qualquer problema: significa que os ")
                  .Append(env.Tests.Count).Append(" testes desta ferramenta nao encontraram indicio nas areas que cobrem.</p></div>");
                return;
            }

            foreach (TestResult t in problems) Finding(sb, t);
            sb.Append("</div>");
        }

        private static void Finding(StringBuilder sb, TestResult t)
        {
            string cls = t.Status == TestStatus.Critical ? "crit" : (t.Status == TestStatus.Error ? "err" : "warn");
            sb.Append("<div class=\"finding ").Append(cls).Append("\">");
            sb.Append("<div class=\"t\">").Append(Badge(t.Status)).Append(" ").Append(Html.Text(t.Name)).Append("</div>");
            sb.Append("<div class=\"r\">").Append(Html.Text(t.Result)).Append("</div>");
            sb.Append("<div class=\"r\"><span class=\"id\">").Append(Html.Text(t.Id)).Append("</span> ");
            sb.Append("<span class=\"tag\">severidade ").Append(Html.Text(t.Severity.ToString())).Append("</span>");
            sb.Append("<span class=\"tag\">confianca ").Append(t.Confidence).Append("%</span>");
            sb.Append("<span class=\"tag\">").Append(Html.Text(t.Category)).Append("</span></div>");

            if (!string.IsNullOrEmpty(t.Recommendation))
                sb.Append("<div class=\"rec\"><b>Recomendacao:</b> ").Append(Html.Text(t.Recommendation)).Append("</div>");

            EvidenceBlock(sb, t.Evidence);
            sb.Append("</div>");
        }

        private static void EvidenceBlock(StringBuilder sb, List<Evidence> evidence)
        {
            if (evidence == null || evidence.Count == 0) return;

            sb.Append("<details><summary>Evidencias (").Append(evidence.Count).Append(")</summary><div class=\"ev\">");
            foreach (Evidence e in evidence)
            {
                sb.Append("<div>[").Append(Html.Text(e.Source)).Append("] ")
                  .Append(Html.Text(e.Query)).Append(" = ").Append(Html.Text(e.Value)).Append("</div>");
            }
            sb.Append("</div></details>");
        }

        private static void ComparisonSection(StringBuilder sb, ReportEnvelope env)
        {
            ComparisonResult c = env.Comparison;

            // Quando --baseline foi passado mas a comparacao nao pode ser
            // feita (arquivo nao encontrado, ilegivel, de outro
            // equipamento, de outro schema/modo), mostramos um aviso
            // explicando o motivo em vez de simplesmente omitir a secao.
            // Mesmo estilo visual do banner de privacidade/sem-admin, para
            // nao passar despercebido.
            if (c != null && !c.Available && c.Note != null)
            {
                sb.Append("<div class=\"card\"><h2>Comparacao com o atendimento anterior</h2>");
                sb.Append("<div class=\"privacy\"><b>Comparacao nao disponivel.</b> ").Append(Html.Text(c.Note)).Append("</div>");
                sb.Append("</div>");
                return;
            }

            if (c == null || !c.Available) return;

            sb.Append("<div class=\"card\"><h2>Comparacao com o atendimento anterior</h2>");
            sb.Append("<p class=\"muted\">Linha de base: scan <b>").Append(Html.Value(c.BaselineScanId, "sem id")).Append("</b>");
            if (c.BaselineDate.HasValue)
                sb.Append(" de ").Append(Html.Text(c.BaselineDate.Value.ToString("dd/MM/yyyy", CultureInfo.InvariantCulture)));
            if (c.ScoreBefore.HasValue)
                sb.Append(". Score: ").Append(c.ScoreBefore.Value).Append(" &rarr; <b>").Append(c.ScoreAfter).Append("</b>");
            sb.Append(".</p>");

            if (c.Changes.Count == 0)
            {
                sb.Append("<p class=\"muted\">Nenhuma diferenca relevante entre as duas execucoes.</p></div>");
                return;
            }

            sb.Append("<div class=\"scroll\"><table><thead><tr><th>Mudanca</th><th>Item</th><th>Antes</th><th>Depois</th></tr></thead><tbody>");
            foreach (ChangeEntry e in c.Changes)
            {
                sb.Append("<tr><td>").Append(Html.Text(KindLabel(e.Kind))).Append("</td>");
                sb.Append("<td>").Append(Html.Text(e.Label)).Append("<br><span class=\"id\">").Append(Html.Text(e.Key)).Append("</span></td>");
                sb.Append("<td>").Append(Html.Value(e.Before, "-")).Append("</td>");
                sb.Append("<td>").Append(Html.Value(e.After, "-")).Append("</td></tr>");
            }
            sb.Append("</tbody></table></div></div>");
        }

        private static string KindLabel(string kind)
        {
            if (kind == "Added") return "Novo";
            if (kind == "Removed") return "Removido";
            return "Alterado";
        }

        // Referencia de hardware: identidade do chipset (medida via PCI
        // Vendor/Device ID) e banco de compatibilidade (tabela de
        // referencia - NUNCA misturada visualmente com o que foi medido).
        // Ver Model/ChipsetDatabase.cs e Analysis/CompatibilityReference.cs.
        private static void ChipsetSection(StringBuilder sb, Model.Inventory inv, CompatibilityReference cr)
        {
            sb.Append("<div class=\"card\"><h2>Chipset e compatibilidade</h2><div class=\"scroll\"><table>");

            if (inv.Chipset != null)
            {
                string chipsetLabel = inv.Chipset.Name != null
                    ? inv.Chipset.Name
                    : "ID nao catalogado (" + T.Name(inv.Chipset.Vendor, "?") + " " +
                        T.Name(inv.Chipset.VendorId, "?") + ":" + T.Name(inv.Chipset.DeviceId, "?") + ")";
                Row(sb, "Chipset", chipsetLabel);
                Row(sb, "Identificado por", inv.Chipset.SourceDevice);
            }
            else
            {
                Row(sb, "Chipset", inv.ChipsetUnavailableReason);
            }

            if (cr != null && cr.Available)
            {
                Row(sb, "Encaixe (socket)", cr.Socket);
                Row(sb, "Geracoes de CPU suportadas", cr.CpuGenerations);
                Row(sb, "PCIe do chipset", cr.ChipsetPcieGeneration);
                Row(sb, "RAID", cr.RaidSupport);
                if (!string.IsNullOrEmpty(cr.Notes)) Row(sb, "Observacoes", cr.Notes);
                sb.Append("<tr><td colspan=\"2\"><i class=\"muted\">").Append(Html.Text(cr.Source)).Append("</i></td></tr>");
            }
            else if (cr != null && cr.UnavailableReason != null)
            {
                sb.Append("<tr><td colspan=\"2\" class=\"muted\">Compatibilidade de referencia indisponivel: ")
                    .Append(Html.Text(cr.UnavailableReason)).Append("</td></tr>");
            }

            sb.Append("</table></div></div>");
        }

        private static void Inventory(StringBuilder sb, ReportEnvelope env)
        {
            Model.Inventory inv = env.Inventory;

            sb.Append("<div class=\"card\"><h2>Identificacao do equipamento</h2><div class=\"scroll\"><table>");
            Row(sb, "Fabricante", inv.Machine.Manufacturer);
            Row(sb, "Modelo", inv.Machine.Model);
            Row(sb, "Tipo", inv.Machine.FormFactor);
            Row(sb, "Numero de serie", inv.Machine.SerialNumber);
            Row(sb, "Placa-mae", Join(inv.Machine.BoardManufacturer, inv.Machine.BoardProduct));
            Row(sb, "Nome do computador", inv.Machine.Hostname);
            Row(sb, "Usuario logado", inv.Machine.LoggedUser);
            Row(sb, "Dominio / grupo", inv.Machine.Domain);
            if (inv.Machine.IsVirtualMachine == true) Row(sb, "Maquina virtual", inv.Machine.VirtualizationHint);
            sb.Append("</table></div></div>");

            sb.Append("<div class=\"card\"><h2>Sistema operacional e firmware</h2><div class=\"scroll\"><table>");
            Row(sb, "Windows", inv.Os.Caption);
            Row(sb, "Versao / build", Join(inv.Os.DisplayVersion, inv.Os.BuildNumber.HasValue ? "build " + inv.Os.BuildNumber.Value : null));
            Row(sb, "Arquitetura", inv.Os.Architecture);
            Row(sb, "Instalado em", Fmt(inv.Os.InstallDate));
            Row(sb, "Ultimo boot", Fmt(inv.Os.LastBootTime));
            Row(sb, "Ativacao", inv.Os.ActivationStatus);
            Row(sb, "Ultima atualizacao", Join(Fmt(inv.Os.LastUpdateInstalled), inv.Os.LastUpdateId));
            Row(sb, "Firmware", Join(inv.Firmware.Manufacturer, inv.Firmware.Version));
            Row(sb, "Data do firmware", Fmt(inv.Firmware.ReleaseDate));
            Row(sb, "Modo de boot", inv.Firmware.FirmwareType);
            Row(sb, "Secure Boot", inv.Firmware.SecureBootState);
            Row(sb, "TPM", inv.Firmware.TpmPresent == true ? "presente, versao " + T.Name(inv.Firmware.TpmVersion, "?") : (inv.Firmware.TpmPresent == false ? "ausente" : null));
            sb.Append("</table></div></div>");

            ChipsetSection(sb, inv, env.CompatibilityReference);

            sb.Append("<div class=\"card\"><h2>Processador e memoria</h2><div class=\"scroll\"><table>");
            Row(sb, "Processador", inv.Cpu.Name);
            Row(sb, "Nucleos / threads", inv.Cpu.PhysicalCores.HasValue && inv.Cpu.LogicalProcessors.HasValue
                ? inv.Cpu.PhysicalCores.Value + " / " + inv.Cpu.LogicalProcessors.Value : null);
            Row(sb, "Clock maximo", inv.Cpu.MaxClockMhz.HasValue ? inv.Cpu.MaxClockMhz.Value + " MHz" : null);
            Row(sb, "Cache L2 / L3", inv.Cpu.L2CacheKb.HasValue || inv.Cpu.L3CacheKb.HasValue
                ? T.Num(inv.Cpu.L2CacheKb) + " KB / " + T.Num(inv.Cpu.L3CacheKb) + " KB" : null);
            Row(sb, "Temperatura", inv.Cpu.TemperatureC.HasValue
                ? T.Num(inv.Cpu.TemperatureC, 1) + " C (" + T.Name(inv.Cpu.TemperatureSource, "?") + ")" : null);
            Row(sb, "Memoria instalada", inv.Memory.InstalledBytes.HasValue ? T.Bytes(inv.Memory.InstalledBytes) : null);
            Row(sb, "Memoria utilizavel", inv.Memory.UsableBytes.HasValue ? T.Bytes(inv.Memory.UsableBytes) : null);
            Row(sb, "Reservada para hardware", inv.Memory.ReservedBytes.HasValue ? T.Bytes(inv.Memory.ReservedBytes) : null);
            Row(sb, "Uso atual", inv.Memory.UsagePercent.HasValue ? T.Num(inv.Memory.UsagePercent, 0) + "%" : null);
            Row(sb, "Configuracao de canais", inv.Memory.ChannelConfiguration);
            sb.Append("</table></div>");

            if (inv.Memory.Modules.Count > 0)
            {
                sb.Append("<h3>Modulos instalados</h3><div class=\"scroll\"><table><thead><tr>");
                sb.Append("<th>Slot</th><th>Capacidade</th><th>Velocidade</th><th>Tipo</th><th>Formato</th><th>Fabricante</th><th>Part number</th></tr></thead><tbody>");
                foreach (MemoryModule mm in inv.Memory.Modules)
                {
                    sb.Append("<tr><td>").Append(Html.Value(mm.Slot)).Append("</td>");
                    sb.Append("<td>").Append(Html.Text(T.Bytes(mm.CapacityBytes))).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(mm.ConfiguredSpeedMhz.HasValue ? mm.ConfiguredSpeedMhz.Value + " MHz" : null)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(mm.MemoryType)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(mm.FormFactor)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(mm.Manufacturer)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(mm.PartNumber)).Append("</td></tr>");
                }
                sb.Append("</tbody></table></div>");
            }
            sb.Append("</div>");

            if (inv.Gpus.Count > 0)
            {
                sb.Append("<div class=\"card\"><h2>Video</h2><div class=\"scroll\"><table><thead><tr>");
                sb.Append("<th>Placa</th><th>Tipo</th><th>VRAM</th><th>Driver</th><th>Data</th><th>Resolucao</th><th>Temp.</th></tr></thead><tbody>");
                foreach (GpuInfo g in inv.Gpus)
                {
                    sb.Append("<tr><td>").Append(Html.Value(g.Name)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(g.Kind)).Append("</td>");
                    sb.Append("<td>").Append(g.VramBytes.HasValue ? Html.Text(T.Bytes(g.VramBytes)) : Html.Value(null)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(g.DriverVersion)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(Fmt(g.DriverDate))).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(g.CurrentHorizontalResolution.HasValue
                        ? g.CurrentHorizontalResolution.Value + " x " + T.Num(g.CurrentVerticalResolution) : null)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(g.TemperatureC.HasValue ? T.Num(g.TemperatureC, 1) + " C" : null)).Append("</td></tr>");
                }
                sb.Append("</tbody></table></div></div>");
            }

            // A tabela de Volumes (inclusive espaco livre critico) tem sua
            // propria condicao, independente do bloco de Discos: a
            // enumeracao de discos fisicos pode falhar enquanto a de
            // volumes logicos funciona, entao os dois blocos nao podem
            // compartilhar o mesmo "if".
            if (inv.Disks.Count > 0)
            {
                sb.Append("<div class=\"card\"><h2>Armazenamento</h2><div class=\"scroll\"><table><thead><tr>");
                sb.Append("<th>Disco</th><th>Tipo</th><th>Interface</th><th>Capacidade</th><th>Saude</th><th>Desgaste</th><th>Horas</th><th>Temp.</th><th>Volumes</th></tr></thead><tbody>");
                foreach (DiskInfo d in inv.Disks)
                {
                    sb.Append("<tr><td>").Append(Html.Value(d.Model)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(d.MediaType)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(d.BusType)).Append("</td>");
                    sb.Append("<td>").Append(Html.Text(T.Bytes(d.SizeBytes))).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(d.HealthStatus)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(d.WearPercent.HasValue ? d.WearPercent.Value + "%" : null)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(d.PowerOnHours.HasValue ? d.PowerOnHours.Value.ToString(CultureInfo.InvariantCulture) : null)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(d.TemperatureC.HasValue ? T.Num(d.TemperatureC, 1) + " C" : null)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(d.VolumeLetters.Count > 0 ? string.Join(", ", d.VolumeLetters.ToArray()) : null)).Append("</td></tr>");
                }
                sb.Append("</tbody></table></div></div>");
            }

            if (inv.Volumes.Count > 0)
            {
                sb.Append("<div class=\"card\"><h3 style=\"margin-top:0\">Volumes</h3><div class=\"scroll\"><table><thead><tr>");
                sb.Append("<th>Unidade</th><th>Rotulo</th><th>Sistema de arquivos</th><th>Tamanho</th><th>Livre</th><th>%</th><th>Disco fisico</th><th>BitLocker</th></tr></thead><tbody>");
                foreach (VolumeInfo v in inv.Volumes)
                {
                    sb.Append("<tr><td>").Append(Html.Value(v.DriveLetter)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(v.Label, "(sem rotulo)")).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(v.FileSystem)).Append("</td>");
                    sb.Append("<td>").Append(Html.Text(T.Bytes(v.SizeBytes))).Append("</td>");
                    sb.Append("<td>").Append(Html.Text(T.Bytes(v.FreeBytes))).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(v.FreePercent.HasValue ? T.Num(v.FreePercent, 1) + "%" : null)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(v.PhysicalDiskIndex.HasValue ? "disco " + v.PhysicalDiskIndex.Value : null)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(v.BitLockerStatus)).Append("</td></tr>");
                }
                sb.Append("</tbody></table></div></div>");
            }

            // O card de Bateria e sempre emitido, mesmo quando inv.Battery
            // e null: o coletor usa null tanto para "desktop sem bateria"
            // quanto para "leitura de bateria falhou num notebook" (WMI
            // degradado, servico parado), e essas duas situacoes precisam
            // aparecer de forma distinguivel no laudo. Machine.IsPortable
            // diferencia as duas ausencias.
            sb.Append("<div class=\"card\"><h2>Bateria</h2>");
            if (inv.Battery != null)
            {
                sb.Append("<div class=\"scroll\"><table>");
                Row(sb, "Modelo", inv.Battery.Name);
                Row(sb, "Carga atual", inv.Battery.ChargePercent.HasValue ? inv.Battery.ChargePercent.Value + "%" : null);
                Row(sb, "Estado", inv.Battery.Status);
                Row(sb, "Capacidade de projeto", inv.Battery.DesignCapacityMwh.HasValue ? inv.Battery.DesignCapacityMwh.Value + " mWh" : null);
                Row(sb, "Capacidade atual", inv.Battery.FullChargeCapacityMwh.HasValue ? inv.Battery.FullChargeCapacityMwh.Value + " mWh" : null);
                Row(sb, "Saude estimada", inv.Battery.HealthPercent.HasValue ? T.Num(inv.Battery.HealthPercent, 1) + "%" : null);
                Row(sb, "Ciclos", inv.Battery.CycleCount.HasValue ? inv.Battery.CycleCount.Value.ToString(CultureInfo.InvariantCulture) : null);
                sb.Append("</table></div>");
            }
            else if (inv.Machine.IsPortable == false)
            {
                sb.Append("<p class=\"muted\">Nao se aplica (equipamento sem bateria).</p>");
            }
            else
            {
                sb.Append("<p class=\"muted\">Nao foi possivel medir (leitura de bateria indisponivel nesta execucao).</p>");
            }
            sb.Append("</div>");

            // Mesmo padrao do bloco de Volumes: a secao de Rede e exibida
            // sempre que houver adaptadores OU uma ConnectivityNote
            // preenchida, para que a observacao sobre o teste de
            // conectividade nao dependa de haver adaptadores enumerados.
            if (inv.Network.Adapters.Count > 0 || inv.Network.ConnectivityNote != null)
            {
                sb.Append("<div class=\"card\"><h2>Rede</h2>");

                if (inv.Network.Adapters.Count > 0)
                {
                    sb.Append("<div class=\"scroll\"><table><thead><tr>");
                    sb.Append("<th>Adaptador</th><th>Tipo</th><th>Estado</th><th>Velocidade</th><th>IPv4</th><th>Gateway</th><th>DNS</th></tr></thead><tbody>");
                    foreach (NetworkAdapterInfo a in inv.Network.Adapters)
                    {
                        sb.Append("<tr><td>").Append(Html.Value(a.Name)).Append("</td>");
                        sb.Append("<td>").Append(Html.Value(a.IsVirtual ? "Virtual (" + T.Name(a.VirtualKind, "?") + ")" : a.InterfaceType)).Append("</td>");
                        sb.Append("<td>").Append(Html.Value(a.Status)).Append("</td>");
                        sb.Append("<td>").Append(Html.Value(a.LinkSpeedBitsPerSecond.HasValue
                            ? (a.LinkSpeedBitsPerSecond.Value / 1000000L) + " Mbps" : null)).Append("</td>");
                        sb.Append("<td>").Append(Html.Value(a.IPv4Addresses.Count > 0 ? string.Join(", ", a.IPv4Addresses.ToArray()) : null)).Append("</td>");
                        sb.Append("<td>").Append(Html.Value(a.Gateways.Count > 0 ? string.Join(", ", a.Gateways.ToArray()) : null)).Append("</td>");
                        sb.Append("<td>").Append(Html.Value(a.DnsServers.Count > 0 ? string.Join(", ", a.DnsServers.ToArray()) : null)).Append("</td></tr>");
                    }
                    sb.Append("</tbody></table></div>");
                }

                if (inv.Network.ConnectivityNote != null)
                    sb.Append("<p class=\"muted\">").Append(Html.Text(inv.Network.ConnectivityNote)).Append("</p>");
                sb.Append("</div>");
            }
        }

        // No modo tecnico o HTML renderiza Seguranca (estado de
        // Defender/firewall/UAC) e Dispositivos com erro (codigo de erro do
        // Gerenciador de Dispositivos), alem do que ja e coberto no
        // report.json. Software/Servicos/Startup completos continuam so no
        // JSON (listas potencialmente longas, ja cobertas pelos testes de
        // seguranca correspondentes) - decisao documentada aqui em vez de
        // deixar a ausencia implicita.
        private static void SecurityAndDevices(StringBuilder sb, ReportEnvelope env)
        {
            Model.Inventory inv = env.Inventory;
            if (inv == null) return;

            if (inv.Security != null)
            {
                sb.Append("<div class=\"card\"><h2>Seguranca</h2><div class=\"scroll\"><table>");
                Row(sb, "Defender - protecao em tempo real", Join(inv.Security.DefenderRealtimeProtection, inv.Security.DefenderRealtimeReason));
                Row(sb, "Defender - protecao na nuvem", inv.Security.DefenderCloudProtection);
                Row(sb, "Defender - Tamper Protection", inv.Security.DefenderTamperProtection);
                Row(sb, "Defender - antispyware", inv.Security.DefenderAntispyware);
                Row(sb, "Defender - servico", inv.Security.DefenderServiceState);
                Row(sb, "Firewall (dominio / privada / publica)", Join(Join(inv.Security.FirewallDomain, inv.Security.FirewallPrivate), inv.Security.FirewallPublic));
                Row(sb, "UAC", inv.Security.UacState);
                Row(sb, "SmartScreen", inv.Security.SmartScreenState);
                Row(sb, "BitLocker (unidade de sistema)", inv.Security.BitLockerSystemDrive);
                Row(sb, "Conta Convidado", inv.Security.GuestAccountEnabled.HasValue ? (inv.Security.GuestAccountEnabled.Value ? "habilitada" : "desabilitada") : null);
                Row(sb, "Administrador embutido", inv.Security.BuiltinAdminEnabled.HasValue ? (inv.Security.BuiltinAdminEnabled.Value ? "habilitado" : "desabilitado") : null);

                if (inv.Security.AntivirusProducts.Count > 0)
                {
                    List<string> avs = new List<string>();
                    foreach (AntivirusProduct av in inv.Security.AntivirusProducts)
                        avs.Add((av.Name ?? "?") + (av.IsEnabled.HasValue ? (av.IsEnabled.Value ? " (ativo)" : " (inativo)") : ""));
                    Row(sb, "Antivirus detectados", string.Join(", ", avs.ToArray()));
                }

                sb.Append("</table></div></div>");
            }

            List<DeviceInfo> withErrors = new List<DeviceInfo>();
            foreach (DeviceInfo d in inv.Devices)
                if (d.ProblemCode.HasValue && d.ProblemCode.Value != 0) withErrors.Add(d);

            if (withErrors.Count > 0)
            {
                sb.Append("<div class=\"card\"><h2>Dispositivos com erro</h2><div class=\"scroll\"><table><thead><tr>");
                sb.Append("<th>Dispositivo</th><th>Classe</th><th>Codigo</th><th>Significado</th></tr></thead><tbody>");
                foreach (DeviceInfo d in withErrors)
                {
                    sb.Append("<tr><td>").Append(Html.Value(d.Name)).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(d.Class)).Append("</td>");
                    sb.Append("<td>").Append(d.ProblemCode.Value).Append("</td>");
                    sb.Append("<td>").Append(Html.Value(d.ProblemMeaning)).Append("</td></tr>");
                }
                sb.Append("</tbody></table></div></div>");
            }
        }

        private static void Inconsistencies(StringBuilder sb, ReportEnvelope env)
        {
            sb.Append("<div class=\"card\"><h2>Divergencias entre fontes</h2>");

            if (env.Inconsistencies == null || env.Inconsistencies.Count == 0)
            {
                sb.Append("<p class=\"muted\">Todas as informacoes lidas de mais de uma fonte independente foram consistentes entre si.</p></div>");
                return;
            }

            sb.Append("<p class=\"muted\">Onde a ferramenta le o mesmo dado por caminhos diferentes e os resultados nao batem, as duas leituras sao mostradas em vez de uma ser escolhida silenciosamente.</p>");

            foreach (Inconsistency i in env.Inconsistencies)
            {
                sb.Append("<div class=\"finding warn\"><div class=\"t\">").Append(Html.Text(i.Subject)).Append("</div>");
                sb.Append("<div class=\"r\">").Append(Html.Text(i.Explanation)).Append("</div>");
                EvidenceBlock(sb, i.Readings);
                sb.Append("</div>");
            }
            sb.Append("</div>");
        }

        private static void AllTests(StringBuilder sb, ReportEnvelope env)
        {
            sb.Append("<div class=\"card\"><h2>Todos os testes executados</h2><div class=\"scroll\"><table><thead><tr>");
            sb.Append("<th>ID</th><th>Teste</th><th>Area</th><th>Status</th><th>Sev.</th><th>Conf.</th><th>Resultado</th></tr></thead><tbody>");

            foreach (TestResult t in env.Tests)
            {
                sb.Append("<tr><td><span class=\"id\">").Append(Html.Text(t.Id)).Append("</span></td>");
                sb.Append("<td>").Append(Html.Text(t.Name)).Append("</td>");
                sb.Append("<td>").Append(Html.Text(t.Category)).Append("</td>");
                sb.Append("<td>").Append(Badge(t.Status)).Append("</td>");
                sb.Append("<td>").Append(t.Severity == Severity.None ? "-" : Html.Text(t.Severity.ToString())).Append("</td>");
                sb.Append("<td>").Append(t.Confidence > 0 ? t.Confidence + "%" : "-").Append("</td>");
                sb.Append("<td>").Append(Html.Text(t.WasExecuted ? t.Result : T.Name(t.NotTestedReason, t.Result))).Append("</td></tr>");
            }

            sb.Append("</tbody></table></div></div>");
        }

        // Versao compacta da tabela de Coverage, usada no modo cliente. So
        // aparece quando ha algo a avisar - um scan sem falha de modulo nao
        // ganha secao extra nenhuma.
        private static void ModuleFailureSummary(StringBuilder sb, ReportEnvelope env)
        {
            if (env.Modules == null) return;

            List<string> failed = new List<string>();
            foreach (ModuleOutcome m in env.Modules)
            {
                if (m.TimedOut) failed.Add(Html.Text(m.Module) + " (tempo esgotado)");
                else if (!m.Succeeded) failed.Add(Html.Text(m.Module) + " (falhou)");
            }

            if (failed.Count == 0) return;

            sb.Append("<div class=\"card\"><h2>Areas nao verificadas nesta execucao</h2>");
            sb.Append("<p class=\"muted\">").Append(failed.Count)
              .Append(" modulo(s) de coleta nao completaram: os testes dessas areas aparecem como nao testados no restante do laudo.</p>");
            sb.Append("<p>");
            for (int i = 0; i < failed.Count; i++)
            {
                if (i > 0) sb.Append(", ");
                sb.Append("<span class=\"tag\">").Append(failed[i]).Append("</span>");
            }
            sb.Append("</p></div>");
        }

        private static void Coverage(StringBuilder sb, ReportEnvelope env)
        {
            sb.Append("<div class=\"card\"><h2>Modulos de coleta</h2><div class=\"scroll\"><table><thead><tr>");
            sb.Append("<th>Modulo</th><th>Resultado</th><th>Duracao</th><th>Detalhe</th></tr></thead><tbody>");

            foreach (ModuleOutcome m in env.Modules)
            {
                string status = m.TimedOut ? "TIMEOUT" : (m.Succeeded ? "OK" : "FALHA");
                string cls = m.Succeeded ? "b-pass" : (m.TimedOut ? "b-warn" : "b-err");
                sb.Append("<tr><td>").Append(Html.Text(m.Module)).Append("</td>");
                sb.Append("<td><span class=\"badge ").Append(cls).Append("\">").Append(status).Append("</span></td>");
                sb.Append("<td>").Append(m.DurationMs).Append(" ms</td>");
                sb.Append("<td>").Append(Html.Value(m.Error, "-")).Append("</td></tr>");
            }

            sb.Append("</tbody></table></div>");
            sb.Append("<p class=\"muted\">Modulo que falha ou estoura o tempo limite nao interrompe o diagnostico: os demais continuam, e o que nao foi medido aparece como nao testado nos resultados.</p></div>");
        }

        private static void Foot(StringBuilder sb, ReportEnvelope env)
        {
            sb.Append("<div class=\"card\"><h2>Sobre este laudo</h2><p class=\"muted\">");
            sb.Append("Gerado por PC Diagnostic Engine v").Append(Html.Text(env.Metadata.ToolVersion));
            sb.Append(" (schema ").Append(env.Metadata.SchemaVersion).Append(", regras ").Append(Html.Text(env.Metadata.RulesVersion)).Append("). ");
            sb.Append("Este laudo cobre as areas verificadas pelos ").Append(env.Tests.Count).Append(" testes listados. ");
            sb.Append("A ausencia de achado de seguranca significa que <b>nenhum indicador suspeito foi encontrado nas areas analisadas</b> - nao equivale a garantia de que o equipamento esta livre de malware. ");
            sb.Append("Os dados brutos completos estao no arquivo <code>report.json</code> ao lado deste documento.");
            sb.Append("</p></div></div></body></html>");
        }

        // ---------- utilitarios ----------

        private static void Row(StringBuilder sb, string label, object value)
        {
            sb.Append("<tr><th style=\"width:230px\">").Append(Html.Text(label)).Append("</th><td>");
            sb.Append(Html.Value(value)).Append("</td></tr>");
        }

        private static string Join(object a, object b)
        {
            string sa = a == null ? null : a.ToString();
            string sb2 = b == null ? null : b.ToString();
            if (string.IsNullOrEmpty(sa)) return sb2;
            if (string.IsNullOrEmpty(sb2)) return sa;
            return sa + " " + sb2;
        }

        private static string Fmt(DateTime? d)
        {
            if (!d.HasValue) return null;
            return d.Value.ToString("dd/MM/yyyy", CultureInfo.InvariantCulture);
        }

        private static int Rank(TestResult t)
        {
            if (t.Status == TestStatus.Critical) return 100;
            if (t.Status == TestStatus.Error) return 50 + (int)t.Severity;
            if (t.Status == TestStatus.Warning) return 20 + (int)t.Severity;
            return 0;
        }

        public static string Badge(TestStatus s)
        {
            switch (s)
            {
                case TestStatus.Pass: return "<span class=\"badge b-pass\">OK</span>";
                case TestStatus.Info: return "<span class=\"badge b-info\">INFO</span>";
                case TestStatus.Warning: return "<span class=\"badge b-warn\">ATENCAO</span>";
                case TestStatus.Error: return "<span class=\"badge b-err\">ERRO</span>";
                case TestStatus.Critical: return "<span class=\"badge b-crit\">CRITICO</span>";
                case TestStatus.RequiresAdmin: return "<span class=\"badge b-skip\">REQUER ADMIN</span>";
                case TestStatus.NotTested: return "<span class=\"badge b-skip\">NAO TESTADO</span>";
                case TestStatus.NotApplicable: return "<span class=\"badge b-skip\">NAO SE APLICA</span>";
                default: return "<span class=\"badge b-skip\">INCONCLUSIVO</span>";
            }
        }
    }
}
