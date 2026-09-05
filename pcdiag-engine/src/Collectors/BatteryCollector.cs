using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Xml;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    public sealed class BatteryCollector : ICollector
    {
        public string Name { get { return "Battery"; } }

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            Stopwatch sw = Stopwatch.StartNew();

            IList<DataRow> rows = Try.Get(ctx, Name, "Win32_Battery", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT Name, DeviceID, EstimatedChargeRemaining, BatteryStatus, Chemistry, DesignVoltage FROM Win32_Battery");
            });

            if (rows == null || rows.Count == 0)
            {
                // Ausencia de bateria em desktop e NOT_APPLICABLE, nao falha.
                // A distincao e feita pela camada de testes usando IsPortable.
                return;
            }

            BatteryInfo b = new BatteryInfo();
            b.BatteryCount = rows.Count;

            DataRow r = rows[0];
            b.Name = r.Str("Name");

            // EstimatedChargeRemaining precisa de validacao de faixa. O
            // ACPI usa 255 como valor sentinela de "nao disponivel", e sem
            // filtro isso iria parar no laudo como "255%". Fora de 0..100 e
            // leitura invalida, nao um fato.
            int? charge = r.Int("EstimatedChargeRemaining");
            if (charge.HasValue && charge.Value >= 0 && charge.Value <= 100)
                b.ChargePercent = charge.Value;

            b.Status = BatteryStatusName(r.Int("BatteryStatus"));
            b.Chemistry = ChemistryName(r.Int("Chemistry"));

            ulong? mv = r.ULong("DesignVoltage");
            if (mv.HasValue && mv.Value > 0 && mv.Value < 100000) b.VoltageMv = (int)mv.Value;

            // Com mais de uma bateria (notebook com bateria interna +
            // removivel), carga/status/quimica so vem da primeira linha -
            // apresentar isso como se fosse o estado consolidado do
            // equipamento seria enganoso. Sem uma lista por bateria no
            // modelo (fora do escopo deste coletor), o minimo seguro e nao
            // afirmar um numero unico que pode nao representar nenhuma das
            // baterias reais, e deixar isso explicito na origem.
            if (rows.Count > 1)
            {
                b.ChargePercent = null;
                b.Status = null;
                b.HealthSource = "Maquina com " + rows.Count + " baterias detectadas via Win32_Battery; " +
                    "carga/status individuais omitidos porque so a primeira bateria seria representada.";
            }

            inv.Battery = b;

            ReadBatteryReport(ctx, src, b, RemainingBudgetMs(ctx, sw));
        }

        // O timeout do powercfg deriva do que resta do orcamento do modulo
        // (ModuleTimeoutMs), em vez de ser fixo - um valor fixo poderia
        // ultrapassar o orcamento do modulo e deixar o processo filho
        // abandonado quando o Runner desiste do modulo antes do powercfg
        // terminar. Usa um piso minimo para nao matar o processo
        // prematuramente por uma amostra de tempo desfavoravel.
        private static int RemainingBudgetMs(ScanContext ctx, Stopwatch sw)
        {
            int budget = ctx.Options.ModuleTimeoutMs;
            int elapsed = (int)sw.ElapsedMilliseconds;
            int remaining = budget - elapsed;
            if (remaining < 1000) remaining = 1000;
            return Math.Min(20000, remaining);
        }

        // powercfg /batteryreport devolve capacidade de projeto x capacidade
        // atual, que e a unica forma de calcular saude real da bateria.
        //
        // Diferencas em relacao ao coletor antigo:
        //  - nome de arquivo temporario ALEATORIO em diretorio proprio (o
        //    anterior usava um nome fixo e previsivel em %TEMP%);
        //  - soma TODAS as baterias (o anterior lia so a primeira, errando a
        //    saude em notebooks com duas baterias);
        //  - o temporario e removido em finally, inclusive em caso de erro.
        //
        // powercfg /batteryreport so sabe gravar em disco (nao ha modo
        // memoria), o que tensiona a garantia de "somente leitura" quando o
        // destino e o %TEMP% da maquina do
        // cliente. Quando o operador informa --out, essa pasta ja e area de
        // escrita declarada pela propria ferramenta (e onde o laudo final
        // sera gravado), entao usamos um subdiretorio dela em vez do TEMP
        // do sistema. Sem --out, o destino final so e resolvido depois que
        // todos os coletores rodam (Program.ResolveOutputDirectory precisa
        // do Inventory pronto), entao o TEMP continua sendo o unico lugar
        // disponivel neste ponto - residual documentado, nao eliminado.
        private void ReadBatteryReport(ScanContext ctx, SourceSet src, BatteryInfo b, int timeoutMs)
        {
            string baseDir = !string.IsNullOrEmpty(ctx.Options.OutputDirectory)
                ? ctx.Options.OutputDirectory
                : Path.GetTempPath();
            string dir = Path.Combine(baseDir, "PcDiag_" + Guid.NewGuid().ToString("N").Substring(0, 12));
            string file = Path.Combine(dir, "battery.xml");

            try
            {
                Directory.CreateDirectory(dir);

                ProcessResult pr = src.Processes.RunSystem32("powercfg.exe",
                    new string[] { "/batteryreport", "/output", file, "/xml" }, timeoutMs);

                if (!pr.Started || pr.TimedOut || !File.Exists(file))
                {
                    AppendHealthSource(b, pr.FailureReason != null
                        ? "powercfg falhou: " + pr.FailureReason
                        : "powercfg nao gerou o relatorio de bateria");
                    return;
                }

                AppendHealthSource(b, "powercfg /batteryreport");
                ParseBatteryReport(File.ReadAllText(file), b);
            }
            catch (Exception ex)
            {
                // ex.Message pode conter o caminho completo do arquivo/pasta
                // (ex.: UnauthorizedAccessException "Acesso ao caminho
                // 'C:\Users\<usuario>\...' foi negado"), vazando o nome do
                // perfil do usuario para um campo do inventario que vai para
                // o laudo/payload. Grava so o tipo da excecao no campo
                // publicado; a mensagem completa continua disponivel no log
                // tecnico local (ctx.Log), que nao e enviado.
                AppendHealthSource(b, "Falha lendo o relatorio de bateria: " + ex.GetType().Name);
                ctx.Log.Error(Name, ex.Message);
            }
            finally
            {
                try { if (File.Exists(file)) File.Delete(file); } catch { }
                try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
            }
        }

        // Concatena em vez de sobrescrever para nao perder o aviso de
        // multiplas baterias que o Collect() ja pode ter gravado em
        // HealthSource antes de chamar o powercfg.
        private static void AppendHealthSource(BatteryInfo b, string text)
        {
            b.HealthSource = string.IsNullOrEmpty(b.HealthSource) ? text : b.HealthSource + " | " + text;
        }

        // Separado da leitura de arquivo para poder ser testado com um XML
        // fixo, sem depender de hardware nem de executar o powercfg.
        public static void ParseBatteryReport(string xml, BatteryInfo b)
        {
            if (string.IsNullOrEmpty(xml) || b == null) return;

            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null; // nao resolver entidades externas (XXE)
            doc.LoadXml(xml);

            XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("b", "http://schemas.microsoft.com/battery/2012");

            XmlNodeList batteries = doc.SelectNodes("//b:Battery", ns);
            if (batteries == null || batteries.Count == 0) return;

            long designSum = 0, fullSum = 0;
            int cycleMax = 0;
            bool anyDesign = false, anyFull = false, anyCycle = false;

            foreach (XmlNode battery in batteries)
            {
                long v;
                if (TryReadLong(battery, "b:DesignCapacity", ns, out v) && v > 0) { designSum += v; anyDesign = true; }
                if (TryReadLong(battery, "b:FullChargeCapacity", ns, out v) && v > 0) { fullSum += v; anyFull = true; }
                if (TryReadLong(battery, "b:CycleCount", ns, out v) && v > 0)
                {
                    anyCycle = true;
                    if (v > cycleMax) cycleMax = (int)v;
                }
            }

            if (anyDesign) b.DesignCapacityMwh = (int)Math.Min(designSum, int.MaxValue);
            if (anyFull) b.FullChargeCapacityMwh = (int)Math.Min(fullSum, int.MaxValue);
            if (anyCycle) b.CycleCount = cycleMax;

            if (anyDesign && anyFull && designSum > 0)
            {
                double health = (double)fullSum / designSum * 100.0;
                // Acima de 100% acontece em bateria nova/recem-calibrada, e
                // saturar em 100 nesse caso continua correto. Mas quando o
                // excesso e grande (> 105%), isso normalmente indica
                // DesignCapacity subestimada ou publicada em unidade
                // diferente de FullChargeCapacity (ACPI que mistura
                // mAh/mWh) - saturar em silencio produziria um PASS de saude
                // 100% sobre um numero que nao significa saude nenhuma.
                // Nesse caso deixamos HealthPercent null e guardamos os
                // valores brutos em HealthSource para o laudo nao afirmar
                // um fato que os dados nao sustentam.
                if (health > 105.0)
                {
                    b.HealthPercent = null;
                    b.HealthSource = "powercfg /batteryreport: saude nao calculada (razao implausivel " +
                        Math.Round(health, 1).ToString(CultureInfo.InvariantCulture) +
                        "%; DesignCapacity=" + designSum + " FullChargeCapacity=" + fullSum + " brutos, mWh)";
                    return;
                }
                else
                {
                    if (health > 100.0) health = 100.0;
                    b.HealthPercent = Math.Round(health, 1);
                }
            }
        }

        private static bool TryReadLong(XmlNode parent, string xpath, XmlNamespaceManager ns, out long value)
        {
            value = 0;
            XmlNode node = parent.SelectSingleNode(xpath, ns);
            if (node == null) return false;
            string text = node.InnerText;
            if (string.IsNullOrEmpty(text)) return false;
            text = text.Replace(".", "").Replace(",", "").Trim();
            return long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }

        public static string BatteryStatusName(int? code)
        {
            if (!code.HasValue) return null;
            switch (code.Value)
            {
                case 1: return "Descarregando";
                case 2: return "Ligado na tomada (AC)";
                case 3: return "Totalmente carregada";
                case 4: return "Baixa";
                case 5: return "Critica";
                case 6: return "Carregando";
                case 7: return "Carregando (alta)";
                case 8: return "Carregando (baixa)";
                case 9: return "Carregando (critica)";
                case 10: return "Indefinido";
                case 11: return "Parcialmente carregada";
                default: return "Status " + code.Value;
            }
        }

        public static string ChemistryName(int? code)
        {
            if (!code.HasValue) return null;
            switch (code.Value)
            {
                case 1: return "Outra";
                case 2: return "Desconhecida";
                case 3: return "Chumbo-acido";
                case 4: return "Niquel-cadmio";
                case 5: return "Niquel-hidreto metalico";
                case 6: return "Litio-ion";
                case 7: return "Zinco-ar";
                case 8: return "Litio-polimero";
                default: return "Codigo " + code.Value;
            }
        }
    }
}
