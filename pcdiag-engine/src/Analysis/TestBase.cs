using System;
using System.Collections.Generic;
using System.Globalization;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Analysis
{
    // Um teste de diagnostico e uma FUNCAO PURA sobre o inventario.
    //
    // Ele nao acessa o sistema operacional, nao faz consulta WMI, nao le
    // registro. Toda a informacao de que precisa ja foi coletada e normalizada.
    // E isso que permite rodar a suite inteira contra inventarios sinteticos
    // nos testes automatizados, sem hardware e sem privilegio.
    public interface IDiagnosticTest
    {
        string Category { get; }
        IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv);
    }

    public static class T
    {
        public static TestResult Make(string id, string name, string category, string description)
        {
            TestResult r = new TestResult();
            r.Id = id;
            r.Name = name;
            r.Category = category;
            r.Description = description;
            r.Requires = Requirement.None;
            r.Status = TestStatus.Unknown;
            r.Severity = Severity.None;
            return r;
        }

        public static TestResult Pass(TestResult r, string result, int confidence)
        {
            r.Status = TestStatus.Pass;
            r.Severity = Severity.None;
            r.Result = result;
            r.Confidence = confidence;
            return r;
        }

        public static TestResult Info(TestResult r, string result, int confidence)
        {
            r.Status = TestStatus.Info;
            r.Severity = Severity.Low;
            r.Result = result;
            r.Confidence = confidence;
            return r;
        }

        public static TestResult Warn(TestResult r, Severity severity, string result, string recommendation, int confidence)
        {
            r.Status = TestStatus.Warning;
            r.Severity = severity;
            r.Result = result;
            r.Recommendation = recommendation;
            r.Confidence = confidence;
            return r;
        }

        public static TestResult Error(TestResult r, Severity severity, string result, string recommendation, int confidence)
        {
            r.Status = TestStatus.Error;
            r.Severity = severity;
            r.Result = result;
            r.Recommendation = recommendation;
            r.Confidence = confidence;
            return r;
        }

        public static TestResult Critical(TestResult r, string result, string recommendation, int confidence)
        {
            r.Status = TestStatus.Critical;
            r.Severity = Severity.Critical;
            r.Result = result;
            r.Recommendation = recommendation;
            r.Confidence = confidence;
            return r;
        }

        // NotTested EXIGE motivo. Nao existe caminho de codigo que produza um
        // teste nao executado sem explicar por que - esse era o defeito
        // estrutural do coletor anterior.
        public static TestResult NotTested(TestResult r, string reason)
        {
            r.Status = TestStatus.NotTested;
            r.Severity = Severity.None;
            r.NotTestedReason = reason;
            r.Confidence = 0;
            r.Result = "Nao verificado";
            return r;
        }

        public static TestResult RequiresAdmin(TestResult r, string what)
        {
            r.Status = TestStatus.RequiresAdmin;
            r.Requires = Requirement.Admin;
            r.Severity = Severity.None;
            r.NotTestedReason = what + " exige execucao como Administrador.";
            r.Confidence = 0;
            r.Result = "Nao verificado (requer Administrador)";
            return r;
        }

        public static TestResult NotApplicable(TestResult r, string reason)
        {
            r.Status = TestStatus.NotApplicable;
            r.Severity = Severity.None;
            r.NotTestedReason = reason;
            r.Confidence = 0;
            r.Result = "Nao se aplica a este equipamento";
            return r;
        }

        public static TestResult Unknown(TestResult r, string reason)
        {
            r.Status = TestStatus.Unknown;
            r.Severity = Severity.None;
            r.NotTestedReason = reason;
            r.Confidence = 0;
            r.Result = "Resultado inconclusivo";
            return r;
        }

        public static TestResult Ev(TestResult r, string source, string query, object value)
        {
            r.Evidence.Add(Evidence.Of(source, query, value));
            return r;
        }

        // Formatacao para texto de resultado. Fica aqui, e nao no modelo:
        // o inventario guarda numeros, o relatorio e quem formata.
        public static string Bytes(ulong? bytes)
        {
            if (!bytes.HasValue) return "nao disponivel";
            double v = bytes.Value;
            if (v >= 1099511627776.0) return (v / 1099511627776.0).ToString("F2", CultureInfo.InvariantCulture) + " TB";
            if (v >= 1073741824.0) return (v / 1073741824.0).ToString("F2", CultureInfo.InvariantCulture) + " GB";
            if (v >= 1048576.0) return (v / 1048576.0).ToString("F0", CultureInfo.InvariantCulture) + " MB";
            if (v >= 1024.0) return (v / 1024.0).ToString("F0", CultureInfo.InvariantCulture) + " KB";
            return v.ToString("F0", CultureInfo.InvariantCulture) + " bytes";
        }

        public static string Num(double? v, int decimals)
        {
            if (!v.HasValue) return "nao disponivel";
            return v.Value.ToString("F" + decimals, CultureInfo.InvariantCulture);
        }

        public static string Num(int? v)
        {
            if (!v.HasValue) return "nao disponivel";
            return v.Value.ToString(CultureInfo.InvariantCulture);
        }

        public static string Date(DateTime? d)
        {
            if (!d.HasValue) return "nao disponivel";
            return d.Value.ToString("dd/MM/yyyy", CultureInfo.InvariantCulture);
        }

        public static string Name(string s, string fallback)
        {
            return string.IsNullOrEmpty(s) ? fallback : s;
        }
    }
}
