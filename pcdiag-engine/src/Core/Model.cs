using System;
using System.Collections.Generic;

namespace PcDiag.Core
{
    // Estados padronizados (item 43 do briefing). A distincao entre
    // NotTested/RequiresAdmin/Unknown/NotApplicable e o antidoto contra o
    // defeito estrutural do coletor antigo, onde "nao consegui medir" era
    // apresentado como "esta tudo bem".
    public enum TestStatus
    {
        Pass,
        Info,
        Warning,
        Error,
        Critical,
        NotTested,
        NotApplicable,
        Unknown,
        RequiresAdmin
    }

    public enum Severity
    {
        None,
        Low,
        Medium,
        High,
        Critical
    }

    // Pre-requisito de um teste. Se nao for satisfeito, o teste devolve
    // NotTested/RequiresAdmin COM motivo - nunca Pass.
    public enum Requirement
    {
        None,
        Admin,
        Sensors,
        Network,
        StressConsent
    }

    // Classificacao de privacidade (item 40). Usada pelo serializador para
    // mascarar campos no modo privacy-safe.
    public enum DataClass
    {
        Public,
        SensitiveSystem,
        Personal
    }

    // ScanMode.Repair ainda nao foi implementado (nenhum caminho de codigo
    // le, seta ou trata esse valor alem do proprio enum). ScanOptions.Mode
    // so pode ser Diagnostic ate o modo repair ser implementado de verdade
    // (flag --repair, confirmacao por acao e re-verificacao pos-acao).
    public enum ScanMode
    {
        Diagnostic
    }

    public enum SupportLevel
    {
        Supported,
        PartiallySupported,
        Unsupported
    }

    // Marca uma propriedade como dado sensivel. No modo privacy-safe o
    // serializador substitui o valor pela mascara em vez de omitir a chave -
    // assim o relatorio continua mostrando que o dado existe.
    [AttributeUsage(AttributeTargets.Property)]
    public sealed class SensitiveAttribute : Attribute
    {
        private readonly DataClass _dataClass;

        public SensitiveAttribute(DataClass dataClass)
        {
            _dataClass = dataClass;
        }

        public DataClass Class { get { return _dataClass; } }
    }

    // Evidencia bruta: de onde o dado veio e o que exatamente foi lido.
    // Toda afirmacao do relatorio precisa poder ser rastreada ate uma destas.
    public sealed class Evidence
    {
        public Evidence()
        {
        }

        public Evidence(string source, string query, string value)
        {
            Source = source;
            Query = query;
            Value = value;
        }

        public string Source { get; set; } // ex: "WMI", "Registry", "Native", "EventLog"
        public string Query { get; set; }  // ex: "Win32_PhysicalDisk.HealthStatus"

        // Value e o dado bruto exatamente como veio da fonte (serial,
        // hostname, IP, etc.). Marcado como sensivel para que Redaction.Apply
        // e JsonWriter mascarem o valor bruto em --privacy-safe, ja que
        // Evidence vive dentro de TestResult (nao do Inventory) e por isso
        // fica fora do alcance de outras varreduras de mascaramento.
        [Sensitive(DataClass.SensitiveSystem)]
        public string Value { get; set; }  // valor bruto, como veio

        public static Evidence Of(string source, string query, object value)
        {
            return new Evidence(source, query, value == null ? "(null)" : value.ToString());
        }
    }

    // Contrato de resultado de teste (item 42).
    public sealed class TestResult
    {
        public TestResult()
        {
            Evidence = new List<Evidence>();
            Severity = Severity.None;
            Confidence = 0;
        }

        public string Id { get; set; }
        public string Name { get; set; }
        public string Category { get; set; }
        public string Description { get; set; }
        public Requirement Requires { get; set; }
        public TestStatus Status { get; set; }
        public Severity Severity { get; set; }
        public string Result { get; set; }
        public string Recommendation { get; set; }
        public int Confidence { get; set; }
        public long DurationMs { get; set; }
        public string NotTestedReason { get; set; }
        public List<Evidence> Evidence { get; set; }

        public bool IsProblem
        {
            get
            {
                return Status == TestStatus.Warning
                    || Status == TestStatus.Error
                    || Status == TestStatus.Critical;
            }
        }

        // Unknown fica de fora, junto com NotTested/RequiresAdmin/
        // NotApplicable: nenhum desses estados representa um veredito real,
        // e o HTML usa WasExecuted para decidir se mostra o motivo de nao
        // ter medido.
        public bool WasExecuted
        {
            get
            {
                return Status != TestStatus.NotTested
                    && Status != TestStatus.RequiresAdmin
                    && Status != TestStatus.NotApplicable
                    && Status != TestStatus.Unknown;
            }
        }
    }

    // Divergencia entre fontes independentes (item 46). Nunca e escondida:
    // vira uma linha propria no relatorio e derruba a confianca do fato.
    public sealed class Inconsistency
    {
        public Inconsistency()
        {
            Readings = new List<Evidence>();
        }

        public string Subject { get; set; }
        public string Explanation { get; set; }
        public Severity Severity { get; set; }
        public List<Evidence> Readings { get; set; }
    }

    // Cadeia sintoma -> evidencia -> causa provavel (item 56). Uma correlacao
    // so e emitida quando ha evidencia; nunca ha causa sem lastro.
    public sealed class Correlation
    {
        public Correlation()
        {
            Evidence = new List<Evidence>();
            RelatedTestIds = new List<string>();
        }

        public string Symptom { get; set; }
        public string LikelyCause { get; set; }
        public string Recommendation { get; set; }
        public int Confidence { get; set; }
        public Severity Severity { get; set; }
        public List<Evidence> Evidence { get; set; }
        public List<string> RelatedTestIds { get; set; }
    }

    // Resultado de um modulo (collector) executado sob timeout/isolamento.
    public sealed class ModuleOutcome
    {
        public ModuleOutcome()
        {
            Evidence = new List<Evidence>();
            FailedQueries = new List<string>();
        }

        public string Module { get; set; }
        public bool Succeeded { get; set; }
        public bool TimedOut { get; set; }
        public string Error { get; set; }
        public long DurationMs { get; set; }
        public List<Evidence> Evidence { get; set; }

        // Succeeded=true so significa que o modulo nao lancou nem estourou o
        // timeout - nao que TODAS as leituras dentro dele funcionaram.
        // Try.Get/Try.Do devem incrementar estes campos a cada leitura
        // individual que falhar dentro de um modulo bem sucedido, para o
        // metadata do relatorio refletir corretamente falhas parciais.
        public int FailedReads { get; set; }
        public List<string> FailedQueries { get; set; }
    }

    // Saude agregada de um componente, para as barras do relatorio (item 55).
    //
    // Score e Coverage sao coisas DIFERENTES e ambas precisam aparecer: uma
    // area onde nada pode ser medido tem score 100 (nada foi descontado) mas
    // cobertura 0 - e mostrar so o score pintaria de verde uma area que nunca
    // foi verificada.
    public sealed class ComponentHealth
    {
        public string Component { get; set; }
        public int Score { get; set; }
        public TestStatus Status { get; set; }
        public string Summary { get; set; }
        public int TestsPassed { get; set; }
        public int TestsProblem { get; set; }
        public int TestsNotExecuted { get; set; }
        public int TestsNotApplicable { get; set; }

        // Fracao dos testes aplicaveis que realmente rodaram (0 a 100).
        public int CoveragePercent { get; set; }

        // True quando nao ha nada a medir nesta maquina (bateria em desktop),
        // que e diferente de "nao consegui medir".
        public bool EntirelyNotApplicable { get; set; }
    }
}
