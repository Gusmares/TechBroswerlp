using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PcDiag.Analysis;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Reporting
{
    // Envelope serializado como report.json.
    //
    // A ordem das propriedades e a ordem de declaracao (o serializador ordena
    // por MetadataToken), entao dois scans da mesma maquina produzem arquivos
    // comparaveis linha a linha.
    public sealed class ReportEnvelope
    {
        public ReportMetadata Metadata { get; set; }
        public ExecutiveSummary Summary { get; set; }
        public List<ComponentHealth> ComponentHealth { get; set; }
        public List<Correlation> Correlations { get; set; }
        public List<Inconsistency> Inconsistencies { get; set; }
        public List<TestResult> Tests { get; set; }
        public List<ModuleOutcome> Modules { get; set; }
        public ComparisonResult Comparison { get; set; }
        public Inventory Inventory { get; set; }

        // Referencia de compatibilidade de hardware - secao separada e
        // paralela a Inventory (dado medido). Ver comentario completo em
        // Analysis/CompatibilityReference.cs.
        public CompatibilityReference CompatibilityReference { get; set; }
        public Dictionary<string, string> Fingerprint { get; set; }

        public static ReportEnvelope From(DiagnosticReport report, ComparisonResult comparison)
        {
            ReportEnvelope e = new ReportEnvelope();
            e.Metadata = report.Metadata;
            e.Summary = report.Summary;
            e.ComponentHealth = report.ComponentHealth;
            e.Correlations = report.Correlations;
            e.Inconsistencies = report.Inconsistencies;
            e.Tests = report.Tests;
            e.Modules = report.Modules;
            e.Comparison = comparison;
            e.Inventory = report.Inventory;
            e.CompatibilityReference = report.CompatibilityReference;
            // Qualificado: a propriedade Comparison desta classe esconderia o
            // nome do tipo estatico PcDiag.Reporting.Comparison.
            e.Fingerprint = PcDiag.Reporting.Comparison.Fingerprint(report);
            return e;
        }
    }

    public static class JsonReport
    {
        // UTF-8 SEM BOM. O coletor antigo gravava com BOM (Out-File -Encoding
        // UTF8 no PowerShell 5.1 sempre adiciona), o que quebra parsers
        // estritos do outro lado.
        public static string Write(string path, ReportEnvelope envelope, bool privacySafe)
        {
            string json = JsonWriter.Serialize(envelope, privacySafe, true);
            File.WriteAllText(path, json, new UTF8Encoding(false));
            return json;
        }
    }
}
