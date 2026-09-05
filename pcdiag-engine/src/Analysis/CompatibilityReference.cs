using PcDiag.Model;

namespace PcDiag.Analysis
{
    // Banco de compatibilidade de hardware. Secao SEPARADA e PARALELA a Inventory, nunca
    // misturada com ela: todo campo de Inventory e dado MEDIDO no
    // equipamento (comentario no topo de Model/Inventory.cs - "null
    // significa exatamente 'nao foi possivel obter'"), e aqui e o oposto -
    // tabela de referencia de fabricante (Model/ChipsetDatabase.cs), sem
    // NENHUMA medicao. Colocar isso dentro de Inventory quebraria essa
    // garantia; por isso mora numa classe propria, com o flag de fonte no
    // nivel da SECAO inteira (Source), nao por campo - simples de nunca
    // esquecer de rotular um campo novo, e impossivel de confundir
    // visualmente com dado medido no relatorio (report.json e report.html
    // usam os MESMOS campos desta classe, sem duplicar a tabela em outro
    // lugar - mesmo principio de "servidor nao reaplica limiar nenhum" que
    // ARQUITETURA.md 10 documenta para o dashboard).
    //
    // Chipset nao identificado ou nao catalogado = Available=false com
    // UnavailableReason preenchido, nunca um campo vazio silencioso -
    // mesmo padrao de NotTestedReason em TestResult.
    public sealed class CompatibilityReference
    {
        public const string ReferenceSourceLabel =
            "Tabela de referencia interna do PC Diagnostic Engine (chipset -> especificacoes de fabricante) - nao lida do equipamento.";

        public bool Available { get; set; }
        public string Source { get; set; }
        public string ChipsetName { get; set; }
        public string Socket { get; set; }
        public string CpuGenerations { get; set; }
        public string ChipsetPcieGeneration { get; set; }
        public string RaidSupport { get; set; }
        public string Notes { get; set; }
        public string UnavailableReason { get; set; }

        public static CompatibilityReference Build(Inventory inv)
        {
            CompatibilityReference r = new CompatibilityReference();
            r.Source = ReferenceSourceLabel;

            if (inv == null || inv.Chipset == null)
            {
                r.UnavailableReason = (inv != null && inv.ChipsetUnavailableReason != null)
                    ? inv.ChipsetUnavailableReason
                    : "Chipset nao identificado nesta maquina.";
                return r;
            }

            r.ChipsetName = inv.Chipset.Name;

            if (inv.Chipset.Name == null)
            {
                r.UnavailableReason = "Chipset " + T.Name(inv.Chipset.Vendor, "?") + " (PCI " +
                    T.Name(inv.Chipset.VendorId, "?") + ":" + T.Name(inv.Chipset.DeviceId, "?") +
                    ") identificado, mas o ID nao esta catalogado na tabela de referencia interna - " +
                    "nenhuma especificacao pode ser afirmada sem risco de palpite.";
                return r;
            }

            ChipsetCompatibilitySpec spec = ChipsetDatabase.LookupCompatibility(inv.Chipset.Name);
            if (spec == null)
            {
                r.UnavailableReason = "Chipset '" + inv.Chipset.Name +
                    "' identificado, mas ainda sem especificacoes de compatibilidade cadastradas na tabela de referencia interna.";
                return r;
            }

            r.Available = true;
            r.Socket = spec.Socket;
            r.CpuGenerations = spec.CpuGenerations;
            r.ChipsetPcieGeneration = spec.ChipsetPcieGeneration;
            r.RaidSupport = spec.RaidSupport;
            r.Notes = spec.Notes;
            return r;
        }
    }
}
