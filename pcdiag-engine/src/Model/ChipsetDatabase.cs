using System;
using System.Collections.Generic;

namespace PcDiag.Model
{
    // Especificacoes de REFERENCIA de um chipset (banco de
    // compatibilidade). Nada aqui e medido no
    // equipamento: e dado de fabricante, curado a mao e embutido no binario,
    // exatamente como ChipsetDatabase (identidade, logo abaixo) traduz um
    // PCI Device ID em nome. Quem consome (Reporting/HtmlReport.cs,
    // Analysis/Engine.cs) e obrigado a rotular toda linha vinda daqui com
    // "fonte: tabela de referencia interna, nao lida do equipamento" -
    // nunca misturado visualmente com Inventory (dado medido). Ver a secao
    // separada CompatibilityReference em Analysis/Engine.cs.
    public sealed class ChipsetCompatibilitySpec
    {
        public string Socket { get; set; }
        public string CpuGenerations { get; set; }
        public string ChipsetPcieGeneration { get; set; }
        public string RaidSupport { get; set; }
        public string Notes { get; set; }
    }

    // Tabelas curadas de chipset: identidade (PCI Vendor/Device ID -> nome)
    // e compatibilidade de referencia (nome -> especificacoes de fabricante).
    //
    // PROVENIENCIA (para quem for expandir esta tabela depois): os Device ID
    // da parte de identidade foram conferidos um a um contra a base publica
    // PCI ID Repository (pci-ids.ucw.cz, mantida pelo mesmo projeto do
    // pciutils/lspci do Linux) e paginas de driver que citam o ID exato no
    // titulo (ex.: "PCI\VEN_8086&DEV_A305 - Z390 Chipset LPC/eSPI
    // Controller"). NENHUM valor aqui foi digitado de memoria - o risco de
    // errar um digito hexadecimal e real e um erro assim e pior que "nao
    // determinavel" (leva o tecnico a confiar num nome errado), entao cada
    // entrada exige uma fonte com o ID por escrito, nao inferencia.
    //
    // A tabela e DELIBERADAMENTE incompleta - cobre os chipsets desktop mais
    // comuns da Intel (100 a 700 series) e o essencial da AMD, nao a lista
    // inteira de SKUs ja lancados. Um ID fora da tabela devolve null e o
    // chamador (ChipsetCollector/CompatibilityReference) trata isso como
    // "nao determinavel", nunca um palpite - mesmo principio de
    // Native.ProblemCodeMeaning para codigos de erro nao catalogados.
    public static class ChipsetDatabase
    {
        // ================= Parte 1: identidade =================

        // Intel: controlador LPC/eSPI (a "ponte ISA/LPC" classica), classe
        // PCI 0601, sempre VEN_8086. Ao contrario da AMD (ver abaixo), a
        // Intel usa um Device ID DIFERENTE por SKU de chipset dentro da
        // mesma geracao (Z390 != H370 != B360, embora os tres sejam "300
        // series") - entao aqui da para reivindicar o nome exato do
        // chipset, nao so a geracao.
        private static readonly Dictionary<string, string> IntelPch = BuildIntelPch();

        private static Dictionary<string, string> BuildIntelPch()
        {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            // 100 series (Skylake, LGA1151 primeira geracao)
            d["A143"] = "Intel H110";
            d["A145"] = "Intel Z170";

            // 200 series (Kaby Lake, mesmo LGA1151)
            d["A2C5"] = "Intel Z270";

            // 300 series (Coffee Lake 8a/9a geracao, LGA1151 segunda geracao -
            // fisicamente igual ao anterior, eletricamente incompativel)
            d["A303"] = "Intel H310";
            d["A304"] = "Intel H370";
            d["A305"] = "Intel Z390";
            d["A308"] = "Intel B360";

            // 400 series (Comet Lake 10a geracao, LGA1200)
            d["0684"] = "Intel H470";
            d["0685"] = "Intel Z490";
            d["0687"] = "Intel Q470";
            d["0697"] = "Intel W480";
            d["A3C8"] = "Intel B460";
            d["A3DA"] = "Intel H410";

            // 500 series (Rocket Lake 11a geracao, mesmo LGA1200)
            d["4385"] = "Intel Z590";
            d["4387"] = "Intel B560";
            d["4388"] = "Intel H510";

            // 600 series (Alder Lake 12a/13a geracao, LGA1700)
            d["7A84"] = "Intel Z690";
            d["7A86"] = "Intel B660";
            d["7A87"] = "Intel H610";

            // 700 series (Raptor Lake 13a/14a geracao, mesmo LGA1700 - varios
            // SKUs 700 series reaproveitam o MESMO die/ID do 600 series
            // equivalente, entao esta tabela so cobre o unico ID de 700
            // series com fonte direta e inequivoca)
            d["7A06"] = "Intel B760";

            return d;
        }

        // AMD: diferente da Intel, a ponte LPC da FCH ("PCI\VEN_1022&DEV_
        // 780E" ou "...790E", classe 0601) e COMPARTILHADA por varios SKUs
        // da MESMA geracao - A320, B350, X370, B450 e X470 relatam
        // literalmente o mesmo Device ID de ponte LPC, porque todos usam a
        // mesma silica FCH ("Promontory"/"Bolton"), so com recursos
        // habilitados/desabilitados por firmware da placa-mae. Confirmado
        // por um relato tecnico da propria equipe do AIDA64 (forum de bugs:
        // "AMD Chipset Identification Problems inside Physical Devices and
        // PCI Devices Pages") - o AIDA64 tinha exatamente esse problema e a
        // correcao proposta la e a mesma usada aqui: o controlador USB XHCI
        // da FCH (classe PCI 0C03) tem um Device ID especifico por SKU onde
        // a ponte LPC nao distingue. Por isso a identificacao de AMD e em
        // DUAS tabelas:
        //  - AmdFchGeneration: fallback generico por geracao de FCH (ponte
        //    LPC, classe 0601) - sempre disponivel, mas so diz a "familia".
        //  - AmdSkuByXhci: quando o controlador USB XHCI (classe 0C03) esta
        //    presente e catalogado, sobrescreve o nome generico por um SKU
        //    especifico.
        private static readonly Dictionary<string, string> AmdFchGeneration = BuildAmdFchGeneration();
        private static readonly Dictionary<string, string> AmdSkuByXhci = BuildAmdSkuByXhci();

        private static Dictionary<string, string> BuildAmdFchGeneration()
        {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            d["780E"] = "AMD FCH (geracao AM4 inicial - series A320/B350/X370/B450/X470)";
            d["790E"] = "AMD FCH (geracao AM4 mais recente - series A520/B550/X570, ou AM5)";
            return d;
        }

        private static Dictionary<string, string> BuildAmdSkuByXhci()
        {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            // Fonte: relato tecnico no forum de bugs do AIDA64 (ver
            // comentario acima) para X470/B450/B550/A520; X370 confirmado
            // separadamente por uma pagina de driver com o ID no titulo
            // ("X370 Series Chipset USB 3.1 xHCI Controller"). X570 NAO
            // entra aqui - o chip adicional do X570 (fora da FCH, ligado por
            // PCIe x4) nao teve um ID confirmado por fonte direta; fica no
            // fallback generico "790E" acima em vez de arriscar um ID errado.
            d["43B9"] = "AMD X370";
            d["43D0"] = "AMD X470";
            d["43D5"] = "AMD B450";
            d["43EE"] = "AMD B550";
            d["43EC"] = "AMD A520";
            return d;
        }

        public static string LookupIntelPch(string deviceId)
        {
            string name;
            if (deviceId != null && IntelPch.TryGetValue(deviceId, out name)) return name;
            return null;
        }

        public static string LookupAmdFchGeneration(string deviceId)
        {
            string name;
            if (deviceId != null && AmdFchGeneration.TryGetValue(deviceId, out name)) return name;
            return null;
        }

        public static string LookupAmdSkuByXhci(string deviceId)
        {
            string name;
            if (deviceId != null && AmdSkuByXhci.TryGetValue(deviceId, out name)) return name;
            return null;
        }

        // ================= Parte 3: compatibilidade de referencia =================
        //
        // Fatos de geracao de chipset amplamente documentados pelos proprios
        // fabricantes (encaixe, geracoes de CPU suportadas, geracao de PCIe
        // que SAI DO CHIPSET - nao das lanes diretas da CPU - e suporte a
        // RAID via controlador SATA integrado). Deliberadamente NAO inclui
        // "RAM maxima": isso e limite do controlador de memoria da CPU e do
        // projeto da placa-mae, no chipset em si - incluir um numero aqui
        // seria proprio o palpite que este banco existe para evitar.
        //
        // Agrupado por GERACAO (varios nomes de chipset apontam para o
        // MESMO objeto Spec) porque socket/geracao de CPU/PCIe do chipset
        // sao identicos dentro de uma geracao - RAID e o unico campo que
        // varia por SKU dentro do grupo, e isso fica explicito em Notes.
        private static readonly Dictionary<string, ChipsetCompatibilitySpec> Compatibility = BuildCompatibility();

        private static ChipsetCompatibilitySpec Spec(string socket, string cpuGen, string pcie, string raid, string notes)
        {
            ChipsetCompatibilitySpec s = new ChipsetCompatibilitySpec();
            s.Socket = socket;
            s.CpuGenerations = cpuGen;
            s.ChipsetPcieGeneration = pcie;
            s.RaidSupport = raid;
            s.Notes = notes;
            return s;
        }

        private static Dictionary<string, ChipsetCompatibilitySpec> BuildCompatibility()
        {
            Dictionary<string, ChipsetCompatibilitySpec> d = new Dictionary<string, ChipsetCompatibilitySpec>(StringComparer.Ordinal);

            ChipsetCompatibilitySpec intel100_200 = Spec(
                "LGA1151 (primeira geracao)",
                "6a e 7a geracao Intel Core (Skylake/Kaby Lake) - conferir na placa, alguns fabricantes nao liberaram suporte a 7a geracao via BIOS",
                "PCIe 3.0",
                "Intel RST 0/1/5/10 nos SKUs Z e H mais completos (Z170/Z270/H170/H270); B150/H110/B250 tipicamente sem RAID",
                "Series 100 e 200 compartilham o mesmo encaixe fisico e eletrico.");
            d["Intel H110"] = intel100_200;
            d["Intel Z170"] = intel100_200;
            d["Intel Z270"] = intel100_200;

            ChipsetCompatibilitySpec intel300 = Spec(
                "LGA1151 (segunda geracao - mesmo encaixe fisico do anterior, mas ELETRICAMENTE incompativel com CPU de 6a/7a geracao)",
                "8a e 9a geracao Intel Core (Coffee Lake)",
                "PCIe 3.0",
                "Intel RST 0/1/5/10 em Z390/H370; B360/H310 tipicamente sem RAID",
                null);
            d["Intel H310"] = intel300;
            d["Intel H370"] = intel300;
            d["Intel Z390"] = intel300;
            d["Intel B360"] = intel300;

            ChipsetCompatibilitySpec intel400 = Spec(
                "LGA1200",
                "10a geracao Intel Core (Comet Lake)",
                "PCIe 3.0 (o chipset em si; CPUs de 10a geracao nao expoem PCIe 4.0 nas lanes diretas)",
                "Intel RST 0/1/5/10 em Z490/H470/Q470/W480; B460/H410 tipicamente sem RAID",
                null);
            d["Intel Z490"] = intel400;
            d["Intel H470"] = intel400;
            d["Intel Q470"] = intel400;
            d["Intel W480"] = intel400;
            d["Intel B460"] = intel400;
            d["Intel H410"] = intel400;

            ChipsetCompatibilitySpec intel500 = Spec(
                "LGA1200 (mesmo encaixe da serie 400)",
                "11a geracao nativa (Rocket Lake); 10a geracao compativel via atualizacao de BIOS",
                "PCIe 3.0 (o chipset em si; CPUs de 11a geracao expoem PCIe 4.0 so nas lanes DIRETAS da CPU, nao nas do chipset)",
                "Intel RST 0/1/5/10 em Z590/B560; H510 tipicamente sem RAID",
                null);
            d["Intel Z590"] = intel500;
            d["Intel B560"] = intel500;
            d["Intel H510"] = intel500;

            ChipsetCompatibilitySpec intel600 = Spec(
                "LGA1700",
                "12a e 13a geracao Intel Core (Alder Lake / Raptor Lake)",
                "PCIe 4.0 em Z690/B660; H610 tipicamente PCIe 3.0",
                "Intel RST 0/1/5/10 em Z690/B660; H610 tipicamente sem RAID",
                "A placa-mae (nao o chipset) decide entre memoria DDR4 e DDR5 nesta geracao.");
            d["Intel Z690"] = intel600;
            d["Intel B660"] = intel600;
            d["Intel H610"] = intel600;

            ChipsetCompatibilitySpec intel700 = Spec(
                "LGA1700 (mesmo encaixe da serie 600)",
                "13a e 14a geracao nativa (Raptor Lake / Raptor Lake Refresh); 12a geracao compativel",
                "PCIe 4.0",
                "Intel RST 0/1/5/10",
                "A placa-mae (nao o chipset) decide entre memoria DDR4 e DDR5 nesta geracao.");
            d["Intel B760"] = intel700;

            ChipsetCompatibilitySpec amdSocketAm4Early = Spec(
                "AM4",
                "Ryzen 1000 a 5000, dependendo do SKU e da atualizacao de BIOS - X370/B350/A320 dependem de suporte do fabricante da placa (alguns descontinuaram antes do Ryzen 5000)",
                "PCIe 2.0 (o chipset em si; lanes PCIe 3.0/4.0 quando presentes vem direto da CPU, nao do chipset)",
                "AMD RAIDXpert2 0/1/10 em X370/B350; A320 tipicamente sem RAID",
                null);
            d["AMD X370"] = amdSocketAm4Early;
            d["AMD FCH (geracao AM4 inicial - series A320/B350/X370/B450/X470)"] = amdSocketAm4Early;

            ChipsetCompatibilitySpec amdX470 = Spec(
                "AM4",
                "Ryzen 1000 a 5000, dependendo da atualizacao de BIOS da placa",
                "PCIe 3.0 (o chipset em si; lanes adicionais vem direto da CPU)",
                "AMD RAIDXpert2 0/1/10",
                null);
            d["AMD X470"] = amdX470;

            ChipsetCompatibilitySpec amdB450 = Spec(
                "AM4",
                "Ryzen 1000 a 5000, dependendo da atualizacao de BIOS da placa",
                "PCIe 3.0 (o chipset em si; lanes adicionais vem direto da CPU)",
                "AMD RAIDXpert2 0/1/10",
                null);
            d["AMD B450"] = amdB450;

            ChipsetCompatibilitySpec amdLater = Spec(
                "AM4 (series A520/B550/X570) - PCI ID de FCH nao distingue AM4 tardio de AM5 com confianca, ver Notes",
                "Ryzen 2000 a 5000 em AM4, dependendo do SKU e da placa",
                "PCIe 3.0 em A520/B550; PCIe 4.0 em X570 (chipset com uplink dedicado)",
                "AMD RAIDXpert2 0/1/10 em B550/X570; A520 tipicamente sem RAID",
                "Esta entrada generica so aparece quando o controlador USB XHCI da FCH (mais especifico) nao foi encontrado ou nao esta catalogado - nesse caso nao da para confirmar se e AM4 serie 500 ou AM5, so a familia de FCH.");
            d["AMD FCH (geracao AM4 mais recente - series A520/B550/X570, ou AM5)"] = amdLater;

            ChipsetCompatibilitySpec amdB550 = Spec(
                "AM4",
                "Ryzen 2000 a 5000, dependendo da atualizacao de BIOS da placa",
                "PCIe 3.0 (o chipset em si; a CPU pode expor PCIe 4.0 direto, dependendo do modelo)",
                "AMD RAIDXpert2 0/1/10",
                null);
            d["AMD B550"] = amdB550;

            ChipsetCompatibilitySpec amdA520 = Spec(
                "AM4",
                "Ryzen 2000 a 5000, dependendo da atualizacao de BIOS da placa",
                "PCIe 3.0 (o chipset em si)",
                "Nao suportado neste SKU",
                null);
            d["AMD A520"] = amdA520;

            return d;
        }

        public static ChipsetCompatibilitySpec LookupCompatibility(string chipsetName)
        {
            ChipsetCompatibilitySpec s;
            if (chipsetName != null && Compatibility.TryGetValue(chipsetName, out s)) return s;
            return null;
        }
    }
}
