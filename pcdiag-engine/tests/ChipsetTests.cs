using System.Collections.Generic;
using PcDiag.Analysis;
using PcDiag.Collectors;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Testing
{
    // Verificacao de hardware, partes 1 (identidade de chipset via PCI
    // Vendor/Device ID) e 3 (banco de compatibilidade de referencia).
    //
    // ChipsetCollector nao usa SourceSet (nem WMI, nem P/Invoke novo - so
    // varre Inventory.Devices, que outro coletor ja populou), entao estes
    // testes chamam ChipsetCollector.IdentifyChipset(inv) direto sobre um
    // Inventory sintetico, sem precisar de FakeWmi nem de hardware real.
    // O caminho real (dispositivo de verdade -> report.json) foi conferido
    // manualmente rodando bin\PcDiag.exe nesta maquina de desenvolvimento:
    // o chipset real (Intel H410, PCI\VEN_8086&DEV_A3DA) saiu identificado
    // como "Intel H410" - o proprio nome amigavel que o Windows da ao
    // dispositivo ("Intel(R) LPC Controller (H410) - A3DA") confirma a
    // entrada da tabela.
    public static class ChipsetTests
    {
        public static void Run(TestRunner t)
        {
            IntelRecognized(t);
            IntelUnrecognizedIdIsNotAGuess(t);
            AmdGenerationFallback(t);
            AmdSkuViaXhciOverridesGeneration(t);
            NoPciDeviceFound(t);
            NativeSourceUnavailableIsDistinctReason(t);
            WrongClassCodeIsIgnored(t);
            WmiOnlyDeviceWithoutHardwareIdsIsIgnored(t);
            SurvivesNullDevicesList(t);
            CompatibilityReferenceForRecognizedChipset(t);
            CompatibilityReferenceWhenChipsetNotDetermined(t);
            CompatibilityReferenceWhenIdNotCatalogued(t);
            CompatibilityReferenceWhenNameHasNoSpecYet(t);
        }

        // HardwareIds no formato exatamente como Native.GetStringProperty
        // grava (REG_MULTI_SZ juntado com " | ", mais especifico primeiro) -
        // ver Sources/Native.cs e o comentario em Collectors/Base.cs sobre
        // onde o Windows coloca o codigo de classe (CC_ccssp e CC_ccss sao
        // sempre as duas ultimas entradas da lista de HardwareID de um
        // dispositivo PCI).
        private static string IsaLpcHardwareIds(string vendorId, string deviceId)
        {
            return "PCI\\VEN_" + vendorId + "&DEV_" + deviceId + "&SUBSYS_00000000&REV_10 | " +
                   "PCI\\VEN_" + vendorId + "&DEV_" + deviceId + "&SUBSYS_00000000 | " +
                   "PCI\\VEN_" + vendorId + "&DEV_" + deviceId + "&CC_060100 | " +
                   "PCI\\VEN_" + vendorId + "&DEV_" + deviceId + "&CC_0601";
        }

        private static string XhciHardwareIds(string vendorId, string deviceId)
        {
            return "PCI\\VEN_" + vendorId + "&DEV_" + deviceId + "&SUBSYS_00000000&REV_00 | " +
                   "PCI\\VEN_" + vendorId + "&DEV_" + deviceId + "&SUBSYS_00000000 | " +
                   "PCI\\VEN_" + vendorId + "&DEV_" + deviceId + "&CC_0C0330 | " +
                   "PCI\\VEN_" + vendorId + "&DEV_" + deviceId + "&CC_0C03";
        }

        private static DeviceInfo Device(string vendorId, string deviceId, string hardwareIds, string name)
        {
            DeviceInfo d = new DeviceInfo();
            d.InstanceId = "PCI\\VEN_" + vendorId + "&DEV_" + deviceId + "\\3&11583659&0&1F";
            d.HardwareIds = hardwareIds;
            d.Name = name;
            d.IsPresent = true;
            d.Source = "SetupAPI";
            return d;
        }

        private static Inventory NativeInventory(params DeviceInfo[] devices)
        {
            Inventory inv = new Inventory();
            inv.DevicesNativeSourceAvailable = true;
            foreach (DeviceInfo d in devices) inv.Devices.Add(d);
            return inv;
        }

        private static void IntelRecognized(TestRunner t)
        {
            t.Suite("ChipsetCollector: Intel catalogado (Z390 - A305)");

            Inventory inv = NativeInventory(
                Device("8086", "A305", IsaLpcHardwareIds("8086", "A305"), "Intel(R) 300 Series Chipset Family LPC Controller (Z390) - A305"));

            ChipsetCollector.IdentifyChipset(inv);

            t.NotNull("Chipset preenchido", inv.Chipset);
            t.Null("Sem motivo de indisponibilidade quando o chipset foi identificado", inv.ChipsetUnavailableReason);
            if (inv.Chipset != null)
            {
                t.Equal("Vendor = Intel", "Intel", inv.Chipset.Vendor);
                t.Equal("DeviceId extraido corretamente", "A305", inv.Chipset.DeviceId);
                t.Equal("Nome traduzido pela tabela curada", "Intel Z390", inv.Chipset.Name);
                t.Contains("SourceDevice cita a classe PCI usada", inv.Chipset.SourceDevice, "0601");
            }
        }

        private static void IntelUnrecognizedIdIsNotAGuess(TestRunner t)
        {
            t.Suite("ChipsetCollector: Device ID Intel fora da tabela nunca vira palpite");

            // FFFF nunca sera um Device ID real de PCH Intel - garante que a
            // tabela nao "acerta por acidente" e que o cross-check abaixo
            // continua fiel ao principio central do motor (ausencia de dado
            // nunca vira afirmacao).
            Inventory inv = NativeInventory(
                Device("8086", "FFFF", IsaLpcHardwareIds("8086", "FFFF"), "Dispositivo PCI desconhecido"));

            ChipsetCollector.IdentifyChipset(inv);

            t.NotNull("Chipset preenchido (o dispositivo PCI FOI encontrado)", inv.Chipset);
            if (inv.Chipset != null)
            {
                t.Equal("VendorId/DeviceId medidos continuam presentes mesmo sem nome", "FFFF", inv.Chipset.DeviceId);
                t.Null("Name fica null - ID nao catalogado nunca vira um nome inventado", inv.Chipset.Name);
            }
        }

        private static void AmdGenerationFallback(TestRunner t)
        {
            t.Suite("ChipsetCollector: AMD sem XHCI catalogado cai para nome de geracao da FCH");

            Inventory inv = NativeInventory(
                Device("1022", "780E", IsaLpcHardwareIds("1022", "780E"), "AMD FCH LPC Bridge"));

            ChipsetCollector.IdentifyChipset(inv);

            t.NotNull("Chipset preenchido", inv.Chipset);
            if (inv.Chipset != null)
            {
                t.Equal("Vendor = AMD", "AMD", inv.Chipset.Vendor);
                t.Contains("Nome e o rotulo generico de geracao, nunca um SKU especifico inventado",
                    inv.Chipset.Name, "AMD FCH (geracao AM4 inicial");
            }
        }

        private static void AmdSkuViaXhciOverridesGeneration(TestRunner t)
        {
            t.Suite("ChipsetCollector: controlador USB XHCI da FCH refina o nome generico para o SKU exato");

            Inventory inv = NativeInventory(
                Device("1022", "780E", IsaLpcHardwareIds("1022", "780E"), "AMD FCH LPC Bridge"),
                Device("1022", "43D5", XhciHardwareIds("1022", "43D5"), "AMD USB 3.1 XHCI Controller"));

            ChipsetCollector.IdentifyChipset(inv);

            t.NotNull("Chipset preenchido", inv.Chipset);
            if (inv.Chipset != null)
            {
                t.Equal("SKU especifico (B450) sobrescreve o nome generico da geracao", "AMD B450", inv.Chipset.Name);
                t.Contains("SourceDevice registra que o XHCI foi usado, nao so a ponte LPC",
                    inv.Chipset.SourceDevice, "XHCI");
            }
        }

        private static void NoPciDeviceFound(TestRunner t)
        {
            t.Suite("ChipsetCollector: nenhuma ponte ISA/LPC nem FCH entre os dispositivos = nao determinavel");

            Inventory inv = NativeInventory(
                Device("10DE", "2504", "PCI\\VEN_10DE&DEV_2504&CC_030000 | PCI\\VEN_10DE&DEV_2504&CC_0300", "GPU NVIDIA"));

            ChipsetCollector.IdentifyChipset(inv);

            t.Null("Chipset fica null - nenhum dispositivo com a classe certa foi encontrado", inv.Chipset);
            t.NotNull("Motivo explicito preenchido (nunca silencioso)", inv.ChipsetUnavailableReason);
            t.Contains("Motivo cita a ausencia do dispositivo, nao a fonte", inv.ChipsetUnavailableReason, "Nenhuma ponte");
        }

        private static void NativeSourceUnavailableIsDistinctReason(TestRunner t)
        {
            t.Suite("ChipsetCollector: motivo distingue 'fonte nativa indisponivel' de 'dispositivo nao encontrado'");

            Inventory inv = new Inventory();
            inv.DevicesNativeSourceAvailable = false; // mesmo par ja usado para Devices em geral

            ChipsetCollector.IdentifyChipset(inv);

            t.Null("Chipset fica null", inv.Chipset);
            t.Contains("Motivo cita a fonte nativa especificamente", inv.ChipsetUnavailableReason, "SetupAPI");
        }

        private static void WrongClassCodeIsIgnored(TestRunner t)
        {
            t.Suite("ChipsetCollector: dispositivo Intel de outra classe (nao 0601) nao e confundido com o PCH");

            // Vendor Intel correto, mas classe de rede (0200) - nao pode
            // virar "chipset" so por bater o VEN_8086.
            Inventory inv = NativeInventory(
                Device("8086", "2723", "PCI\\VEN_8086&DEV_2723&CC_020000 | PCI\\VEN_8086&DEV_2723&CC_0200", "Intel Wi-Fi 6 AX200"));

            ChipsetCollector.IdentifyChipset(inv);

            t.Null("Chipset fica null - VEN_8086 sozinho nao basta sem a classe 0601", inv.Chipset);
        }

        private static void WmiOnlyDeviceWithoutHardwareIdsIsIgnored(TestRunner t)
        {
            t.Suite("ChipsetCollector: dispositivo so-WMI (sem HardwareIds) nao pode ser usado como fonte");

            // CollectWmi (DeviceCollector) nunca preenche HardwareIds - so a
            // fonte nativa preenche. Um DeviceInfo assim nao tem como
            // confirmar a classe PCI e precisa ser ignorado, nao tratado
            // como "classe desconhecida = pode ser a ponte".
            DeviceInfo wmiOnly = new DeviceInfo();
            wmiOnly.InstanceId = "PCI\\VEN_8086&DEV_A305\\3&11583659&0&1F";
            wmiOnly.HardwareIds = null;
            wmiOnly.Source = "WMI";

            Inventory inv = NativeInventory(wmiOnly);
            ChipsetCollector.IdentifyChipset(inv);

            t.Null("Chipset fica null sem HardwareIds para confirmar a classe", inv.Chipset);
        }

        private static void SurvivesNullDevicesList(TestRunner t)
        {
            t.Suite("ChipsetCollector: sobrevive a inventario sem nenhum dispositivo (injecao de falha)");

            ScanContext ctx = Fixture.Context(false);
            Inventory inv = new Inventory(); // Devices vazio, nao nulo (construtor de Inventory ja inicializa)
            SourceSet src = Fixture.Sources(new FakeWmi(), new FakeRegistry(), new FakeEventLog(), new FakeProcessRunner());

            t.DoesNotThrow("Collect() completo sobrevive a inventario vazio", delegate
            {
                new ChipsetCollector().Collect(ctx, src, inv);
            });
            t.Null("Chipset continua null", inv.Chipset);
            t.NotNull("Motivo preenchido mesmo no caminho completo via Collect()", inv.ChipsetUnavailableReason);
        }

        // ---------- Parte 3: banco de compatibilidade ----------

        private static void CompatibilityReferenceForRecognizedChipset(TestRunner t)
        {
            t.Suite("CompatibilityReference: chipset catalogado produz especificacoes com fonte rotulada");

            Inventory inv = NativeInventory(
                Device("8086", "A305", IsaLpcHardwareIds("8086", "A305"), "Intel(R) LPC Controller (Z390) - A305"));
            ChipsetCollector.IdentifyChipset(inv);

            CompatibilityReference cr = CompatibilityReference.Build(inv);

            t.True("Available = true", cr.Available);
            t.Equal("ChipsetName ecoa o nome identificado na parte 1", "Intel Z390", cr.ChipsetName);
            t.Equal("Socket correto para a geracao", "LGA1151 (segunda geracao - mesmo encaixe fisico do anterior, mas ELETRICAMENTE incompativel com CPU de 6a/7a geracao)", cr.Socket);
            t.NotNull("PCIe do chipset preenchido", cr.ChipsetPcieGeneration);
            t.NotNull("RAID preenchido", cr.RaidSupport);
            t.Equal("Fonte sempre a mesma label constante (nunca por campo)", CompatibilityReference.ReferenceSourceLabel, cr.Source);
            t.Null("Sem motivo de indisponibilidade quando disponivel", cr.UnavailableReason);
        }

        private static void CompatibilityReferenceWhenChipsetNotDetermined(TestRunner t)
        {
            t.Suite("CompatibilityReference: sem chipset identificado, nunca inventa especificacao");

            Inventory inv = new Inventory();
            inv.DevicesNativeSourceAvailable = true; // rodou, so nao achou nada
            ChipsetCollector.IdentifyChipset(inv);

            CompatibilityReference cr = CompatibilityReference.Build(inv);

            t.False("Available = false", cr.Available);
            t.Null("Nenhum campo de especificacao preenchido", cr.Socket);
            t.NotNull("Motivo explicito", cr.UnavailableReason);
            t.Equal("Fonte ainda e rotulada mesmo quando indisponivel (para nunca ficar ambiguo)",
                CompatibilityReference.ReferenceSourceLabel, cr.Source);
        }

        private static void CompatibilityReferenceWhenIdNotCatalogued(TestRunner t)
        {
            t.Suite("CompatibilityReference: chipset encontrado mas ID nao catalogado tambem nao vira palpite");

            Inventory inv = NativeInventory(
                Device("8086", "FFFF", IsaLpcHardwareIds("8086", "FFFF"), "Dispositivo desconhecido"));
            ChipsetCollector.IdentifyChipset(inv);

            CompatibilityReference cr = CompatibilityReference.Build(inv);

            t.False("Available = false mesmo com o dispositivo PCI identificado", cr.Available);
            t.Null("ChipsetName fica null (nao 'FFFF' nem qualquer palpite)", cr.ChipsetName);
            t.Contains("Motivo cita o ID bruto para rastreabilidade", cr.UnavailableReason, "FFFF");
        }

        private static void CompatibilityReferenceWhenNameHasNoSpecYet(TestRunner t)
        {
            t.Suite("CompatibilityReference: nome identificado sem entrada na tabela de specs tambem e tratado, nao lanca");

            // Cenario defensivo: simula uma entrada futura de identidade
            // (parte 1) cadastrada antes da entrada de compatibilidade
            // (parte 3) correspondente - as duas tabelas em ChipsetDatabase
            // sao mantidas por partes separadas do arquivo e podem divergir
            // temporariamente durante uma expansao futura.
            Inventory inv = new Inventory();
            ChipsetInfo synthetic = new ChipsetInfo();
            synthetic.Vendor = "Intel";
            synthetic.VendorId = "8086";
            synthetic.DeviceId = "0000";
            synthetic.Name = "Intel Chipset Hipotetico Sem Spec";
            inv.Chipset = synthetic;

            CompatibilityReference cr = CompatibilityReference.Build(inv);

            t.False("Available = false", cr.Available);
            t.Equal("ChipsetName ainda e ecoado (e um fato medido/identificado, so falta a spec)",
                "Intel Chipset Hipotetico Sem Spec", cr.ChipsetName);
            t.NotNull("Motivo explica a lacuna", cr.UnavailableReason);
        }
    }
}
