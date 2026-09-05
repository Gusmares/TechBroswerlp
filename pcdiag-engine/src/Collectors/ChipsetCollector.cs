using System;
using System.Collections.Generic;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Collectors
{
    // Identificacao de chipset (Intel PCH / AMD FCH) - parte 1 do
    // levantamento de hardware.
    //
    // NAO ha P/Invoke novo nem consulta ao SO aqui: este coletor so varre
    // Inventory.Devices, que DeviceCollector ja preencheu via SetupAPI (ver
    // DeviceCollector.CollectNative). Por isso precisa rodar DEPOIS de
    // DeviceCollector na lista de Program.RunCollection - a ordem de
    // execucao ali e sequencial (cada modulo roda e so entao o proximo
    // comeca, ver ModuleRunner.Run dentro do foreach), entao isso e
    // garantido pela posicao no array, nao por dependencia explicita.
    //
    // O sinal usado e o PCI Vendor/Device ID da ponte ISA/LPC (Intel) ou da
    // FCH (AMD) - o mesmo que CPU-Z/AIDA64 usam para isso. DeviceInfo.
    // HardwareIds so vem preenchido para dispositivos que passaram pela
    // fonte nativa (SetupAPI) - um dispositivo so-WMI nunca tem o campo
    // CC_xxxx (codigo de classe PCI) que este coletor precisa, entao sem a
    // fonte nativa a identificacao vira "nao determinavel" de forma
    // explicita (ver Inventory.ChipsetUnavailableReason), nunca um palpite.
    public sealed class ChipsetCollector : ICollector
    {
        public string Name { get { return "Chipset"; } }

        // Classes PCI usadas para achar o dispositivo certo sem presumir
        // bus/device/function (ver Helpers.HasPciClassCode).
        private const string ClassIsaLpcBridge = "0601"; // ponte ISA/LPC (Intel) ou LPC da FCH (AMD)
        private const string ClassUsbController = "0C03"; // controlador XHCI - mais especifico para o SKU da AMD

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            Try.Do(ctx, Name, "Identificar chipset via PCI Vendor/Device ID", delegate
            {
                IdentifyChipset(inv);
            });
        }

        // internal (nao private) para ser exercitado diretamente pelos
        // testes com um Inventory sintetico, sem precisar rodar o coletor
        // inteiro por cima de ModuleRunner/ScanContext.
        internal static void IdentifyChipset(Inventory inv)
        {
            ChipsetInfo found = FindIntel(inv.Devices);
            if (found == null) found = FindAmd(inv.Devices);

            if (found != null)
            {
                inv.Chipset = found;
                return;
            }

            if (!inv.DevicesNativeSourceAvailable)
            {
                inv.ChipsetUnavailableReason = "Fonte nativa (SetupAPI) indisponivel - sem ela, os dispositivos PCI nao trazem o codigo de classe (CC_xxxx) necessario para achar a ponte ISA/LPC ou o controlador da FCH; a WMI (Win32_PnPEntity) nao expoe esse dado.";
                return;
            }

            inv.ChipsetUnavailableReason = "Nenhuma ponte ISA/LPC (Intel, classe PCI 0601) nem controlador FCH (AMD) foi encontrado entre os dispositivos PCI enumerados.";
        }

        private static ChipsetInfo FindIntel(List<DeviceInfo> devices)
        {
            DeviceInfo d = FindPciDevice(devices, "8086", ClassIsaLpcBridge);
            if (d == null) return null;

            Helpers.PciIds ids = Helpers.ParsePciIds(d.InstanceId);
            if (ids == null || ids.DeviceId == null) return null;

            ChipsetInfo c = new ChipsetInfo();
            c.VendorId = ids.VendorId;
            c.DeviceId = ids.DeviceId;
            c.Vendor = "Intel";
            c.Name = ChipsetDatabase.LookupIntelPch(ids.DeviceId);
            c.SourceDevice = "Ponte ISA/LPC (PCI classe 0601): " + Helpers.FirstNonEmpty(d.Name, d.InstanceId);
            return c;
        }

        private static ChipsetInfo FindAmd(List<DeviceInfo> devices)
        {
            DeviceInfo lpc = FindPciDevice(devices, "1022", ClassIsaLpcBridge);
            if (lpc == null) return null;

            Helpers.PciIds lpcIds = Helpers.ParsePciIds(lpc.InstanceId);
            if (lpcIds == null || lpcIds.DeviceId == null) return null;

            ChipsetInfo c = new ChipsetInfo();
            c.VendorId = lpcIds.VendorId;
            c.DeviceId = lpcIds.DeviceId;
            c.Vendor = "AMD";
            c.SourceDevice = "Ponte LPC da FCH (PCI classe 0601): " + Helpers.FirstNonEmpty(lpc.Name, lpc.InstanceId);

            // A ponte LPC da FCH e COMPARTILHADA entre varios SKUs da mesma
            // geracao (A320/B350/X370/B450/X470 relatam o MESMO Device ID de
            // ponte LPC) - ver o comentario longo em
            // ChipsetDatabase.BuildAmdFchGeneration. O controlador USB XHCI
            // da FCH e mais especifico e, quando presente e catalogado,
            // sobrescreve o nome generico da geracao por um nome de SKU
            // exato.
            string sku = FindAmdSkuViaXhci(devices);
            if (sku != null)
            {
                c.Name = sku;
                c.SourceDevice += " + controlador USB XHCI da FCH (PCI classe 0C03, mais especifico para o SKU)";
            }
            else
            {
                c.Name = ChipsetDatabase.LookupAmdFchGeneration(lpcIds.DeviceId);
            }

            return c;
        }

        private static string FindAmdSkuViaXhci(List<DeviceInfo> devices)
        {
            DeviceInfo xhci = FindPciDevice(devices, "1022", ClassUsbController);
            if (xhci == null) return null;

            Helpers.PciIds ids = Helpers.ParsePciIds(xhci.InstanceId);
            if (ids == null || ids.DeviceId == null) return null;

            return ChipsetDatabase.LookupAmdSkuByXhci(ids.DeviceId);
        }

        private static DeviceInfo FindPciDevice(List<DeviceInfo> devices, string vendorId, string classCode)
        {
            if (devices == null) return null;

            foreach (DeviceInfo d in devices)
            {
                if (d == null || d.InstanceId == null || d.HardwareIds == null) continue;

                Helpers.PciIds ids = Helpers.ParsePciIds(d.InstanceId);
                if (ids == null || !string.Equals(ids.VendorId, vendorId, StringComparison.OrdinalIgnoreCase)) continue;

                if (Helpers.HasPciClassCode(d.HardwareIds, classCode)) return d;
            }

            return null;
        }
    }
}
