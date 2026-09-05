using System;
using System.Collections.Generic;
using System.Diagnostics;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    public sealed class SensorCollector : ICollector
    {
        public string Name { get { return "Sensors"; } }

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            SensorsInfo s = inv.Sensors;

            if (src.Sensors == null || !src.Sensors.Available)
            {
                s.Available = false;
                s.UnavailableReason = src.Sensors == null
                    ? "Biblioteca de sensores nao inicializada."
                    : src.Sensors.UnavailableReason;

                // Ultimo recurso: zona termica ACPI. Funciona em poucos
                // fabricantes, mas quando funciona e uma leitura real.
                //
                // TryAcpiThermalZone aplica o resultado diretamente em
                // inv.Cpu quando encontra uma leitura valida, ja que
                // ApplyToInventory (que copia para inv.Cpu.TemperatureC, o
                // campo que os testes de CPU realmente leem) so roda no
                // caminho feliz mais abaixo, e esse "return" antecipado
                // pula essa chamada.
                TryAcpiThermalZone(ctx, src, inv, s);
                return;
            }

            s.Available = true;

            IList<SensorReading> readings = Try.Get(ctx, Name, "leitura de sensores", delegate
            {
                return src.Sensors.Read();
            });

            if (readings == null || readings.Count == 0)
            {
                s.Available = false;
                s.UnavailableReason = "A biblioteca de sensores carregou mas nao devolveu nenhuma leitura.";
                return;
            }

            // A leitura crua da lib de sensores passa por um filtro de
            // plausibilidade antes de virar fato no Inventory. Um Super I/O
            // nao suportado frequentemente devolve 0 C em vez de falhar, o
            // que sairia como "CPU a 0,0 C em repouso" - o mesmo tipo de
            // leitura morta que StorageCollector.cs ja filtra para disco
            // (Wear/Temperature). Aplica Helpers.IsPlausibleTemperature
            // (Base.cs) aqui, antes de gravar em qualquer campo do Inventory.
            s.CpuTemperatureC = PlausibleOrNull(SensorSource.Find(readings, "Cpu", "Temperature",
                new string[] { "Package", "Tctl", "Average", "Core" }));
            s.GpuTemperatureC = PlausibleOrNull(SensorSource.Find(readings, "Gpu", "Temperature",
                new string[] { "Core", "Hot Spot", "HotSpot" }));
            s.MotherboardTemperatureC = PlausibleOrNull(SensorSource.Find(readings, "Motherboard", "Temperature", null));
            if (!s.MotherboardTemperatureC.HasValue)
                s.MotherboardTemperatureC = PlausibleOrNull(SensorSource.Find(readings, "SuperIO", "Temperature", null));

            foreach (SensorReading r in readings)
            {
                if (string.Equals(r.SensorType, "Fan", StringComparison.OrdinalIgnoreCase))
                {
                    FanReading f = new FanReading();
                    f.Hardware = r.Hardware;
                    f.Name = r.Name;
                    f.Rpm = r.Value;
                    s.Fans.Add(f);
                }
                else if (string.Equals(r.SensorType, "Temperature", StringComparison.OrdinalIgnoreCase))
                {
                    if (r.Name != null && r.Name.IndexOf("Distance", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    NamedReading t = new NamedReading();
                    t.Hardware = r.Hardware;
                    t.Name = r.Name;
                    t.Value = r.Value;
                    s.Temperatures.Add(t);
                }
            }

            ApplyToInventory(inv, readings);
        }

        // Valor null quando a leitura nao passa no filtro de
        // plausibilidade, em vez de deixar 0 C (ou qualquer outro numero
        // fora da faixa fisica) virar fato no Inventory.
        private static double? PlausibleOrNull(double? value)
        {
            return Helpers.IsPlausibleTemperature(value) ? value : null;
        }

        private void ApplyToInventory(Inventory inv, IList<SensorReading> readings)
        {
            if (inv.Sensors.CpuTemperatureC.HasValue)
            {
                inv.Cpu.TemperatureC = inv.Sensors.CpuTemperatureC;
                inv.Cpu.TemperatureSource = "Sensor de hardware (LibreHardwareMonitor)";
            }

            foreach (GpuInfo g in inv.Gpus)
            {
                if (g.TemperatureC.HasValue) continue;
                // Casa o sensor com a GPU pelo nome do hardware, para nao
                // atribuir a temperatura da GPU errada quando ha duas.
                double? t = PlausibleOrNull(FindForHardware(readings, "Gpu", "Temperature", g.Name));
                if (t.HasValue) g.TemperatureC = t;
                else if (inv.Gpus.Count == 1) g.TemperatureC = inv.Sensors.GpuTemperatureC;
            }

            foreach (DiskInfo d in inv.Disks)
            {
                if (d.TemperatureC.HasValue) continue;
                double? t = PlausibleOrNull(FindForHardware(readings, "Storage", "Temperature", d.Model));
                if (t.HasValue)
                {
                    d.TemperatureC = t;
                    d.TemperatureSource = "Sensor de hardware (LibreHardwareMonitor)";
                }
            }
        }

        // Fabricantes cujo nome aparece como token isolado no modelo de
        // muitos discos diferentes (ex.: "Samsung SSD 970 EVO Plus 1TB" e
        // "Samsung SSD 860 EVO 500GB" na mesma maquina). Casar por esse
        // token primeiro atribuia a temperatura de um disco Samsung a
        // qualquer outro disco Samsung presente nas leituras.
        private static readonly string[] KnownManufacturerTokens = new string[]
        {
            "Samsung", "Western", "Digital", "WDC", "Kingston", "Seagate",
            "Toshiba", "SanDisk", "Crucial", "Micron", "ADATA", "Hynix",
            "Intel", "Corsair", "Lexar", "PNY", "Team", "Apacer", "Hitachi",
            "Fujitsu", "Plextor", "Transcend", "Gigabyte", "Patriot"
        };

        private static bool IsKnownManufacturerToken(string token)
        {
            foreach (string m in KnownManufacturerTokens)
                if (string.Equals(m, token, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        // Casamento por token do modelo (ex: "SN850X"), evitando atribuir a
        // leitura de um disco a outro numa maquina com varios. Os tokens
        // sao ordenados do mais especifico (mais longo) para o menos
        // especifico, e tokens que sao apenas o nome de um fabricante
        // conhecido (ex.: "Samsung", que tende a aparecer antes do modelo
        // no nome) so entram como ultimo recurso, depois de tentar todos os
        // demais tokens - senao o nome do fabricante venceria por ser o
        // primeiro token, nao por ser o mais especifico.
        public static double? FindForHardware(IList<SensorReading> readings, string hardwareType, string sensorType, string deviceName)
        {
            if (readings == null || string.IsNullOrEmpty(deviceName)) return null;

            string[] rawTokens = deviceName.Split(new char[] { ' ', '_', '-' }, StringSplitOptions.RemoveEmptyEntries);

            List<string> specific = new List<string>();
            List<string> generic = new List<string>();
            foreach (string token in rawTokens)
            {
                if (token.Length < 4) continue;
                if (IsKnownManufacturerToken(token)) generic.Add(token);
                else specific.Add(token);
            }

            specific.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });
            generic.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });

            List<string> orderedTokens = new List<string>(specific);
            orderedTokens.AddRange(generic);

            foreach (string token in orderedTokens)
            {
                foreach (SensorReading r in readings)
                {
                    if (r.HardwareType == null || r.SensorType == null || r.Hardware == null) continue;
                    if (r.HardwareType.IndexOf(hardwareType, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    if (!string.Equals(r.SensorType, sensorType, StringComparison.OrdinalIgnoreCase)) continue;
                    if (r.Name != null && r.Name.IndexOf("Distance", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    if (r.Hardware.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0) return r.Value;
                }
            }

            return null;
        }

        private void TryAcpiThermalZone(ScanContext ctx, SourceSet src, Inventory inv, SensorsInfo s)
        {
            IList<DataRow> zones = Try.Get(ctx, Name, "MSAcpi_ThermalZoneTemperature", delegate
            {
                return src.Wmi.Query(WmiSource.Wmi, "SELECT CurrentTemperature, InstanceName FROM MSAcpi_ThermalZoneTemperature");
            });

            if (zones == null || zones.Count == 0) return;

            double max = double.MinValue;
            foreach (DataRow r in zones)
            {
                uint? deciKelvin = null;
                try
                {
                    ulong? v = r.ULong("CurrentTemperature");
                    if (v.HasValue) deciKelvin = (uint)v.Value;
                }
                catch { }

                if (!deciKelvin.HasValue || deciKelvin.Value == 0) continue;
                double celsius = (deciKelvin.Value / 10.0) - 273.15;
                if (celsius > 0 && celsius < 130 && celsius > max) max = celsius;
            }

            if (max > double.MinValue)
            {
                s.CpuTemperatureC = Math.Round(max, 1);
                s.UnavailableReason = (s.UnavailableReason == null ? "" : s.UnavailableReason + " ") +
                    "Temperatura obtida pela zona termica ACPI (menos precisa que sensor dedicado).";

                // Sem isto, o valor ficaria so em s.CpuTemperatureC (JSON de
                // sensores) e o teste de temperatura da CPU, que le
                // inv.Cpu.TemperatureC, nunca o veria - reportaria "Nao
                // verificado" mesmo com uma leitura ACPI valida disponivel.
                if (inv != null && inv.Cpu != null)
                {
                    inv.Cpu.TemperatureC = s.CpuTemperatureC;
                    inv.Cpu.TemperatureSource = "Zona termica ACPI (fallback, menos precisa que sensor dedicado)";
                }
            }
        }
    }

    public sealed class PerformanceCollector : ICollector
    {
        public string Name { get { return "Performance"; } }

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            PerformanceInfo p = inv.Performance;

            Native.MemoryStatus mem = Native.GetMemoryStatus();
            if (mem != null) p.MemoryLoadPercent = mem.LoadPercent;

            // Uso de CPU medido com duas amostras espacadas do tempo total de
            // processador, e nao com o LoadPercentage da WMI (que e uma media
            // grosseira de 1 segundo). Ainda assim e uma amostra instantanea,
            // e a camada de testes trata isso reduzindo a confianca.
            Try.Do(ctx, Name, "amostragem de CPU", delegate
            {
                p.CpuLoadPercent = SampleCpuLoad(600);
                p.SamplingNote = "Uso de CPU medido em duas amostras separadas por 600 ms.";
            });

            Try.Do(ctx, Name, "contagem de processos", delegate
            {
                Process[] procs = Process.GetProcesses();
                p.ProcessCount = procs.Length;

                int threads = 0, handles = 0;
                foreach (Process proc in procs)
                {
                    try { threads += proc.Threads.Count; }
                    catch { }
                    try { handles += proc.HandleCount; }
                    catch { }
                    finally { proc.Dispose(); }
                }
                p.ThreadCount = threads;
                p.HandleCount = handles;
            });
        }

        // GetSystemTimes (Native.cs) mede a carga de CPU com uma chamada de
        // kernel O(1), sem depender de enumerar processos nem de privilegio
        // de acesso a cada um - enumerar todos os processos da maquina para
        // somar tempo de CPU escala mal, e o proprio custo da enumeracao
        // pode superar o intervalo de amostragem pedido numa maquina com
        // centenas de processos. Devolve null (nunca um valor grudado em
        // 100 por clamp silencioso) quando a amostra nao for confiavel.
        public static double? SampleCpuLoad(int intervalMs)
        {
            return Native.SampleSystemCpuLoad(intervalMs);
        }
    }
}
