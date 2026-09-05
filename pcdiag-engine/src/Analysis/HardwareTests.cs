using System;
using System.Collections.Generic;
using System.Globalization;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Analysis
{
    public sealed class CpuTests : IDiagnosticTest
    {
        public string Category { get { return "Processador"; } }

        public IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv)
        {
            List<TestResult> list = new List<TestResult>();
            list.Add(DeviceStatus(inv));
            list.Add(Temperature(ctx, inv));
            list.Add(Virtualization(inv));
            return list;
        }

        private TestResult DeviceStatus(Inventory inv)
        {
            TestResult r = T.Make("CPU-001", "Estado do processador", Category,
                "Status que o Windows reporta para o dispositivo de processador.");

            CpuInfo c = inv.Cpu;
            if (c.Name == null) return T.Unknown(r, "Nenhuma informacao de processador foi obtida.");

            T.Ev(r, "WMI", "Win32_Processor.Name", c.Name);
            T.Ev(r, "WMI", "Win32_Processor.NumberOfCores", T.Num(c.PhysicalCores));
            T.Ev(r, "WMI", "Win32_Processor.NumberOfLogicalProcessors", T.Num(c.LogicalProcessors));
            if (c.WmiStatus != null) T.Ev(r, "WMI", "Win32_Processor.Status", c.WmiStatus);

            // A fonte primaria aqui e WMI (Win32_Processor), nao API nativa
            // nem contador do kernel - nao reivindica Authoritative().
            // AgreeingSource() so e concedido quando o CpuCollector de fato
            // confirmou o nome (registro) ou a contagem de threads (API
            // nativa) contra uma segunda fonte independente - nunca
            // incondicionalmente.
            Confidence confBuilder = Confidence.Build();
            if (c.NameConfirmedByRegistry || c.LogicalProcessorsConfirmedByNativeApi)
                confBuilder = confBuilder.AgreeingSource();
            int confidence = confBuilder.Value;

            if (c.WmiStatus != null && !string.Equals(c.WmiStatus, "OK", StringComparison.OrdinalIgnoreCase))
                return T.Error(r, Severity.High,
                    "O Windows reporta o processador com status '" + c.WmiStatus + "'.",
                    "Status diferente de OK em CPU e raro e costuma acompanhar erro de hardware no log. Conferir os eventos WHEA.",
                    confidence);

            // c.Name pode vir SO do fallback do registro (CpuCollector.cs)
            // quando a consulta Win32_Processor falha por completo - nesse
            // caso c.WmiStatus fica nulo, e sem ele nao ha confirmacao de
            // que o status do dispositivo foi de fato consultado ao Windows.
            if (c.WmiStatus == null)
                return T.Unknown(r, "O nome do processador foi obtido (fonte alternativa), mas a consulta Win32_Processor - que informa o status de funcionamento - nao respondeu. Nao ha confirmacao de que o dispositivo esta OK.");

            string desc = c.Name;
            if (c.PhysicalCores.HasValue && c.LogicalProcessors.HasValue)
                desc += " (" + c.PhysicalCores.Value + " nucleos / " + c.LogicalProcessors.Value + " threads)";
            if (c.SocketCount.HasValue && c.SocketCount.Value > 1)
                desc += ", " + c.SocketCount.Value + " sockets";

            return T.Pass(r, desc + " operando normalmente.", confidence);
        }

        private TestResult Temperature(ScanContext ctx, Inventory inv)
        {
            TestResult r = T.Make("CPU-002", "Temperatura do processador", Category,
                "Temperatura da CPU comparada aos limiares configurados.");
            r.Requires = Requirement.Sensors;

            CpuInfo c = inv.Cpu;

            if (!c.TemperatureC.HasValue)
            {
                if (!ctx.IsElevated) return T.RequiresAdmin(r, "Ler sensores de temperatura de hardware");
                return T.NotTested(r, inv.Sensors.UnavailableReason != null
                    ? inv.Sensors.UnavailableReason
                    : "Nenhum sensor de temperatura de CPU foi exposto por este hardware.");
            }

            double temp = c.TemperatureC.Value;

            // Executed==true so diz que o modulo de carga RODOU - nao que
            // produziu uma amostra termica sob carga de verdade (sensor pode
            // ter ficado indisponivel so durante essa fase). Sem
            // CpuMaxTempC, inv.Cpu.TemperatureC nunca foi sobrescrito pelo
            // maximo sob carga (StressCollector.RunAllPhases) e continua
            // sendo a leitura de REPOUSO original - rotula-la como "sob
            // carga total" seria uma etiqueta falsa aplicada a um dado de
            // repouso.
            bool underLoad = inv.Stress != null && inv.Stress.Executed && inv.Stress.CpuMaxTempC.HasValue;

            int warnC = underLoad ? ctx.Options.CpuWarnC : ctx.Options.CpuIdleWarnC;
            int critC = underLoad ? ctx.Options.CpuCritC : ctx.Options.CpuIdleCritC;

            T.Ev(r, "Sensor", "CPU Package Temperature", T.Num(temp, 1) + " C");
            T.Ev(r, "Config", "limiar atencao / critico (" + (underLoad ? "sob carga" : "repouso") + ")", warnC + " / " + critC + " C");

            Confidence conf = Confidence.Build().Authoritative();
            if (Collectors.Helpers.IsPlausibleTemperature(temp)) conf = conf.PlausibleRange();
            // Sem teste de carga, a leitura e de repouso: nao representa o pior
            // caso, e a confianca reflete isso.
            if (!underLoad) conf = conf.SingleVolatileSample();
            int confidence = conf.Value;

            string context = underLoad ? "sob carga no teste de estresse" : "em repouso";

            if (temp >= critC)
                return T.Error(r, Severity.High,
                    "CPU a " + T.Num(temp, 1) + " C " + context + ", acima do limiar critico de " + critC + " C.",
                    "Verificar cooler, pasta termica e fluxo de ar. Temperatura nessa faixa causa throttling e reduz a vida util do processador.",
                    confidence);

            if (temp >= warnC)
                return T.Warn(r, Severity.Medium,
                    "CPU a " + T.Num(temp, 1) + " C " + context + ", acima do limiar de atencao de " + warnC + " C.",
                    "Acompanhar. Se ja estiver assim em repouso, limpar o dissipador e reaplicar pasta termica costuma resolver.",
                    confidence);

            if (!underLoad)
                return T.Pass(r, "CPU a " + T.Num(temp, 1) + " C em repouso. Sem teste de carga, esta leitura nao descarta superaquecimento sob uso pesado.", confidence);

            return T.Pass(r, "CPU atingiu no maximo " + T.Num(temp, 1) + " C sob carga total.", confidence);
        }

        private TestResult Virtualization(Inventory inv)
        {
            TestResult r = T.Make("CPU-003", "Virtualizacao por hardware", Category,
                "Verifica se a extensao de virtualizacao esta habilitada no firmware.");

            CpuInfo c = inv.Cpu;
            if (!c.VirtualizationEnabled.HasValue)
                return T.Unknown(r, "O campo VirtualizationFirmwareEnabled nao foi reportado por este processador.");

            T.Ev(r, "WMI", "Win32_Processor.VirtualizationFirmwareEnabled", c.VirtualizationEnabled.Value);
            int confidence = Confidence.Build().Authoritative().Value;

            if (c.VirtualizationEnabled.Value)
                return T.Pass(r, "Virtualizacao por hardware habilitada.", confidence);

            return T.Info(r,
                "Virtualizacao por hardware desabilitada no firmware. Necessaria para Hyper-V, WSL2, emuladores e para a Integridade de Memoria do Windows.",
                confidence);
        }
    }

    public sealed class MemoryTests : IDiagnosticTest
    {
        public string Category { get { return "Memoria"; } }

        public IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv)
        {
            List<TestResult> list = new List<TestResult>();
            list.Add(Usage(inv));
            list.Add(ReservedMemory(inv));
            list.Add(UpgradeSlots(inv));
            list.Add(ModuleConsistency(inv));
            list.Add(HardwareErrors(ctx, inv));
            return list;
        }

        private TestResult Usage(Inventory inv)
        {
            TestResult r = T.Make("MEM-001", "Uso de memoria", Category,
                "Percentual de memoria fisica em uso no momento da coleta.");

            MemoryInfo m = inv.Memory;
            if (!m.UsagePercent.HasValue) return T.Unknown(r, "GlobalMemoryStatusEx nao retornou o percentual de uso.");

            double pct = m.UsagePercent.Value;
            T.Ev(r, "Native", "GlobalMemoryStatusEx.dwMemoryLoad", T.Num(pct, 0) + "%");
            T.Ev(r, "Native", "memoria disponivel", T.Bytes(m.AvailableBytes));

            // Amostra instantanea de grandeza volatil: confianca reduzida de
            // proposito, porque 90% de uso pode ser cache legitimo.
            int confidence = Confidence.Build().Authoritative().SingleVolatileSample().Value;

            if (pct >= 92)
                return T.Warn(r, Severity.Medium,
                    "Memoria em " + T.Num(pct, 0) + "% de uso, com apenas " + T.Bytes(m.AvailableBytes) + " disponiveis.",
                    "Verificar quais aplicativos estao consumindo memoria. Se for o uso normal do cliente, considerar upgrade de RAM.",
                    confidence);

            return T.Pass(r, "Memoria em " + T.Num(pct, 0) + "% de uso (" + T.Bytes(m.AvailableBytes) + " disponiveis).", confidence);
        }

        // O caso "32 GB instalados / 29,7 GB utilizaveis" do briefing: precisa
        // de CONTEXTO, nao de alerta. Memoria reservada e normal em maquina com
        // grafico integrado - o que importa e distinguir a reserva esperada de
        // uma anomalia (modulo nao reconhecido, limite de memoria em msconfig).
        private TestResult ReservedMemory(Inventory inv)
        {
            TestResult r = T.Make("MEM-002", "Memoria reservada para hardware", Category,
                "Compara a memoria fisicamente instalada com a que o sistema operacional consegue usar.");

            MemoryInfo m = inv.Memory;
            if (!m.InstalledBytes.HasValue || !m.UsableBytes.HasValue)
                return T.Unknown(r, "Nao foi possivel obter simultaneamente a memoria instalada e a utilizavel.");

            T.Ev(r, "Native", "GetPhysicallyInstalledSystemMemory", T.Bytes(m.InstalledBytes));
            T.Ev(r, "Native", "GlobalMemoryStatusEx.ullTotalPhys", T.Bytes(m.UsableBytes));
            T.Ev(r, "Native", "diferenca (reservado)", T.Bytes(m.ReservedBytes));

            // InstalledBytes (GetPhysicallyInstalledSystemMemory) e
            // UsableBytes (GlobalMemoryStatusEx) sao duas chamadas nativas,
            // mas nao sao uma segunda fonte CONFIRMANDO o mesmo fato - cada
            // uma mede uma grandeza diferente (instalado x utilizavel),
            // combinadas para derivar a reserva. AgreeingSource() exige duas
            // fontes concordando sobre o MESMO valor, o que nao e o caso
            // aqui.
            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (!m.ReservedBytes.HasValue || m.ReservedBytes.Value == 0)
                return T.Pass(r, "Toda a memoria instalada (" + T.Bytes(m.InstalledBytes) + ") esta disponivel ao sistema.", confidence);

            double reservedPct = (double)m.ReservedBytes.Value / m.InstalledBytes.Value * 100.0;
            bool hasIntegratedGpu = false;
            foreach (GpuInfo g in inv.Gpus)
            {
                if (g.Kind == "Integrada") { hasIntegratedGpu = true; break; }
            }

            string baseText = T.Bytes(m.InstalledBytes) + " instalados, " + T.Bytes(m.UsableBytes) +
                " utilizaveis pelo Windows - " + T.Bytes(m.ReservedBytes) + " reservados (" + T.Num(reservedPct, 1) + "%).";

            // A propria GPU integrada ja reserva, de fato, ate ~2 GB de UMA
            // numa maquina de 8 GB (25% so por conta do video, sem nada de
            // anormal). Com GPU integrada presente, o limiar sobe para 35%
            // antes de virar alerta, para nao confundir reserva normal de
            // video com anomalia.
            double warnThreshold = hasIntegratedGpu ? 35 : 25;

            if (reservedPct >= warnThreshold)
                return T.Warn(r, Severity.Medium,
                    baseText + " Reserva desse tamanho e alta demais para ser apenas video integrado.",
                    "Verificar se ha limite de memoria configurado em msconfig (Inicializacao > Opcoes avancadas > Memoria maxima) e se todos os modulos estao sendo reconhecidos.",
                    confidence);

            string explanation = hasIntegratedGpu
                ? " Isso e esperado: a GPU integrada reserva parte da RAM como memoria de video."
                : " Reserva compativel com o uso normal de firmware e dispositivos.";

            return T.Info(r, baseText + explanation, confidence);
        }

        private TestResult UpgradeSlots(Inventory inv)
        {
            TestResult r = T.Make("MEM-003", "Slots de memoria disponiveis", Category,
                "Avalia se ha slot livre para upgrade de RAM.");

            MemoryInfo m = inv.Memory;
            if (!m.SlotsUsed.HasValue) return T.Unknown(r, "Nao foi possivel enumerar os modulos de memoria instalados.");

            T.Ev(r, "WMI", "Win32_PhysicalMemory (modulos detectados)", m.SlotsUsed.Value);

            if (!m.SlotsTotalReportedByFirmware.HasValue)
                return T.Info(r,
                    m.SlotsUsed.Value + " modulo(s) instalado(s). O firmware nao informa o total de slots da placa, entao nao e possivel dizer quantos estao livres.",
                    Confidence.Build().Authoritative().Value);

            int total = m.SlotsTotalReportedByFirmware.Value;
            T.Ev(r, "WMI", "Win32_PhysicalMemoryArray.MemoryDevices", total);

            // Campo declarativo do SMBIOS: confianca baixa por construcao.
            Confidence conf = Confidence.Build().UnreliableSource();
            if (m.SlotsTotalLooksTemplated) conf = conf.Divergent();
            int confidence = conf.Value;

            if (m.SlotsTotalLooksTemplated)
                return T.Info(r,
                    m.SlotsUsed.Value + " modulo(s) instalado(s) (confirmado). O firmware declara " + total +
                    " slots, mas esse valor tem caracteristica de template de fabrica e nao e confiavel.",
                    confidence);

            int free = total - m.SlotsUsed.Value;
            if (free <= 0)
                return T.Info(r,
                    "Todos os " + total + " slots declarados pelo firmware estao ocupados. Upgrade de RAM exigiria substituir modulos, nao acrescentar.",
                    confidence);

            return T.Info(r,
                m.SlotsUsed.Value + " de " + total + " slots ocupados - ate " + free +
                " livre(s) para upgrade, segundo o firmware. Confirmar fisicamente antes de comprar.",
                confidence);
        }

        // Modulos de capacidade ou velocidade diferentes fazem toda a memoria
        // operar no menor denominador e podem impedir dual-channel. E um achado
        // de configuracao com impacto real de desempenho.
        private TestResult ModuleConsistency(Inventory inv)
        {
            TestResult r = T.Make("MEM-004", "Consistencia entre modulos de memoria", Category,
                "Verifica se os modulos instalados tem mesma capacidade, velocidade e tipo.");

            MemoryInfo m = inv.Memory;
            if (m.Modules.Count == 0) return T.Unknown(r, "Nenhum modulo de memoria foi enumerado.");
            if (m.Modules.Count == 1)
                return T.Info(r, "Apenas um modulo instalado - operando em single-channel, que entrega cerca de metade da banda de memoria de uma configuracao dual-channel.",
                    Confidence.Build().Authoritative().Value);

            List<ulong> capacities = new List<ulong>();
            List<int> speeds = new List<int>();
            List<string> types = new List<string>();

            foreach (MemoryModule mod in m.Modules)
            {
                if (mod.CapacityBytes.HasValue && !capacities.Contains(mod.CapacityBytes.Value)) capacities.Add(mod.CapacityBytes.Value);
                if (mod.ConfiguredSpeedMhz.HasValue && !speeds.Contains(mod.ConfiguredSpeedMhz.Value)) speeds.Add(mod.ConfiguredSpeedMhz.Value);
                if (mod.MemoryType != null && !types.Contains(mod.MemoryType)) types.Add(mod.MemoryType);
            }

            foreach (MemoryModule mod in m.Modules)
            {
                T.Ev(r, "WMI", "Win32_PhysicalMemory[" + T.Name(mod.Slot, "?") + "]",
                    T.Bytes(mod.CapacityBytes) + " / " + T.Num(mod.ConfiguredSpeedMhz) + " MHz / " + T.Name(mod.MemoryType, "?"));
            }

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;
            List<string> problems = new List<string>();

            if (capacities.Count > 1) problems.Add("capacidades diferentes entre os modulos");
            if (speeds.Count > 1) problems.Add("velocidades configuradas diferentes");
            if (types.Count > 1) problems.Add("tipos de memoria diferentes");

            if (problems.Count == 0)
            {
                string channel = m.ChannelConfiguration == null ? "" : " " + m.ChannelConfiguration + ".";
                return T.Pass(r, m.Modules.Count + " modulos homogeneos." + channel, confidence);
            }

            return T.Warn(r, Severity.Low,
                "Modulos heterogeneos: " + string.Join(", ", problems.ToArray()) + ".",
                "Memoria mista funciona, mas todos os modulos operam na menor velocidade comum e o dual-channel pode ficar parcial. Para maximo desempenho, usar modulos identicos.",
                confidence);
        }

        // Erros WHEA NAO CORRIGIDOS sao defeito. Erros CORRIGIDOS sao rotina em
        // hardware saudavel, e o coletor antigo somava os dois num alerta unico
        // de "erro de memoria".
        private TestResult HardwareErrors(ScanContext ctx, Inventory inv)
        {
            TestResult r = T.Make("MEM-005", "Erros de hardware (WHEA)", Category,
                "Erros de hardware registrados pelo Windows, separados entre corrigidos e nao corrigidos.");

            EventsInfo e = inv.Events;
            if (!e.Accessible)
                return e.InaccessibleReason != null && e.InaccessibleReason.IndexOf("Administrador", StringComparison.OrdinalIgnoreCase) >= 0
                    ? T.RequiresAdmin(r, "Ler o log de eventos do sistema")
                    : T.NotTested(r, T.Name(e.InaccessibleReason, "Log de eventos indisponivel."));

            if (!e.WheaUncorrectedCount.HasValue && !e.WheaCorrectedCount.HasValue)
                return T.NotTested(r, "A consulta ao provedor WHEA-Logger nao pode ser concluida.");

            // A contagem de NAO corrigidos e a que importa para a
            // severidade. Sem ela (mesmo com a contagem de corrigidos
            // disponivel), nao ha teste possivel: tratar a ausencia como
            // zero afirmaria "nenhum nao corrigido" sobre um dado que nunca
            // foi de fato obtido.
            if (!e.WheaUncorrectedCount.HasValue)
                return T.NotTested(r, "A contagem de erros WHEA NAO corrigidos nao pode ser obtida (a consulta de nivel 1-2 falhou), mesmo com a contagem de corrigidos disponivel. Nao e possivel afirmar se ha erro nao corrigido.");

            int uncorrected = e.WheaUncorrectedCount.Value;
            bool correctedKnown = e.WheaCorrectedCount.HasValue;
            int corrected = correctedKnown ? e.WheaCorrectedCount.Value : 0;

            T.Ev(r, "EventLog", "WHEA-Logger nivel 1-2 (nao corrigidos), " + e.WindowDays + " dias", uncorrected);
            T.Ev(r, "EventLog", "WHEA-Logger nivel 3-4 (corrigidos), " + e.WindowDays + " dias", corrected);

            foreach (EventSummaryItem item in e.WheaEvents)
            {
                T.Ev(r, "EventLog", "System/" + T.Name(item.Provider, "WHEA") + " id " + item.Id,
                    T.Date(item.Time) + " - " + Html.Truncate(item.Message, 160));
            }

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (uncorrected > 0)
                return T.Error(r, Severity.High,
                    uncorrected + " erro(s) de hardware NAO corrigidos nos ultimos " + e.WindowDays + " dias.",
                    "Erro nao corrigido indica falha real de hardware. Rodar o Diagnostico de Memoria do Windows (mdsched.exe) ou o MemTest86, e conferir na mensagem do evento qual componente foi acusado - WHEA cobre CPU, memoria e PCIe, nao so RAM.",
                    confidence);

            if (corrected > 0)
                return T.Info(r,
                    corrected + " erro(s) de hardware CORRIGIDOS nos ultimos " + e.WindowDays + " dias, e nenhum nao corrigido. " +
                    "Erros corrigidos sao tratados pelo hardware e ocorrem em maquinas saudaveis; so merecem atencao se crescerem com o tempo.",
                    confidence);

            // uncorrected==0 esta confirmado neste ponto (garantido pelo
            // retorno antecipado acima) - so falta saber se corrected==0 e
            // um fato ou um fallback por ausencia de dado.
            if (!correctedKnown)
                return T.Unknown(r, "Nenhum erro WHEA NAO corrigido nos ultimos " + e.WindowDays +
                    " dias (confirmado), mas a contagem de erros corrigidos nao pode ser obtida.");

            return T.Pass(r, "Nenhum erro de hardware WHEA nos ultimos " + e.WindowDays + " dias.", confidence);
        }
    }

    public sealed class GpuTests : IDiagnosticTest
    {
        public string Category { get { return "Video"; } }

        public IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv)
        {
            List<TestResult> list = new List<TestResult>();

            if (inv.Gpus.Count == 0)
            {
                TestResult none = T.Make("GPU-001", "Adaptadores de video", Category,
                    "Enumera as GPUs fisicas reconhecidas pelo Windows.");
                list.Add(T.Unknown(none, "Nenhum adaptador de video PCI foi enumerado - Win32_VideoController pode estar indisponivel."));
                return list;
            }

            int n = 0;
            foreach (GpuInfo g in inv.Gpus)
            {
                n++;
                list.Add(DeviceState(g, n));
                list.Add(DriverQuality(g, n));
            }
            return list;
        }

        private TestResult DeviceState(GpuInfo g, int n)
        {
            string suffix = "-" + n.ToString("D2", CultureInfo.InvariantCulture);
            TestResult r = T.Make("GPU-001" + suffix, "Estado da GPU: " + T.Name(g.Name, "desconhecida"), Category,
                "Verifica se o Windows conseguiu inicializar a placa de video.");

            T.Ev(r, "WMI", "Win32_VideoController.PNPDeviceID", T.Name(g.PnpDeviceId, "?"));
            T.Ev(r, "Analise", "classificacao", T.Name(g.Kind, "?") + " (" + T.Name(g.KindSource, "?") + ")");
            if (g.VramBytes.HasValue) T.Ev(r, "Registry", "VRAM", T.Bytes(g.VramBytes) + " via " + T.Name(g.VramSource, "?"));

            // A fonte primaria aqui e WMI (Win32_VideoController) e nao ha,
            // no modelo atual, nenhuma segunda fonte independente que de
            // fato confirme o estado do dispositivo (diferente de
            // STO-001/SEC-001, que tem um flag proprio de cross-check). Sem
            // essa confirmacao, o bonus de AgreeingSource() nunca pode ser
            // reivindicado. Quando a classificacao Integrada/Dedicada veio
            // de heuristica de nome (KindSource comeca com "Heuristica") em
            // vez de um identificador estavel (PCI VendorId), a confianca
            // cai mais ainda - e cai mais ainda quando nem a heuristica
            // conseguiu decidir (Kind == "Indeterminado").
            Confidence confBuilder = Confidence.Build().Authoritative();
            bool heuristic = g.KindSource != null && g.KindSource.StartsWith("Heuristica", StringComparison.OrdinalIgnoreCase);
            if (heuristic) confBuilder = confBuilder.Heuristic();
            if (g.Kind == "Indeterminado") confBuilder = confBuilder.Heuristic();
            int confidence = confBuilder.Value;

            if (g.ConfigManagerErrorCode.HasValue)
            {
                uint code = g.ConfigManagerErrorCode.Value;
                string meaning = Sources.Native.ProblemCodeMeaning(code);
                T.Ev(r, "WMI", "Win32_VideoController.ConfigManagerErrorCode", code);

                // ARQUITETURA.md 5 define "Dispositivo com Code 43/10 ->
                // ERROR/HIGH", nao CRITICAL - usar T.Critical aqui
                // derrubaria o score em 40 pontos (o dobro do Error/High) e
                // forcaria o Status do laudo inteiro para CRITICO por um
                // problema tipicamente resolvido em minutos (reinstalar
                // driver).
                if (code == 43)
                    return T.Error(r, Severity.High,
                        "A placa de video foi PARADA pelo Windows (Code 43). " + meaning,
                        "Code 43 em GPU tem tres causas usuais, nesta ordem de frequencia: driver corrompido, falha de alimentacao/contato no slot, e defeito do chip. Reinstalar o driver limpo (DDU) e o primeiro passo; se persistir, testar a placa em outra maquina.",
                        confidence);

                if (Sources.Native.IsCodeAdministrativeChoice(code))
                    return T.Info(r, "Placa de video desativada administrativamente. " + meaning, confidence);

                return T.Error(r, Severity.High,
                    "Placa de video com problema. " + meaning,
                    "Reinstalar o driver do fabricante e verificar o encaixe da placa e a alimentacao auxiliar.",
                    confidence);
            }

            string vram = g.VramBytes.HasValue ? ", " + T.Bytes(g.VramBytes) + " de VRAM" : "";
            return T.Pass(r, T.Name(g.Kind, "GPU") + vram + ", operando normalmente.", confidence);
        }

        private TestResult DriverQuality(GpuInfo g, int n)
        {
            string suffix = "-" + n.ToString("D2", CultureInfo.InvariantCulture);
            TestResult r = T.Make("GPU-002" + suffix, "Driver de video: " + T.Name(g.Name, "desconhecida"), Category,
                "Avalia se o driver instalado e o do fabricante e ha quanto tempo nao e atualizado.");

            T.Ev(r, "WMI", "Win32_VideoController.DriverVersion", T.Name(g.DriverVersion, "?"));
            T.Ev(r, "WMI", "Win32_VideoController.DriverDate", T.Date(g.DriverDate));
            if (g.DriverProvider != null) T.Ev(r, "Registry", "ProviderName", g.DriverProvider);

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (g.IsGenericMicrosoftDriver == true)
                return T.Warn(r, Severity.Medium,
                    "A placa esta usando driver generico da Microsoft, nao o driver do fabricante.",
                    "Driver generico entrega imagem mas nao entrega aceleracao 3D completa, controle de energia nem multiplos monitores em alta taxa. Instalar o driver do fabricante (" +
                    T.Name(g.Manufacturer, "NVIDIA/AMD/Intel") + ") resolve.",
                    confidence);

            if (g.DriverAgeYears.HasValue && g.DriverAgeYears.Value >= 4)
                return T.Info(r,
                    "Driver de video com " + T.Num(g.DriverAgeYears, 1) + " anos (versao " + T.Name(g.DriverVersion, "?") + ").",
                    confidence);

            if (!g.DriverDate.HasValue)
                return T.Unknown(r, "A data do driver de video nao foi informada.");

            return T.Pass(r, "Driver " + T.Name(g.DriverVersion, "?") + " de " + T.Date(g.DriverDate) +
                (g.DriverProvider == null ? "" : ", fornecido por " + g.DriverProvider) + ".", confidence);
        }
    }

    public sealed class BatteryTests : IDiagnosticTest
    {
        public string Category { get { return "Bateria"; } }

        public IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv)
        {
            List<TestResult> list = new List<TestResult>();
            TestResult r = T.Make("BAT-001", "Saude da bateria", Category,
                "Compara a capacidade atual de carga com a capacidade de projeto.");

            if (inv.Battery == null)
            {
                if (inv.Machine.IsPortable == true)
                    list.Add(T.Unknown(r, "Equipamento identificado como portatil, mas nenhuma bateria foi detectada - bateria removida, desconectada ou com falha de comunicacao."));
                else
                    list.Add(T.NotApplicable(r, "Equipamento de mesa, sem bateria."));
                return list;
            }

            BatteryInfo b = inv.Battery;
            T.Ev(r, "WMI", "Win32_Battery.EstimatedChargeRemaining", T.Num(b.ChargePercent) + "%");

            if (!b.HealthPercent.HasValue)
            {
                list.Add(T.NotTested(r, T.Name(b.HealthSource, "O relatorio de bateria do Windows nao pode ser gerado.")));
                return list;
            }

            T.Ev(r, "powercfg", "DesignCapacity", T.Num(b.DesignCapacityMwh) + " mWh");
            T.Ev(r, "powercfg", "FullChargeCapacity", T.Num(b.FullChargeCapacityMwh) + " mWh");
            if (b.CycleCount.HasValue) T.Ev(r, "powercfg", "CycleCount", b.CycleCount.Value);

            double health = b.HealthPercent.Value;
            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;
            string cycles = b.CycleCount.HasValue && b.CycleCount.Value > 0 ? " apos " + b.CycleCount.Value + " ciclos" : "";

            if (health <= 50)
                list.Add(T.Error(r, Severity.High,
                    "Bateria com " + T.Num(health, 1) + "% da capacidade original" + cycles + ".",
                    "Bateria proxima do fim da vida util: autonomia muito reduzida e risco de desligamento abrupto fora da tomada. Recomenda-se substituicao.",
                    confidence));
            else if (health <= 70)
                list.Add(T.Warn(r, Severity.Medium,
                    "Bateria com " + T.Num(health, 1) + "% da capacidade original" + cycles + ".",
                    "Desgaste perceptivel na autonomia. Planejar substituicao; ainda utilizavel.",
                    confidence));
            else
                list.Add(T.Pass(r, "Bateria com " + T.Num(health, 1) + "% da capacidade original" + cycles + ".", confidence));

            return list;
        }
    }

    public sealed class PerformanceTests : IDiagnosticTest
    {
        public string Category { get { return "Desempenho"; } }

        public IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv)
        {
            List<TestResult> list = new List<TestResult>();

            TestResult r = T.Make("PERF-001", "Carga de CPU no momento da coleta", Category,
                "Amostra instantanea de uso de processador.");

            if (!inv.Performance.CpuLoadPercent.HasValue)
            {
                list.Add(T.Unknown(r, "Nao foi possivel amostrar o uso de CPU."));
                return list;
            }

            double load = inv.Performance.CpuLoadPercent.Value;
            T.Ev(r, "Native", "amostragem de tempo de processador", T.Num(load, 1) + "%");
            if (inv.Performance.ProcessCount.HasValue) T.Ev(r, "Native", "processos em execucao", inv.Performance.ProcessCount.Value);

            // Pico momentaneo nao e problema (item 30 do briefing): a confianca
            // e reduzida e o resultado nunca passa de WARNING.
            int confidence = Confidence.Build().SingleVolatileSample().Value;

            if (load >= 90)
                list.Add(T.Warn(r, Severity.Low,
                    "CPU em " + T.Num(load, 0) + "% durante a coleta, com " + T.Num(inv.Performance.ProcessCount) + " processos ativos.",
                    "Esta e uma amostra de poucos segundos e pode ser um pico normal. Confirmar no Gerenciador de Tarefas se a carga se sustenta e qual processo a causa.",
                    confidence));
            else
                list.Add(T.Pass(r, "CPU em " + T.Num(load, 0) + "% durante a coleta.", confidence));

            return list;
        }
    }
}
