using System;
using System.Collections.Generic;
using System.Globalization;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Analysis
{
    public sealed class DeviceTests : IDiagnosticTest
    {
        public string Category { get { return "Dispositivos"; } }

        public IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv)
        {
            List<TestResult> list = new List<TestResult>();
            list.Add(ProblemDevices(inv));
            list.Add(UnknownDevices(inv));
            list.Add(HiddenProblemDevices(inv));
            list.Add(UnsignedDrivers(inv));
            return list;
        }

        private TestResult ProblemDevices(Inventory inv)
        {
            TestResult r = T.Make("DEV-001", "Dispositivos com problema", Category,
                "Dispositivos presentes que o Windows nao conseguiu inicializar.");

            if (inv.Devices.Count == 0)
                return T.Unknown(r, "Nenhum dispositivo foi enumerado - SetupAPI e WMI falharam. Ausencia de enumeracao NAO significa ausencia de problema.");

            List<DeviceInfo> problems = new List<DeviceInfo>();
            List<DeviceInfo> disabled = new List<DeviceInfo>();

            foreach (DeviceInfo d in inv.Devices)
            {
                if (!d.ProblemCode.HasValue || d.ProblemCode.Value == 0) continue;
                if (!d.IsPresent) continue;
                if (d.IsAdministrativeChoice) disabled.Add(d);
                else problems.Add(d);
            }

            // A fonte nativa (SetupAPI/CfgMgr32, que enxerga TODO dispositivo,
            // inclusive oculto/fantasma) pode ter falhado e inv.Devices ainda
            // assim vir populado so pela WMI (CollectWmi). O rotulo da
            // evidencia reflete qual fonte de fato respondeu, em vez de
            // assumir SetupAPI incondicionalmente e reivindicar confianca de
            // "duas fontes concordando" quando a segunda nunca respondeu.
            string sourceLabel = inv.DevicesNativeSourceAvailable ? "SetupAPI" : "WMI (SetupAPI indisponivel)";
            T.Ev(r, sourceLabel, "dispositivos enumerados", inv.Devices.Count);
            T.Ev(r, sourceLabel, "com problema (excluindo desativados)", problems.Count);
            T.Ev(r, sourceLabel, "desativados administrativamente", disabled.Count);
            if (!inv.DevicesNativeSourceAvailable)
                T.Ev(r, "Analise", "fonte nativa indisponivel", T.Name(inv.DevicesNativeSourceUnavailableReason, "motivo desconhecido"));

            foreach (DeviceInfo d in problems)
                T.Ev(r, "CfgMgr32", "CM_Get_DevNode_Status(" + T.Name(d.Name, "?") + ")", d.ProblemMeaning);

            Confidence confBuilder = Confidence.Build().Authoritative();
            if (inv.DevicesNativeSourceAvailable) confBuilder = confBuilder.AgreeingSource();
            int confidence = confBuilder.Value;

            if (problems.Count == 0)
            {
                // Sem a fonte que enxerga dispositivo oculto/fantasma, "zero
                // problema" nao pode ser uma aprovacao confiante - SetupAPI
                // e justamente a fonte que capta o Code 12 de um resto de
                // driver de hardware ja trocado, que a WMI sozinha nao ve.
                if (!inv.DevicesNativeSourceAvailable)
                    return T.Unknown(r, "A fonte SetupAPI/CfgMgr32 (que enxerga dispositivo oculto/fantasma) nao respondeu; " +
                        "a WMI sozinha nao encontrou dispositivo com erro, mas nao cobre os mesmos casos - resultado parcial, nao uma aprovacao completa.");

                // Dispositivo desativado (Code 22, tipicamente placa de
                // rede/Wi-Fi desligada no Gerenciador de Dispositivos - causa
                // frequente de "nao conecta") recebe um INFO explicito,
                // listando cada dispositivo desativado, em vez de ficar
                // escondido dentro de uma aprovacao silenciosa.
                if (disabled.Count > 0)
                {
                    List<string> disabledNames = new List<string>();
                    foreach (DeviceInfo d in disabled)
                    {
                        T.Ev(r, "CfgMgr32", "CM_Get_DevNode_Status(" + T.Name(d.Name, "?") + ")", d.ProblemMeaning);
                        disabledNames.Add(T.Name(d.Name, "?") + " [" + T.Name(d.Class, "sem classe") + ", Code " + d.ProblemCode.Value + "]");
                    }

                    return T.Info(r,
                        "Nenhum dispositivo com erro. " + disabled.Count + " dispositivo(s) desativado(s) administrativamente: " +
                        string.Join("; ", disabledNames.ToArray()) + ".",
                        confidence);
                }

                return T.Pass(r, "Nenhum dispositivo com erro no Gerenciador de Dispositivos.", confidence);
            }

            bool hardwareSuspect = false;
            List<string> names = new List<string>();
            foreach (DeviceInfo d in problems)
            {
                if (d.IsHardwareSuspect) hardwareSuspect = true;
                names.Add(T.Name(d.Name, "?") + " [" + T.Name(d.Class, "sem classe") + ", Code " + d.ProblemCode.Value + "]");
            }

            string listText = string.Join("; ", names.ToArray());

            if (hardwareSuspect)
                return T.Error(r, Severity.High,
                    problems.Count + " dispositivo(s) com erro, incluindo codigo que sugere falha de hardware ou driver: " + listText,
                    "Comecar pelo driver do fabricante do dispositivo. Se o codigo for 10, 43 ou 12 e a reinstalacao do driver nao resolver, testar o dispositivo em outra porta/slot ou em outra maquina.",
                    confidence);

            return T.Warn(r, Severity.Medium,
                problems.Count + " dispositivo(s) com erro: " + listText,
                "Instalar os drivers correspondentes. A maioria desses codigos e resolvida com o driver correto do fabricante.",
                confidence);
        }

        private TestResult UnknownDevices(Inventory inv)
        {
            TestResult r = T.Make("DEV-002", "Dispositivos desconhecidos", Category,
                "Dispositivos presentes sem driver instalado - aparecem como 'Dispositivo desconhecido'.");

            if (inv.Devices.Count == 0)
                return T.NotTested(r, "Nenhum dispositivo foi enumerado.");

            List<DeviceInfo> unknown = new List<DeviceInfo>();
            foreach (DeviceInfo d in inv.Devices)
            {
                if (!d.IsPresent) continue;

                bool code28 = d.ProblemCode.HasValue && d.ProblemCode.Value == 28;

                // Pseudo-dispositivos (raiz da arvore, dispositivos de
                // software) nao tem classe nem driver por natureza. Sem esta
                // excecao, HTREE\ROOT\0 aparecia como "dispositivo sem driver"
                // em toda maquina. Um codigo 28 explicito ainda conta.
                if (!code28 && Collectors.Helpers.IsPseudoEnumerator(d.Enumerator, d.InstanceId)) continue;

                bool noClass = string.IsNullOrEmpty(d.Class);
                bool unknownName = d.Name != null &&
                    (d.Name.IndexOf("Unknown", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     d.Name.IndexOf("desconhecid", StringComparison.OrdinalIgnoreCase) >= 0);

                if (noClass || unknownName || code28) unknown.Add(d);
            }

            int confidence = Confidence.Build().Authoritative().Value;

            if (unknown.Count == 0)
                return T.Pass(r, "Todos os dispositivos presentes tem driver e classe identificados.", confidence);

            List<string> ids = new List<string>();
            foreach (DeviceInfo d in unknown)
            {
                T.Ev(r, "SetupAPI", "HardwareID de " + T.Name(d.Name, "?"), T.Name(d.HardwareIds, "nao informado"));
                ids.Add(T.Name(d.Name, T.Name(d.InstanceId, "?")));
            }

            return T.Warn(r, Severity.Medium,
                unknown.Count + " dispositivo(s) sem driver: " + string.Join("; ", ids.ToArray()),
                "O HardwareID de cada um esta nas evidencias deste teste - e com ele que se identifica o componente e se localiza o driver correto no site do fabricante.",
                confidence);
        }

        // Dispositivo oculto/fantasma so aparece pela SetupAPI. E onde ficam
        // restos de hardware ja trocado, que explicam conflito de recurso.
        private TestResult HiddenProblemDevices(Inventory inv)
        {
            TestResult r = T.Make("DEV-003", "Dispositivos ocultos com registro de problema", Category,
                "Dispositivos ja desconectados que permanecem registrados no sistema.");

            if (inv.Devices.Count == 0) return T.NotTested(r, "Nenhum dispositivo foi enumerado.");

            int hidden = 0;
            foreach (DeviceInfo d in inv.Devices)
            {
                if (d.IsHidden) hidden++;
            }

            T.Ev(r, "SetupAPI", "dispositivos nao presentes (fantasma)", hidden);
            int confidence = Confidence.Build().Authoritative().Value;

            // Dezenas de dispositivos fantasma sao NORMAIS (todo pendrive ja
            // conectado deixa um). So o volume muito alto merece nota.
            if (hidden >= 200)
                return T.Info(r,
                    hidden + " dispositivos registrados mas nao presentes. Volume alto e normal em maquina antiga (cada dispositivo USB ja conectado deixa um registro), mas pode poluir o Gerenciador de Dispositivos.",
                    confidence);

            return T.Pass(r, hidden + " dispositivo(s) registrado(s) mas nao presente(s) - dentro do normal.", confidence);
        }

        private TestResult UnsignedDrivers(Inventory inv)
        {
            TestResult r = T.Make("DEV-004", "Assinatura digital dos drivers", Category,
                "Drivers sem assinatura digital valida.");

            if (inv.Drivers.Count == 0)
                return T.NotTested(r, "A consulta de drivers assinados (Win32_PnPSignedDriver) nao retornou dados - ela e lenta e pode ter estourado o timeout do modulo.");

            // d.IsSigned == null (WMI nao reportou a propriedade IsSigned
            // para aquele driver) e contado separadamente do grupo "sem
            // assinatura": um driver de assinatura DESCONHECIDA nao deve
            // engrossar silenciosamente o grupo "possui assinatura", nem
            // permitir que o Pass abaixo afirme "todos possuem assinatura
            // digital" sem confirmacao para esses drivers.
            List<string> unsigned = new List<string>();
            int unknown = 0;
            foreach (DriverInfo d in inv.Drivers)
            {
                if (d.IsSigned == false) unsigned.Add(T.Name(d.DeviceName, "?") + " (" + T.Name(d.Provider, "sem fornecedor") + ")");
                else if (!d.IsSigned.HasValue) unknown++;
            }

            T.Ev(r, "WMI", "Win32_PnPSignedDriver (total)", inv.Drivers.Count);
            T.Ev(r, "WMI", "drivers com IsSigned=False", unsigned.Count);
            if (unknown > 0) T.Ev(r, "WMI", "drivers com IsSigned nao reportado (desconhecido)", unknown);

            int confidence = Confidence.Build().Authoritative().Value;

            if (unsigned.Count == 0 && unknown == 0)
                return T.Pass(r, "Todos os " + inv.Drivers.Count + " drivers enumerados possuem assinatura digital.", confidence);

            if (unsigned.Count == 0)
                return T.Info(r,
                    "Nenhum driver confirmado sem assinatura, mas " + unknown + " de " + inv.Drivers.Count +
                    " nao reportaram a propriedade IsSigned - o estado deles e desconhecido, nao confirmado como assinado.",
                    confidence);

            foreach (string u in unsigned) T.Ev(r, "WMI", "driver sem assinatura", u);

            return T.Warn(r, Severity.Medium,
                unsigned.Count + " driver(s) sem assinatura digital: " + string.Join("; ", unsigned.ToArray()),
                "Driver sem assinatura nao e necessariamente malicioso - hardware antigo e software de nicho costumam ter. Vale conferir a procedencia de cada um e substituir por versao assinada quando existir.",
                confidence);
        }
    }

    public sealed class NetworkTests : IDiagnosticTest
    {
        public string Category { get { return "Rede"; } }

        public IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv)
        {
            List<TestResult> list = new List<TestResult>();
            list.Add(AdapterHealth(inv));
            list.Add(Connectivity(inv));
            list.Add(LinkSpeed(inv));
            return list;
        }

        private TestResult AdapterHealth(Inventory inv)
        {
            TestResult r = T.Make("NET-001", "Estado dos adaptadores de rede", Category,
                "Verifica se ha adaptador de rede fisico com erro de driver.");

            NetworkInfo net = inv.Network;
            if (net.Adapters.Count == 0)
                return T.Unknown(r, "Nenhum adaptador de rede foi enumerado.");

            List<string> broken = new List<string>();
            int physical = 0, virtualCount = 0;

            foreach (NetworkAdapterInfo a in net.Adapters)
            {
                if (a.IsVirtual) { virtualCount++; continue; }
                physical++;
                if (a.ConfigManagerErrorCode.HasValue && a.ConfigManagerErrorCode.Value != 0)
                {
                    broken.Add(T.Name(a.Name, "?") + " (Code " + a.ConfigManagerErrorCode.Value + ")");
                    T.Ev(r, "WMI", "Win32_NetworkAdapter.ConfigManagerErrorCode(" + T.Name(a.Name, "?") + ")",
                        Sources.Native.ProblemCodeMeaning(a.ConfigManagerErrorCode.Value));
                }
            }

            T.Ev(r, "WMI", "adaptadores fisicos", physical);
            T.Ev(r, "WMI", "adaptadores virtuais", virtualCount);
            T.Ev(r, "WMI", "adaptadores conectados", T.Num(net.AdaptersUp));

            int confidence = Confidence.Build().Authoritative().Value;

            if (broken.Count > 0)
                return T.Error(r, Severity.High,
                    "Adaptador de rede com erro: " + string.Join("; ", broken.ToArray()),
                    "Instalar o driver de rede do fabricante da placa-mae ou do adaptador. Adaptador com Code 10 costuma voltar a funcionar com o driver correto; se nao voltar, testar outra placa.",
                    confidence);

            if (physical == 0)
                return T.Warn(r, Severity.Medium,
                    "Nenhum adaptador de rede fisico foi identificado (" + virtualCount + " virtuais).",
                    "Verificar se o driver de rede esta instalado - sem ele o adaptador nao aparece como fisico.",
                    confidence);

            return T.Pass(r, physical + " adaptador(es) fisico(s) sem erro, " +
                T.Num(net.AdaptersUp) + " conectado(s). " + virtualCount + " adaptador(es) virtual(is).", confidence);
        }

        private TestResult Connectivity(Inventory inv)
        {
            TestResult r = T.Make("NET-002", "Conectividade por camada", Category,
                "Separa falha de gateway, de DNS e de saida para a internet.");

            NetworkInfo net = inv.Network;

            if (net.GatewayReachable == null)
                return T.NotTested(r, T.Name(net.ConnectivityNote, "Testes de conectividade nao foram executados."));

            T.Ev(r, "ICMP", "gateway alcancavel", T.Name(net.GatewayReachable, "?"));
            T.Ev(r, "DNS", "resolucao de nome publico", T.Name(net.DnsResolves, "?"));
            T.Ev(r, "TCP", "conexao 443 para host publico", T.Name(net.HttpsReachable, "?"));
            if (net.GatewayLatencyMs.HasValue) T.Ev(r, "ICMP", "latencia ate o gateway", T.Num(net.GatewayLatencyMs, 0) + " ms");

            // ICMP (gateway), DNS (resolucao) e TCP (HTTPS) medem TRES
            // FATOS DIFERENTES da cadeia de conectividade, nao a mesma
            // leitura confirmada por uma segunda fonte independente -
            // AgreeingSource() exige a segunda condicao (mesmo fato, fonte
            // diferente), que nao e o caso aqui.
            int confidence = Confidence.Build().Authoritative().Value;
            string diagnosis = T.Name(net.ConnectivityNote, "Sem diagnostico.");

            if (net.HttpsReachable == "Yes" && net.DnsResolves == "Yes")
                return T.Pass(r, diagnosis, confidence);

            if (net.GatewayReachable == "NotTested" && net.AdaptersUp == 0)
                return T.NotApplicable(r, "Nenhuma interface de rede conectada.");

            if (net.DnsResolves == "No" && net.HttpsReachable == "No")
                return T.Error(r, Severity.High, diagnosis,
                    "Sem saida para a internet. Conferir, nesta ordem: cabo/Wi-Fi conectado, IP obtido por DHCP, gateway respondendo e servidor DNS configurado.",
                    confidence);

            return T.Warn(r, Severity.Medium, diagnosis,
                "Conectividade parcial. O resultado por camada acima aponta onde a cadeia quebra.",
                confidence);
        }

        // Placa Gigabit negociando 100 Mbps normalmente e cabo ruim ou porta de
        // switch degradada - um achado concreto e barato de corrigir.
        private TestResult LinkSpeed(Inventory inv)
        {
            TestResult r = T.Make("NET-003", "Velocidade de link negociada", Category,
                "Compara a velocidade negociada com a esperada para o tipo de adaptador.");

            List<string> slow = new List<string>();
            int checkedCount = 0;

            foreach (NetworkAdapterInfo a in inv.Network.Adapters)
            {
                if (a.IsVirtual || a.IsUp != true || !a.LinkSpeedBitsPerSecond.HasValue) continue;
                if (a.InterfaceType != "Ethernet") continue;

                checkedCount++;
                long mbps = a.LinkSpeedBitsPerSecond.Value / 1000000L;
                T.Ev(r, "WMI", "Win32_NetworkAdapter.Speed(" + T.Name(a.Name, "?") + ")", mbps + " Mbps");

                if (mbps > 0 && mbps <= 100) slow.Add(T.Name(a.Name, "?") + " a " + mbps + " Mbps");
            }

            if (checkedCount == 0)
                return T.NotApplicable(r, "Nenhum adaptador Ethernet conectado para avaliar velocidade de link.");

            int confidence = Confidence.Build().Authoritative().Value;

            if (slow.Count > 0)
                return T.Info(r,
                    "Link Ethernet negociado em velocidade baixa: " + string.Join("; ", slow.ToArray()) +
                    ". Se a placa e o switch forem Gigabit, isso normalmente e cabo com par rompido ou conector mal crimpado.",
                    confidence);

            return T.Pass(r, checkedCount + " link(s) Ethernet negociado(s) em velocidade adequada.", confidence);
        }
    }
}
