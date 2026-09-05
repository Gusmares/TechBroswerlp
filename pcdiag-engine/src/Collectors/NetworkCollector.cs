using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    public sealed class NetworkCollector : ICollector
    {
        public string Name { get { return "Network"; } }

        private readonly bool _testConnectivity;

        public NetworkCollector(bool testConnectivity)
        {
            _testConnectivity = testConnectivity;
        }

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            CollectAdapters(ctx, src, inv);
            if (_testConnectivity) TestConnectivity(ctx, inv);
            else inv.Network.ConnectivityNote = "Testes de conectividade desativados nesta execucao (--no-connectivity).";
        }

        private void CollectAdapters(ScanContext ctx, SourceSet src, Inventory inv)
        {
            IList<DataRow> adapters = Try.Get(ctx, Name, "Win32_NetworkAdapter", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT Index, Name, NetConnectionID, NetConnectionStatus, Speed, MACAddress, PNPDeviceID, " +
                    "Manufacturer, AdapterTypeID, PhysicalAdapter, NetEnabled, ConfigManagerErrorCode FROM Win32_NetworkAdapter");
            });

            if (adapters == null) return;

            IList<DataRow> configs = Try.Get(ctx, Name, "Win32_NetworkAdapterConfiguration", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT Index, IPAddress, DefaultIPGateway, DNSServerSearchOrder, DHCPEnabled, MACAddress FROM Win32_NetworkAdapterConfiguration");
            });

            Dictionary<int, DataRow> configByIndex = new Dictionary<int, DataRow>();
            if (configs != null)
            {
                foreach (DataRow c in configs)
                {
                    int? idx = c.Int("Index");
                    if (idx.HasValue) configByIndex[idx.Value] = c;
                }
            }

            int up = 0;
            bool anyGateway = false, anyDns = false;

            foreach (DataRow a in adapters)
            {
                string pnp = a.Str("PNPDeviceID");
                string description = a.Str("Name");

                NetworkAdapterInfo n = new NetworkAdapterInfo();
                n.Name = Helpers.FirstNonEmpty(a.Str("NetConnectionID"), description);
                n.Description = description;
                n.Manufacturer = SystemCollector.IsPlaceholder(a.Str("Manufacturer")) ? null : a.Str("Manufacturer");
                n.MacAddress = a.Str("MACAddress");

                int? cm = a.Int("ConfigManagerErrorCode");
                if (cm.HasValue && cm.Value != 0) n.ConfigManagerErrorCode = (uint)cm.Value;

                int? statusCode = a.Int("NetConnectionStatus");
                n.Status = ConnectionStatusName(statusCode);
                n.IsUp = statusCode.HasValue && statusCode.Value == 2;

                // Velocidade de link e bits/s DECIMAL. Dividir por 1048576
                // (como fazia o coletor antigo) exibe 953 Mbps num link de
                // 1 Gbps.
                long? speed = a.Long("Speed");
                if (speed.HasValue && speed.Value > 0 && speed.Value < 400000000000L)
                    n.LinkSpeedBitsPerSecond = speed.Value;

                ClassifyInterface(n, pnp, a.Int("AdapterTypeID"), a.Bool("PhysicalAdapter"));

                // Precisa classificar a interface antes de contar como "up" -
                // vEthernet (Hyper-V), Host-Only (VirtualBox) e adaptadores
                // TAP de VPN sao reportados pelo Windows como
                // permanentemente "Conectado", entao contar qualquer
                // interface com esse status inflaria AdaptersUp com
                // adaptadores virtuais mesmo com o cabo fisico desconectado.
                // So conta interface fisica de verdade.
                if (n.IsUp == true && !n.IsVirtual) up++;

                int? index = a.Int("Index");
                if (index.HasValue)
                {
                    DataRow cfg;
                    if (configByIndex.TryGetValue(index.Value, out cfg))
                    {
                        AddAddresses(cfg.StrArray("IPAddress"), n);
                        string[] gws = cfg.StrArray("DefaultIPGateway");
                        if (gws != null) { n.Gateways.AddRange(gws); if (gws.Length > 0) anyGateway = true; }
                        string[] dns = cfg.StrArray("DNSServerSearchOrder");
                        if (dns != null) { n.DnsServers.AddRange(dns); if (dns.Length > 0) anyDns = true; }
                        n.DhcpEnabled = cfg.Bool("DHCPEnabled");
                    }
                }

                inv.Network.Adapters.Add(n);
            }

            inv.Network.AdaptersUp = up;
            inv.Network.HasDefaultGateway = anyGateway;
            inv.Network.HasDnsConfigured = anyDns;
        }

        private static void AddAddresses(string[] addresses, NetworkAdapterInfo n)
        {
            if (addresses == null) return;
            foreach (string a in addresses)
            {
                if (string.IsNullOrEmpty(a)) continue;
                if (a.IndexOf(':') >= 0) n.IPv6Addresses.Add(a);
                else n.IPv4Addresses.Add(a);
            }
        }

        // Distingue placa fisica de adaptador virtual e identifica a origem do
        // virtual (VPN, hipervisor, WSL, loopback), como pede o item 19.
        public static void ClassifyInterface(NetworkAdapterInfo n, string pnpDeviceId, int? adapterTypeId, bool? physical)
        {
            string hay = ((n.Description == null ? "" : n.Description) + " " + (n.Name == null ? "" : n.Name)).ToLowerInvariant();

            string[][] virtualHints = new string[][]
            {
                new string[] { "vmware", "VMware" },
                new string[] { "virtualbox", "VirtualBox" },
                new string[] { "hyper-v", "Hyper-V" },
                new string[] { "vethernet", "Hyper-V" },
                new string[] { "wsl", "WSL" },
                new string[] { "loopback", "Loopback" },
                new string[] { "tap-windows", "VPN (TAP)" },
                new string[] { "tap-nordvpn", "VPN" },
                new string[] { "openvpn", "VPN" },
                new string[] { "wireguard", "VPN" },
                new string[] { "wan miniport", "WAN Miniport" },
                new string[] { "teredo", "Tunelamento" },
                new string[] { "virtual", "Virtual" }
            };

            foreach (string[] h in virtualHints)
            {
                if (hay.IndexOf(h[0], StringComparison.Ordinal) >= 0)
                {
                    n.IsVirtual = true;
                    n.VirtualKind = h[1];
                    n.InterfaceType = "Virtual";
                    return;
                }
            }

            // PNPDeviceID de hardware real comeca com PCI\ ou USB\; adaptador
            // sintetico comeca com ROOT\ ou SWD\.
            if (pnpDeviceId != null &&
                (pnpDeviceId.StartsWith("ROOT\\", StringComparison.OrdinalIgnoreCase) ||
                 pnpDeviceId.StartsWith("SWD\\", StringComparison.OrdinalIgnoreCase)))
            {
                n.IsVirtual = true;
                n.VirtualKind = "Adaptador de software";
                n.InterfaceType = "Virtual";
                return;
            }

            if (physical == false)
            {
                n.IsVirtual = true;
                n.VirtualKind = "Nao fisico (reportado pelo Windows)";
                n.InterfaceType = "Virtual";
                return;
            }

            if (hay.IndexOf("wi-fi", StringComparison.Ordinal) >= 0 ||
                hay.IndexOf("wifi", StringComparison.Ordinal) >= 0 ||
                hay.IndexOf("wireless", StringComparison.Ordinal) >= 0 ||
                hay.IndexOf("802.11", StringComparison.Ordinal) >= 0)
            {
                n.InterfaceType = "Wi-Fi";
                return;
            }

            if (hay.IndexOf("bluetooth", StringComparison.Ordinal) >= 0)
            {
                n.InterfaceType = "Bluetooth";
                return;
            }

            if (adapterTypeId.HasValue && adapterTypeId.Value == 0)
            {
                n.InterfaceType = "Ethernet";
                return;
            }

            n.InterfaceType = "Outro";
        }

        // Conectividade em camadas: o objetivo e separar "sem internet" de
        // "DNS quebrado" de "gateway inacessivel" de "interface desativada",
        // que sao quatro problemas com solucoes diferentes.
        private void TestConnectivity(ScanContext ctx, Inventory inv)
        {
            NetworkInfo net = inv.Network;

            if (net.AdaptersUp.HasValue && net.AdaptersUp.Value == 0)
            {
                net.GatewayReachable = "NotTested";
                net.DnsResolves = "NotTested";
                net.InternetReachable = "NotTested";
                net.HttpsReachable = "NotTested";
                net.ConnectivityNote = "Nenhuma interface de rede conectada - testes de conectividade nao se aplicam.";
                return;
            }

            string gateway = FirstGateway(net);
            if (gateway == null)
            {
                net.GatewayReachable = "NotTested";
                net.ConnectivityNote = "Nenhum gateway padrao configurado.";
            }
            else
            {
                // O registro de seguranca deixa explicito que o teste rodou,
                // sem o IP do gateway (endereco interno do cliente) -
                // logs/security.log fica na mesma pasta do laudo e costuma
                // ser zipado junto, e --privacy-safe depende de nenhum dado
                // de rede do cliente vazar para ali. O IP nao acrescenta
                // nada ao registro (o teste em si ja e o fato relevante) -
                // so o texto fixo, sem o valor.
                ctx.Log.Security(Name, "Teste de conectividade: ping ICMP para o gateway configurado");
                PingOutcome ping = PingHost(gateway, 1500);
                net.GatewayLatencyMs = ping.LatencyMs;
                net.GatewayReachable = ping.Reachable.HasValue ? (ping.Reachable.Value ? "Yes" : "No") : "Unknown";
            }

            // Resolucao de nome usa o resolvedor do proprio sistema; nao envia
            // dado nenhum da maquina, so consulta um nome publico.
            // Dns.GetHostEntry e sincrono e sem timeout proprio - numa
            // maquina sem internet ou com DNS inalcancavel, ele pode
            // bloquear alem do orcamento do modulo (30 s no ModuleRunner).
            // Por isso usa o par Begin/EndGetHostEntry com WaitOne(2000), o
            // mesmo padrao ja usado em TcpProbe. Quando estoura o timeout, o
            // resultado fica "Unknown" (nao "No"): o timeout nao prova que o
            // DNS esta quebrado, so que nao respondeu a tempo.
            ctx.Log.Security(Name, "Teste de conectividade: resolucao DNS de um nome publico");
            bool dnsOk = false;
            bool dnsTimedOut = false;
            Try.Do(ctx, Name, "DNS resolve", delegate
            {
                IAsyncResult ar = Dns.BeginGetHostEntry("www.microsoft.com", null, null);
                if (!ar.AsyncWaitHandle.WaitOne(2000, false))
                {
                    dnsTimedOut = true;
                    return;
                }
                IPHostEntry entry = Dns.EndGetHostEntry(ar);
                dnsOk = entry != null && entry.AddressList != null && entry.AddressList.Length > 0;
            });
            net.DnsResolves = dnsTimedOut ? "Unknown" : (dnsOk ? "Yes" : "No");

            ctx.Log.Security(Name, "Teste de conectividade: conexao TCP 443 para um host publico");
            bool httpsOk = TcpProbe("www.microsoft.com", 443, 2500);
            net.HttpsReachable = httpsOk ? "Yes" : "No";
            net.InternetReachable = httpsOk ? "Yes" : (dnsOk ? "No" : "Unknown");

            net.ConnectivityNote = BuildConnectivityDiagnosis(net);
        }

        private sealed class PingOutcome
        {
            public bool? Reachable { get; set; }
            public double? LatencyMs { get; set; }
        }

        private static string FirstGateway(NetworkInfo net)
        {
            foreach (NetworkAdapterInfo a in net.Adapters)
            {
                if (a.IsUp != true) continue;
                foreach (string g in a.Gateways)
                {
                    if (!string.IsNullOrEmpty(g) && g.IndexOf(':') < 0) return g;
                }
            }
            return null;
        }

        private static PingOutcome PingHost(string host, int timeoutMs)
        {
            PingOutcome outcome = new PingOutcome();
            try
            {
                using (Ping p = new Ping())
                {
                    PingReply reply = p.Send(host, timeoutMs);
                    if (reply == null) return outcome;
                    if (reply.Status == IPStatus.Success)
                    {
                        outcome.Reachable = true;
                        outcome.LatencyMs = reply.RoundtripTime;
                    }
                    else
                    {
                        outcome.Reachable = false;
                    }
                }
            }
            catch
            {
                // Reachable fica null: "nao foi possivel testar", que e
                // diferente de "nao respondeu".
            }
            return outcome;
        }

        private static bool TcpProbe(string host, int port, int timeoutMs)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    IAsyncResult ar = client.BeginConnect(host, port, null, null);
                    bool ok = ar.AsyncWaitHandle.WaitOne(timeoutMs, false);
                    if (!ok) return false;
                    client.EndConnect(ar);
                    return client.Connected;
                }
            }
            catch
            {
                return false;
            }
        }

        // Traduz a combinacao de resultados em uma frase que aponta a camada
        // que falhou, em vez de um generico "sem internet".
        public static string BuildConnectivityDiagnosis(NetworkInfo net)
        {
            bool gwYes = net.GatewayReachable == "Yes";
            bool gwNo = net.GatewayReachable == "No";
            bool dnsYes = net.DnsResolves == "Yes";
            bool httpsYes = net.HttpsReachable == "Yes";

            if (httpsYes && dnsYes) return "Conectividade completa: gateway, DNS e saida HTTPS funcionando.";
            if (!dnsYes && httpsYes) return "Saida HTTPS funciona mas a resolucao de nomes falhou - problema no servidor DNS configurado.";
            if (dnsYes && !httpsYes) return "DNS resolve mas a conexao HTTPS nao completa - possivel bloqueio de firewall, proxy ou filtro de rede.";
            if (gwYes && !dnsYes) return "O gateway responde mas o DNS nao resolve - a rede local esta ok e o problema esta no DNS ou na saida para a internet.";
            if (gwNo) return "O gateway padrao nao respondeu ao ping - pode ser bloqueio de ICMP no roteador ou falha real na rede local.";
            return "Conectividade parcial ou nao determinada - ver os resultados por camada.";
        }

        public static string ConnectionStatusName(int? code)
        {
            if (!code.HasValue) return null;
            switch (code.Value)
            {
                case 0: return "Desconectado";
                case 1: return "Conectando";
                case 2: return "Conectado";
                case 3: return "Desconectando";
                case 4: return "Hardware ausente";
                case 5: return "Hardware desativado";
                case 6: return "Hardware com falha";
                case 7: return "Midia desconectada (cabo fora)";
                case 8: return "Autenticando";
                case 9: return "Autenticacao concluida";
                case 10: return "Falha de autenticacao";
                case 11: return "Endereco invalido";
                case 12: return "Credenciais requeridas";
                default: return "Status " + code.Value;
            }
        }
    }
}
