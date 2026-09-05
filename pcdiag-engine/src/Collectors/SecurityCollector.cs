using System;
using System.Collections.Generic;
using System.Globalization;
using System.ServiceProcess;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    public sealed class SecurityCollector : ICollector
    {
        public string Name { get { return "Security"; } }

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            CollectDefender(ctx, src, inv.Security);
            CrossCheckDefenderService(ctx, inv.Security);
            CrossCheckDefenderPolicy(ctx, src, inv.Security);
            CollectThirdPartyAv(ctx, src, inv.Security);
            CollectFirewall(ctx, src, inv.Security);
            CollectUacAndSmartScreen(ctx, src, inv.Security);
            CollectAccounts(ctx, src, inv.Security);
        }

        // Estados possiveis, todos distintos (item 25):
        //   Enabled | Disabled | NotAvailable | RequiresAdmin | Error
        // e, quando desativado, a RAZAO: usuario, politica de dominio, ou
        // presenca de antivirus de terceiro (que desliga o Defender de forma
        // legitima e NAO deve virar alerta de seguranca).
        private void CollectDefender(ScanContext ctx, SourceSet src, SecurityInfo s)
        {
            IList<DataRow> status = Try.Get(ctx, Name, "MSFT_MpComputerStatus", delegate
            {
                return src.Wmi.Query(WmiSource.Defender,
                    "SELECT RealTimeProtectionEnabled, AntispywareEnabled, IsTamperProtected, " +
                    "AntivirusSignatureLastUpdated, AMServiceEnabled, QuickScanEndTime, FullScanEndTime FROM MSFT_MpComputerStatus");
            });

            if (status == null || status.Count == 0)
            {
                s.DefenderRealtimeProtection = ctx.IsElevated ? "NotAvailable" : "RequiresAdmin";
                s.DefenderRealtimeReason = ctx.IsElevated
                    ? "Provedor do Defender nao respondeu (pode estar substituido por antivirus de terceiro)"
                    : "Consulta ao Defender exige privilegio de Administrador";
            }
            else
            {
                DataRow r = status[0];
                bool? rtp = r.Bool("RealTimeProtectionEnabled");
                s.DefenderRealtimeProtection = rtp.HasValue ? (rtp.Value ? "Enabled" : "Disabled") : "Unknown";

                bool? anti = r.Bool("AntispywareEnabled");
                s.DefenderAntispyware = anti.HasValue ? (anti.Value ? "Enabled" : "Disabled") : "Unknown";

                bool? tamper = r.Bool("IsTamperProtected");
                s.DefenderTamperProtection = tamper.HasValue ? (tamper.Value ? "Enabled" : "Disabled") : "Unknown";

                bool? svc = r.Bool("AMServiceEnabled");
                s.DefenderServiceState = svc.HasValue ? (svc.Value ? "Running" : "Stopped") : "Unknown";

                s.DefenderSignatureDate = r.Date("AntivirusSignatureLastUpdated");
                if (s.DefenderSignatureDate.HasValue)
                {
                    double days = (DateTime.Now - s.DefenderSignatureDate.Value).TotalDays;
                    if (days >= 0 && days < 3650) s.DefenderSignatureAgeDays = Math.Round(days, 1);
                }

                s.DefenderLastQuickScan = r.Date("QuickScanEndTime");
                s.DefenderLastFullScan = r.Date("FullScanEndTime");
            }

            // Protecao em nuvem (MAPS) e a razao do desligamento vem do
            // registro de politica, nao do MpComputerStatus.
            object mapsRaw = RegistryWalk.ValueSafe(src.Registry, "HKLM",
                @"SOFTWARE\Microsoft\Windows Defender\SpyNet", "SpynetReporting");
            if (mapsRaw != null)
            {
                int maps = ToInt(mapsRaw, -1);
                s.DefenderCloudProtection = maps > 0 ? "Enabled" : "Disabled";
            }
            else
            {
                s.DefenderCloudProtection = "Unknown";
            }

            if (s.DefenderRealtimeProtection == "Disabled")
                s.DefenderRealtimeReason = DetermineDisableReason(src, s);
        }

        // ServiceController le o Service Control Manager diretamente, uma
        // fonte independente da WMI (nao passa por MSFT_MpComputerStatus
        // nem por nenhum provedor WMI) e nao exige elevacao para consultar
        // o status de um servico. So quando as duas fontes concordam de
        // fato e que SEC-001 pode reivindicar AgreeingSource().
        private void CrossCheckDefenderService(ScanContext ctx, SecurityInfo s)
        {
            if (s.DefenderRealtimeProtection == null ||
                s.DefenderRealtimeProtection == "RequiresAdmin" ||
                s.DefenderRealtimeProtection == "NotAvailable")
                return;

            ServiceController sc = null;
            try
            {
                sc = new ServiceController("WinDefend");
                ServiceControllerStatus status = sc.Status;
                s.DefenderScmStatus = status.ToString();
            }
            catch (Exception)
            {
                // Servico nao existe (Defender removido/substituido) ou o
                // SCM esta inacessivel - ausencia de segunda fonte, nao um
                // erro do diagnostico.
                return;
            }
            finally
            {
                if (sc != null) sc.Dispose();
            }

            bool scmSaysRunning = s.DefenderScmStatus == "Running";
            bool wmiSaysEnabled = s.DefenderRealtimeProtection == "Enabled";

            if (scmSaysRunning == wmiSaysEnabled)
            {
                s.DefenderRealtimeConfirmedByScm = true;
            }
            else
            {
                ctx.AddInconsistency("Estado do servico do Microsoft Defender",
                    "A WMI (MSFT_MpComputerStatus) e o Service Control Manager (servico WinDefend) discordam sobre se a protecao em tempo real esta ativa.",
                    Severity.Medium,
                    Evidence.Of("WMI", "MSFT_MpComputerStatus.RealTimeProtectionEnabled", s.DefenderRealtimeProtection),
                    Evidence.Of("SCM", "ServiceController(\"WinDefend\").Status", s.DefenderScmStatus));
            }
        }

        // As chaves de politica sao lidas incondicionalmente aqui (nao so
        // dentro de DetermineDisableReason, que so roda quando a WMI ja diz
        // Disabled) - se a politica manda desligar (Disable*=1) mas a WMI
        // (adulterada, atrasada, ou provedor inconsistente) reporta
        // Enabled, isso tambem precisa ser comparado. Gera uma divergencia
        // quando a politica e o estado reportado nao batem - nos dois
        // sentidos.
        private void CrossCheckDefenderPolicy(ScanContext ctx, SourceSet src, SecurityInfo s)
        {
            if (s.DefenderRealtimeProtection == null ||
                s.DefenderRealtimeProtection == "RequiresAdmin" ||
                s.DefenderRealtimeProtection == "NotAvailable")
                return;

            object policyDisable = RegistryWalk.ValueSafe(src.Registry, "HKLM",
                @"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware");
            object policyRtp = RegistryWalk.ValueSafe(src.Registry, "HKLM",
                @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring");

            if (policyDisable == null && policyRtp == null) return; // sem politica aplicada, nada a comparar

            bool policySaysDisabled = ToInt(policyDisable, 0) == 1 || ToInt(policyRtp, 0) == 1;
            bool wmiSaysEnabled = s.DefenderRealtimeProtection == "Enabled";

            if (policySaysDisabled && wmiSaysEnabled)
            {
                ctx.AddInconsistency("Politica do Defender x estado reportado pela WMI",
                    "A politica de grupo manda desativar a protecao em tempo real, mas MSFT_MpComputerStatus reporta ativa - o provedor WMI pode estar desatualizado ou a politica ainda nao foi aplicada.",
                    Severity.Medium,
                    Evidence.Of("Registry", "Policies\\...\\Real-Time Protection\\DisableRealtimeMonitoring ou \\Windows Defender\\DisableAntiSpyware", "1 (desativa)"),
                    Evidence.Of("WMI", "MSFT_MpComputerStatus.RealTimeProtectionEnabled", "Enabled"));
            }
        }

        // Distinguir "desligado por politica de TI" de "desligado pelo usuario"
        // de "desligado porque ha outro antivirus" muda completamente a
        // recomendacao no laudo.
        private string DetermineDisableReason(SourceSet src, SecurityInfo s)
        {
            bool policyDisableFailed, policyRtpFailed;
            int policyDisableVal, policyRtpVal;
            bool hasPolicyDisable = TryReadRegistryInt(src, @"SOFTWARE\Policies\Microsoft\Windows Defender",
                "DisableAntiSpyware", out policyDisableVal, out policyDisableFailed);
            bool hasPolicyRtp = TryReadRegistryInt(src, @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                "DisableRealtimeMonitoring", out policyRtpVal, out policyRtpFailed);

            if ((hasPolicyDisable && policyDisableVal == 1) || (hasPolicyRtp && policyRtpVal == 1))
                return "Policy";

            // RegistryWalk.ValueSafe devolve null tanto quando a chave/valor
            // nao existe quanto quando a leitura falha por ACL negada
            // (comum em maquina de dominio com politica endurecida em
            // SOFTWARE\Policies) - os dois casos precisam ser distinguidos,
            // senao o laudo entregue ao cliente cairia direto no "return
            // User" abaixo, atribuindo a desativacao ao usuario quando na
            // verdade a ferramenta nao conseguiu nem checar se havia
            // politica. Le a chave diretamente (nao via ValueSafe) para
            // saber se a excecao aconteceu, e nesse caso devolve "Unknown"
            // em vez de fingir que sabe a causa.
            if (policyDisableFailed || policyRtpFailed) return "Unknown";

            foreach (AntivirusProduct av in s.AntivirusProducts)
            {
                if (av.Name != null && av.Name.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) < 0 && av.IsEnabled == true)
                    return "ThirdPartyAv";
            }

            return "User";
        }

        // Le um valor DWORD do registro distinguindo "ausente" (devolve
        // false, readFailed=false) de "leitura falhou" (devolve false,
        // readFailed=true) - RegistryWalk.ValueSafe engole os dois casos no
        // mesmo null.
        private static bool TryReadRegistryInt(SourceSet src, string path, string name, out int value, out bool readFailed)
        {
            value = 0;
            readFailed = false;
            try
            {
                object v = src.Registry.GetValue("HKLM", path, name);
                if (v == null) return false;
                value = ToInt(v, 0);
                return true;
            }
            catch
            {
                readFailed = true;
                return false;
            }
        }

        private void CollectThirdPartyAv(ScanContext ctx, SourceSet src, SecurityInfo s)
        {
            IList<DataRow> products = Try.Get(ctx, Name, "AntiVirusProduct", delegate
            {
                return src.Wmi.Query(WmiSource.SecurityCenter, "SELECT displayName, productState FROM AntiVirusProduct");
            });

            if (products == null) return;

            foreach (DataRow r in products)
            {
                AntivirusProduct av = new AntivirusProduct();
                av.Name = r.Str("displayName");

                int? state = r.Int("productState");
                if (state.HasValue)
                {
                    av.State = "0x" + state.Value.ToString("X6", CultureInfo.InvariantCulture);
                    DecodeProductState(state.Value, av);
                }

                s.AntivirusProducts.Add(av);
            }

            // Reavalia a razao agora que a lista de antivirus esta preenchida.
            if (s.DefenderRealtimeProtection == "Disabled")
                s.DefenderRealtimeReason = DetermineDisableReason(src, s);
        }

        // Decodificacao do productState do Windows Security Center.
        //
        // O estado ligado/desligado esta no byte 8-15; o byte 16-23 e o
        // TIPO de provedor (0x01 antivirus, 0x02 antispyware, 0x04
        // firewall), nao o estado. Exemplos reais confirmados contra o WMI
        // desta maquina (SecurityCenter2.AntiVirusProduct, Defender ativo =
        // 0x061100):
        //   0x061100 -> byte 8-15 = 0x11 -> (0x11 & 0x10) != 0 -> ligado
        //   0x060100 -> byte 8-15 = 0x01 -> (0x01 & 0x10) == 0 -> desligado
        //   0x041010 -> byte 8-15 = 0x10 -> ligado; byte 0-7 = 0x10 -> assinatura vencida
        //   bits 8-15: estado do produto (0x10 = ligado)
        //   bits 0-7 : estado das assinaturas (0x10 = desatualizado)
        public static void DecodeProductState(int state, AntivirusProduct av)
        {
            int product = (state >> 8) & 0xFF;
            int signature = state & 0xFF;
            av.IsEnabled = (product & 0x10) != 0;
            av.IsUpToDate = (signature & 0x10) == 0;
        }

        // Firewall pelo registro: funciona sem elevacao e sem depender do
        // provedor MSFT_NetFirewallProfile, que nao existe em toda edicao.
        //
        // A chave de POLITICA (SOFTWARE\Policies\Microsoft\WindowsFirewall)
        // tem PRECEDENCIA sobre a chave local (SharedAccess). Um GPO que
        // desliga o firewall por perfil escreve so na chave de politica, e
        // SharedAccess pode continuar valendo 1 (o valor anterior, antes da
        // politica) - por isso as duas precisam ser lidas: usar so a local
        // faria o laudo reportar "ativo" quando a politica efetiva desligou,
        // em maquina de dominio (ou com politica local aplicada).
        private void CollectFirewall(ScanContext ctx, SourceSet src, SecurityInfo s)
        {
            const string policyBase = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";
            const string localBase = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

            s.FirewallDomain = ReadFirewallProfile(ctx, src, policyBase + @"\DomainProfile", localBase + @"\DomainProfile");
            s.FirewallPrivate = ReadFirewallProfile(ctx, src, policyBase + @"\StandardProfile", localBase + @"\StandardProfile");
            s.FirewallPublic = ReadFirewallProfile(ctx, src, policyBase + @"\PublicProfile", localBase + @"\PublicProfile");
        }

        private static string ReadFirewallProfile(ScanContext ctx, SourceSet src, string policyPath, string localPath)
        {
            object policyValue = RegistryWalk.ValueSafe(src.Registry, "HKLM", policyPath, "EnableFirewall");
            object localValue = RegistryWalk.ValueSafe(src.Registry, "HKLM", localPath, "EnableFirewall");

            if (policyValue != null)
            {
                string policyResult = ToInt(policyValue, 0) == 1 ? "Enabled" : "Disabled";

                // A politica vence, mas se o valor local discordar isso e
                // sinal de que a politica pode nao estar sendo efetivamente
                // aplicada (servico Firewall parado, atraso de propagacao de
                // GPO) - vale registrar.
                if (localValue != null)
                {
                    string localResult = ToInt(localValue, 0) == 1 ? "Enabled" : "Disabled";
                    if (localResult != policyResult)
                    {
                        ctx.AddInconsistency("Politica de firewall x valor local (" + policyPath.Substring(policyPath.LastIndexOf('\\') + 1) + ")",
                            "A chave de politica de grupo tem precedencia, mas o valor local (SharedAccess) discorda dela - pode indicar que a politica nao esta sendo efetivamente aplicada.",
                            Severity.Medium,
                            Evidence.Of("Registry", policyPath + "\\EnableFirewall (politica, vence)", policyResult),
                            Evidence.Of("Registry", localPath + "\\EnableFirewall (local)", localResult));
                    }
                }

                return policyResult;
            }

            if (localValue == null) return "Unknown";
            return ToInt(localValue, 0) == 1 ? "Enabled" : "Disabled";
        }

        private void CollectUacAndSmartScreen(ScanContext ctx, SourceSet src, SecurityInfo s)
        {
            const string policies = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

            object enableLua = RegistryWalk.ValueSafe(src.Registry, "HKLM", policies, "EnableLUA");
            if (enableLua != null) s.UacState = ToInt(enableLua, 1) == 1 ? "Enabled" : "Disabled";
            else s.UacState = "Unknown";

            object consent = RegistryWalk.ValueSafe(src.Registry, "HKLM", policies, "ConsentPromptBehaviorAdmin");
            if (consent != null) s.UacConsentPromptLevel = ToInt(consent, -1);

            // Politica de dominio tem precedencia sobre a configuracao local.
            object policySmart = RegistryWalk.ValueSafe(src.Registry, "HKLM",
                @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen");
            if (policySmart != null)
            {
                s.SmartScreenState = ToInt(policySmart, 0) == 0 ? "Disabled (por politica)" : "Enabled (por politica)";
                return;
            }

            object localSmart = RegistryWalk.ValueSafe(src.Registry, "HKLM",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled");
            string v = localSmart == null ? null : Convert.ToString(localSmart, CultureInfo.InvariantCulture);
            if (v == null) s.SmartScreenState = "Unknown";
            else if (string.Equals(v, "Off", StringComparison.OrdinalIgnoreCase)) s.SmartScreenState = "Disabled";
            else s.SmartScreenState = "Enabled (" + v + ")";
        }

        // Contas locais. Nao coleta senha, hash, token nem qualquer segredo -
        // apenas o que e necessario para avaliar exposicao: contas ativas,
        // conta Convidado ligada e Administrador embutido ligado.
        private void CollectAccounts(ScanContext ctx, SourceSet src, SecurityInfo s)
        {
            IList<DataRow> users = Try.Get(ctx, Name, "Win32_UserAccount", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT Name, SID, Disabled, Lockout, PasswordRequired FROM Win32_UserAccount WHERE LocalAccount=True");
            });

            if (users == null) return;

            int enabled = 0, disabled = 0;
            foreach (DataRow r in users)
            {
                bool isDisabled = r.Bool("Disabled") == true;
                if (isDisabled) disabled++; else enabled++;

                string sid = r.Str("SID");
                if (sid == null) continue;

                if (sid.EndsWith("-500", StringComparison.Ordinal)) s.BuiltinAdminEnabled = !isDisabled;
                else if (sid.EndsWith("-501", StringComparison.Ordinal)) s.GuestAccountEnabled = !isDisabled;
            }

            s.LocalAccountsEnabled = enabled;
            s.LocalAccountsDisabled = disabled;
        }

        private static int ToInt(object value, int fallback)
        {
            if (value == null) return fallback;
            try { return Convert.ToInt32(value, CultureInfo.InvariantCulture); }
            catch { return fallback; }
        }
    }
}
