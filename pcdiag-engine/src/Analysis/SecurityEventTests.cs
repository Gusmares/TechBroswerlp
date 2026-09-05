using System;
using System.Collections.Generic;
using System.Globalization;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Analysis
{
    public sealed class SecurityTests : IDiagnosticTest
    {
        public string Category { get { return "Seguranca"; } }

        public IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv)
        {
            List<TestResult> list = new List<TestResult>();
            list.Add(RealtimeProtection(ctx, inv));
            list.Add(Signatures(ctx, inv));
            list.Add(Firewall(inv));
            list.Add(Uac(inv));
            list.Add(GuestAccount(inv));
            list.Add(BrokenServices(inv));
            list.Add(Persistence(inv));
            list.Add(RemoteAccessSoftware(inv));
            list.Add(TamperProtection(inv));
            list.Add(DefenderServiceState(inv));
            return list;
        }

        // DefenderTamperProtection e DefenderServiceState
        // (SecurityCollector.cs) sao dois estados que so ficam desligados
        // por acao deliberada de malware ou do usuario, nunca por
        // configuracao padrao do Windows - por isso valem um teste proprio.
        private TestResult TamperProtection(Inventory inv)
        {
            TestResult r = T.Make("SEC-009", "Protecao contra adulteracao (Tamper Protection)", Category,
                "Impede que malware ou o proprio usuario desative a protecao do Defender por fora da interface oficial.");

            SecurityInfo s = inv.Security;
            if (s.DefenderTamperProtection == null || s.DefenderTamperProtection == "Unknown")
                return T.NotTested(r, "O estado da protecao contra adulteracao nao foi reportado pelo provedor do Defender.");

            T.Ev(r, "WMI", "MSFT_MpComputerStatus.IsTamperProtected", s.DefenderTamperProtection);
            int confidence = Confidence.Build().Authoritative().Value;

            if (s.DefenderTamperProtection == "Enabled")
                return T.Pass(r, "Protecao contra adulteracao ativa.", confidence);

            return T.Warn(r, Severity.High,
                "Protecao contra adulteracao DESATIVADA.",
                "Sem ela, malware com privilegio de administrador pode desligar o Defender diretamente, sem passar pela interface do Windows. Reativar em Seguranca do Windows > Protecao contra virus e ameacas > Configuracoes.",
                confidence);
        }

        private TestResult DefenderServiceState(Inventory inv)
        {
            TestResult r = T.Make("SEC-010", "Servico do Microsoft Defender (WinDefend)", Category,
                "Estado do servico do Antimalware Service (AM) no Service Control Manager - independente da WMI.");

            SecurityInfo s = inv.Security;
            if (s.DefenderScmStatus == null)
                return T.NotTested(r, "O Service Control Manager nao respondeu para o servico WinDefend (pode ter sido removido/substituido por outro antivirus).");

            T.Ev(r, "SCM", "ServiceController(\"WinDefend\").Status", s.DefenderScmStatus);
            int confidence = Confidence.Build().Authoritative().Value;

            if (s.DefenderScmStatus == "Running")
                return T.Pass(r, "Servico WinDefend em execucao.", confidence);

            return T.Warn(r, Severity.High,
                "Servico WinDefend com status '" + s.DefenderScmStatus + "' (nao Running).",
                "Um servico de antimalware parado, mesmo com outro antivirus instalado, merece confirmacao de que a substituicao foi deliberada. Verificar em services.msc.",
                confidence);
        }

        // O ponto central deste teste (item 25 do briefing): desligado POR
        // POLITICA e decisao de TI, desligado porque HA OUTRO ANTIVIRUS e
        // comportamento correto do Windows, e desligado PELO USUARIO e o unico
        // caso que merece alerta de seguranca.
        private TestResult RealtimeProtection(ScanContext ctx, Inventory inv)
        {
            TestResult r = T.Make("SEC-001", "Protecao em tempo real", Category,
                "Estado da protecao antivirus em tempo real e a razao de estar desligada, quando for o caso.");

            SecurityInfo s = inv.Security;
            string state = s.DefenderRealtimeProtection;

            if (state == null) return T.Unknown(r, "Estado da protecao em tempo real nao pode ser determinado.");
            if (state == "RequiresAdmin") return T.RequiresAdmin(r, "Consultar o estado do Microsoft Defender");

            T.Ev(r, "WMI", "MSFT_MpComputerStatus.RealTimeProtectionEnabled", state);
            if (s.DefenderRealtimeReason != null) T.Ev(r, "Analise", "razao", s.DefenderRealtimeReason);
            foreach (AntivirusProduct av in s.AntivirusProducts)
                T.Ev(r, "WMI", "SecurityCenter2.AntiVirusProduct", T.Name(av.Name, "?") + " (ativo: " + av.IsEnabled + ", atualizado: " + av.IsUpToDate + ")");
            if (s.DefenderScmStatus != null) T.Ev(r, "SCM", "ServiceController(\"WinDefend\").Status", s.DefenderScmStatus);

            // A fonte primaria aqui e WMI (MSFT_MpComputerStatus), nao API
            // nativa nem contador do kernel - nao reivindica
            // Authoritative(). AgreeingSource() so e concedido quando o
            // Service Control Manager (fonte independente da WMI) de fato
            // confirmou o mesmo estado.
            Confidence confBuilder = Confidence.Build();
            if (s.DefenderRealtimeConfirmedByScm) confBuilder = confBuilder.AgreeingSource();
            int confidence = confBuilder.Value;

            if (state == "Enabled")
                return T.Pass(r, "Protecao em tempo real do Microsoft Defender ativa.", confidence);

            if (state == "NotAvailable")
            {
                foreach (AntivirusProduct av in s.AntivirusProducts)
                {
                    if (av.Name != null && av.Name.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) < 0 && av.IsEnabled == true)
                        return T.Pass(r, "Microsoft Defender inativo porque o antivirus '" + av.Name + "' esta no comando - comportamento correto do Windows.", confidence);
                }
                return T.Warn(r, Severity.High,
                    "O provedor do Microsoft Defender nao respondeu e nenhum antivirus de terceiro ativo foi identificado.",
                    "Verificar em Seguranca do Windows se ha alguma protecao ativa. Maquina sem antivirus em funcionamento fica exposta.",
                    confidence);
            }

            if (state == "Disabled")
            {
                if (s.DefenderRealtimeReason == "ThirdPartyAv")
                    return T.Pass(r, "Defender desligado porque ha outro antivirus ativo - comportamento esperado.", confidence);

                if (s.DefenderRealtimeReason == "Policy")
                    return T.Info(r,
                        "Protecao em tempo real desativada POR POLITICA (configuracao administrativa, nao acao do usuario).",
                        confidence);

                // ARQUITETURA.md 5 define "Defender desativado POR USUARIO
                // -> WARNING/HIGH" - usar T.Error aqui divergiria da regra
                // versionada e derrubaria o score 10 pontos a mais do que a
                // doc do projeto manda.
                return T.Warn(r, Severity.High,
                    "Protecao em tempo real DESATIVADA, sem politica que justifique e sem outro antivirus ativo.",
                    "Reativar em Seguranca do Windows > Protecao contra virus e ameacas. Se ela nao permanecer ligada, e um forte indicio de que algum software indesejado esta desligando a protecao.",
                    confidence);
            }

            return T.Unknown(r, "Estado reportado como '" + state + "'.");
        }

        private TestResult Signatures(ScanContext ctx, Inventory inv)
        {
            TestResult r = T.Make("SEC-002", "Atualizacao das definicoes de antivirus", Category,
                "Ha quanto tempo as assinaturas de deteccao foram atualizadas.");

            SecurityInfo s = inv.Security;
            if (!s.DefenderSignatureAgeDays.HasValue)
            {
                if (!ctx.IsElevated) return T.RequiresAdmin(r, "Consultar a data das definicoes do Defender");
                return T.NotTested(r, "A data das definicoes nao foi reportada pelo provedor do Defender.");
            }

            double days = s.DefenderSignatureAgeDays.Value;
            T.Ev(r, "WMI", "MSFT_MpComputerStatus.AntivirusSignatureLastUpdated", T.Date(s.DefenderSignatureDate));

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (days >= 30)
                return T.Error(r, Severity.High,
                    "Definicoes de antivirus com " + T.Num(days, 0) + " dias.",
                    "Atualizar imediatamente. Definicoes com mais de um mes deixam a protecao cega para ameacas recentes; a defasagem costuma indicar que o Windows Update esta quebrado.",
                    confidence);

            if (days >= 7)
                return T.Warn(r, Severity.Medium,
                    "Definicoes de antivirus com " + T.Num(days, 0) + " dias.",
                    "Executar a atualizacao de definicoes em Seguranca do Windows.",
                    confidence);

            return T.Pass(r, "Definicoes atualizadas ha " + T.Num(days, 1) + " dias.", confidence);
        }

        private TestResult Firewall(Inventory inv)
        {
            TestResult r = T.Make("SEC-003", "Firewall do Windows", Category,
                "Estado do firewall em cada perfil de rede.");

            SecurityInfo s = inv.Security;
            T.Ev(r, "Registry", "DomainProfile\\EnableFirewall", T.Name(s.FirewallDomain, "?"));
            T.Ev(r, "Registry", "StandardProfile\\EnableFirewall", T.Name(s.FirewallPrivate, "?"));
            T.Ev(r, "Registry", "PublicProfile\\EnableFirewall", T.Name(s.FirewallPublic, "?"));

            // Qualquer valor de perfil que nao seja literalmente "Disabled"
            // ou "Enabled" (null por coleta abortada, ou "Unknown") e
            // classificado como nao avaliado, para nunca cair num Pass
            // afirmando "ativo em todos os perfis avaliados" sem o perfil
            // ter sido de fato avaliado.
            List<string> off = new List<string>();
            List<string> on = new List<string>();
            List<string> unknown = new List<string>();
            ClassifyFirewallProfile("Dominio", s.FirewallDomain, off, on, unknown);
            ClassifyFirewallProfile("Particular", s.FirewallPrivate, off, on, unknown);
            ClassifyFirewallProfile("Publico", s.FirewallPublic, off, on, unknown);

            int confidence = Confidence.Build().Authoritative().Value;

            if (off.Count == 0 && on.Count == 0)
                return T.Unknown(r, "Nenhum dos perfis de firewall expos o valor EnableFirewall no registro.");

            if (off.Count > 0)
            {
                // O perfil Publico e o mais critico: e o usado em rede de terceiros.
                Severity sev = off.Contains("Publico") ? Severity.High : Severity.Medium;
                return T.Error(r, sev,
                    "Firewall DESATIVADO no(s) perfil(is): " + string.Join(", ", off.ToArray()) + ".",
                    "Reativar em Seguranca do Windows > Firewall e protecao de rede. O perfil Publico e o que protege a maquina em redes de terceiros e nunca deveria ficar desligado.",
                    confidence);
            }

            if (unknown.Count > 0)
                return T.Unknown(r, "Firewall confirmado ativo em " + string.Join(", ", on.ToArray()) +
                    ", mas o(s) perfil(is) " + string.Join(", ", unknown.ToArray()) + " nao puderam ser lidos - sem confirmacao para eles.");

            return T.Pass(r, "Firewall ativo em todos os perfis avaliados.", confidence);
        }

        private static void ClassifyFirewallProfile(string label, string value, List<string> off, List<string> on, List<string> unknown)
        {
            if (string.Equals(value, "Disabled", StringComparison.OrdinalIgnoreCase)) off.Add(label);
            else if (string.Equals(value, "Enabled", StringComparison.OrdinalIgnoreCase)) on.Add(label);
            else unknown.Add(label);
        }

        private TestResult Uac(Inventory inv)
        {
            TestResult r = T.Make("SEC-004", "Controle de Conta de Usuario (UAC)", Category,
                "Verifica se o UAC esta ativo e em que nivel de notificacao.");

            SecurityInfo s = inv.Security;
            if (s.UacState == null || s.UacState == "Unknown")
                return T.Unknown(r, "O valor EnableLUA nao pode ser lido do registro.");

            T.Ev(r, "Registry", "Policies\\System\\EnableLUA", s.UacState);
            if (s.UacConsentPromptLevel.HasValue)
                T.Ev(r, "Registry", "ConsentPromptBehaviorAdmin", s.UacConsentPromptLevel.Value);

            int confidence = Confidence.Build().Authoritative().Value;

            if (s.UacState == "Disabled")
                return T.Error(r, Severity.High,
                    "UAC completamente desativado (EnableLUA = 0).",
                    "Com o UAC desligado, qualquer programa executado pelo usuario administrador roda elevado sem pedir confirmacao. Reativar em Contas de Usuario e reiniciar.",
                    confidence);

            if (s.UacConsentPromptLevel.HasValue && s.UacConsentPromptLevel.Value == 0)
                return T.Warn(r, Severity.Medium,
                    "UAC ativo, mas configurado para elevar sem pedir confirmacao (ConsentPromptBehaviorAdmin = 0).",
                    "Elevar para o nivel padrao de notificacao, que exige confirmacao explicita para acoes administrativas.",
                    confidence);

            return T.Pass(r, "UAC ativo.", confidence);
        }

        private TestResult GuestAccount(Inventory inv)
        {
            TestResult r = T.Make("SEC-005", "Contas locais sensiveis", Category,
                "Verifica se as contas Convidado e Administrador embutido estao habilitadas.");

            SecurityInfo s = inv.Security;
            if (!s.GuestAccountEnabled.HasValue && !s.BuiltinAdminEnabled.HasValue)
                return T.Unknown(r, "As contas locais nao puderam ser enumeradas.");

            T.Ev(r, "WMI", "Win32_UserAccount (SID -501, Convidado)", s.GuestAccountEnabled);
            T.Ev(r, "WMI", "Win32_UserAccount (SID -500, Administrador)", s.BuiltinAdminEnabled);
            T.Ev(r, "WMI", "contas locais habilitadas", T.Num(s.LocalAccountsEnabled));

            int confidence = Confidence.Build().Authoritative().Value;
            List<string> issues = new List<string>();
            // Quando so UMA das duas contas vem com valor (a outra null -
            // SID nao encontrado entre as contas locais enumeradas, ou WQL
            // parcial), a conta sem valor precisa ficar marcada como nao
            // verificada - o que e diferente de "verificada e desabilitada".
            // Um Administrador embutido cujo estado nunca foi confirmado
            // nao pode virar PASS silencioso.
            List<string> unverified = new List<string>();
            if (s.GuestAccountEnabled == true) issues.Add("conta Convidado habilitada");
            else if (!s.GuestAccountEnabled.HasValue) unverified.Add("conta Convidado");
            if (s.BuiltinAdminEnabled == true) issues.Add("Administrador embutido habilitado");
            else if (!s.BuiltinAdminEnabled.HasValue) unverified.Add("Administrador embutido");

            if (issues.Count > 0)
            {
                string unverifiedNote = unverified.Count > 0
                    ? " (" + string.Join(" e ", unverified.ToArray()) + " nao pode(m) ser confirmada(s))"
                    : "";
                return T.Warn(r, Severity.Medium,
                    string.Join(" e ", issues.ToArray()) + "." + unverifiedNote,
                    "Ambas ampliam a superficie de ataque e normalmente devem ficar desabilitadas. O Administrador embutido nao tem as protecoes de UAC das demais contas administrativas.",
                    confidence);
            }

            if (unverified.Count > 0)
                return T.Info(r,
                    "Nenhum problema confirmado, mas " + string.Join(" e ", unverified.ToArray()) +
                    " nao pode(m) ser verificada(s) entre as contas locais enumeradas - o estado dela(s) e desconhecido, nao confirmado como desabilitada.",
                    confidence);

            return T.Pass(r, "Contas Convidado e Administrador embutido desabilitadas, como esperado. " +
                T.Num(s.LocalAccountsEnabled) + " conta(s) local(is) ativa(s).", confidence);
        }

        private TestResult BrokenServices(Inventory inv)
        {
            TestResult r = T.Make("SEC-006", "Servicos com binario ausente ou em local incomum", Category,
                "Servicos cujo executavel nao existe, ou que rodam de diretorios de onde software de sistema normalmente nao roda.");

            if (inv.Services.Count == 0) return T.NotTested(r, "Nenhum servico foi enumerado.");

            List<string> missing = new List<string>();
            List<string> unusual = new List<string>();
            // BinaryExists==null (caminho existia mas File.Exists nao pode
            // ser confirmado - permissao, caminho em volume removido)
            // precisa ficar distinguivel de "confirmado existente", em vez
            // de contar como "nenhum problema".
            int unverified = 0;

            foreach (ServiceInfo s in inv.Services)
            {
                if (s.BinaryExists == false && s.ExecutablePath != null)
                    missing.Add(T.Name(s.Name, "?") + " -> " + s.ExecutablePath);
                else if (!s.BinaryExists.HasValue && s.ExecutablePath != null)
                    unverified++;

                if (s.IsInUnusualLocation && s.State == "Running")
                    unusual.Add(T.Name(s.Name, "?") + " -> " + T.Name(s.ExecutablePath, "?"));
            }

            T.Ev(r, "WMI", "Win32_Service (total)", inv.Services.Count);
            T.Ev(r, "Analise", "binario inexistente", missing.Count);
            T.Ev(r, "Analise", "em local incomum e em execucao", unusual.Count);
            if (unverified > 0) T.Ev(r, "Analise", "existencia do binario nao pode ser confirmada", unverified);

            int confidence = Confidence.Build().Authoritative().Value;

            if (missing.Count == 0 && unusual.Count == 0)
            {
                string suffix = unverified > 0
                    ? " (" + unverified + " servico(s) com caminho reportado, mas cuja existencia nao pode ser confirmada)"
                    : "";
                return T.Pass(r, "Os " + inv.Services.Count + " servicos apontam para binarios existentes em locais esperados." + suffix, confidence);
            }

            List<string> parts = new List<string>();

            if (missing.Count > 0)
            {
                foreach (string m in missing) T.Ev(r, "Analise", "binario ausente", m);
                parts.Add(missing.Count + " servico(s) apontando para executavel inexistente");
            }

            if (unusual.Count > 0)
            {
                foreach (string u in unusual) T.Ev(r, "Analise", "local incomum", u);
                parts.Add(unusual.Count + " servico(s) em execucao a partir de diretorio incomum");
            }

            return T.Warn(r, Severity.Medium,
                string.Join("; ", parts.ToArray()) + ".",
                "Servico com binario ausente e restos de desinstalacao mal feita e pode ser removido com seguranca depois de confirmado. Servico rodando de Temp/AppData merece verificacao da assinatura do executavel antes de qualquer conclusao - nao e, por si so, indicio de malware.",
                confidence);
        }

        private TestResult Persistence(Inventory inv)
        {
            TestResult r = T.Make("SEC-007", "Itens de inicializacao automatica", Category,
                "O que e executado automaticamente no boot ou no logon.");

            if (inv.Startup.Count == 0)
                return T.Info(r, "Nenhum item de inicializacao automatica encontrado nas chaves Run/RunOnce e nas pastas de Inicializacao.",
                    Confidence.Build().Authoritative().Value);

            List<string> suspicious = new List<string>();
            List<string> broken = new List<string>();

            foreach (StartupItem s in inv.Startup)
            {
                if (s.IsInUnusualLocation) suspicious.Add(T.Name(s.Name, "?") + " [" + T.Name(s.Location, "?") + "] -> " + T.Name(s.Command, "?"));
                if (s.TargetExists == false) broken.Add(T.Name(s.Name, "?") + " -> " + T.Name(s.Command, "?"));
            }

            T.Ev(r, "Registry", "itens de inicializacao", inv.Startup.Count);
            int confidence = Confidence.Build().Authoritative().Value;

            if (suspicious.Count == 0 && broken.Count == 0)
                return T.Pass(r, inv.Startup.Count + " item(ns) de inicializacao, todos em locais esperados e apontando para arquivos existentes.", confidence);

            List<string> parts = new List<string>();
            if (suspicious.Count > 0)
            {
                foreach (string s in suspicious) T.Ev(r, "Analise", "inicializacao em local incomum", s);
                parts.Add(suspicious.Count + " item(ns) executando de diretorio incomum");
            }
            if (broken.Count > 0)
            {
                foreach (string b in broken) T.Ev(r, "Analise", "alvo inexistente", b);
                parts.Add(broken.Count + " item(ns) apontando para arquivo inexistente");
            }

            return T.Warn(r, Severity.Medium,
                string.Join("; ", parts.ToArray()) + ".",
                "Estes sao indicadores para VERIFICACAO, nao um veredito. Item apontando para arquivo inexistente e lixo de desinstalacao. Item rodando de Temp ou AppData deve ter a assinatura do executavel conferida antes de qualquer acao.",
                confidence);
        }

        // Ferramenta de acesso remoto instalada sem o cliente saber e um dos
        // achados mais uteis num atendimento. Nao e acusacao: e informacao.
        private TestResult RemoteAccessSoftware(Inventory inv)
        {
            TestResult r = T.Make("SEC-008", "Software de acesso remoto instalado", Category,
                "Lista ferramentas de acesso remoto presentes no equipamento.");

            List<string> remote = new List<string>();
            foreach (SoftwareInfo s in inv.Software)
            {
                if (s.Category == "RemoteAccess") remote.Add(T.Name(s.Name, "?") + " " + T.Name(s.Version, ""));
            }

            T.Ev(r, "Registry", "software inventariado", inv.Software.Count);
            int confidence = Confidence.Build().Authoritative().Value;

            if (inv.Software.Count == 0)
                return T.NotTested(r, "O inventario de software nao pode ser lido.");

            if (remote.Count == 0)
                return T.Pass(r, "Nenhuma ferramenta de acesso remoto instalada entre os " + inv.Software.Count + " programas inventariados.", confidence);

            foreach (string s in remote) T.Ev(r, "Registry", "acesso remoto", s);

            return T.Info(r,
                remote.Count + " ferramenta(s) de acesso remoto instalada(s): " + string.Join("; ", remote.ToArray()) +
                ". Confirmar com o cliente se o uso e conhecido e autorizado.",
                confidence);
        }
    }

    public sealed class EventTests : IDiagnosticTest
    {
        public string Category { get { return "Eventos"; } }

        public IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv)
        {
            List<TestResult> list = new List<TestResult>();
            list.Add(BlueScreens(inv));
            list.Add(UnexpectedShutdowns(inv));
            list.Add(ErrorVolume(inv));
            return list;
        }

        private TestResult BlueScreens(Inventory inv)
        {
            TestResult r = T.Make("EVT-001", "Telas azuis (bugcheck)", Category,
                "Historico de paradas do kernel registradas pelo Windows.");

            EventsInfo e = inv.Events;
            if (!e.Accessible)
                return e.InaccessibleReason != null && e.InaccessibleReason.IndexOf("Administrador", StringComparison.OrdinalIgnoreCase) >= 0
                    ? T.RequiresAdmin(r, "Ler o log de eventos do sistema")
                    : T.NotTested(r, T.Name(e.InaccessibleReason, "Log de eventos indisponivel."));

            // BugChecks.Count==0 e ambiguo entre "coletado e realmente
            // zero" e "nunca coletado" (Accessible vira true bem antes de
            // CollectBugChecks rodar - um timeout de modulo no meio dos
            // dois deixa a lista vazia sem nenhum erro). Esta flag distingue
            // os dois casos.
            if (!e.BugChecksCollected)
                return T.NotTested(r, "A consulta ao log de eventos que registra telas azuis (WER-SystemErrorReporting) nao pode ser concluida.");

            T.Ev(r, "EventLog", "bugchecks em " + e.WindowDays + " dias", e.BugChecks.Count);
            if (e.MinidumpCount.HasValue) T.Ev(r, "Arquivo", "minidumps em %SystemRoot%\\Minidump", e.MinidumpCount.Value);
            if (e.LastMinidump.HasValue) T.Ev(r, "Arquivo", "minidump mais recente", T.Date(e.LastMinidump));

            foreach (BugCheckEvent bc in e.BugChecks)
                T.Ev(r, "EventLog", "bugcheck " + T.Name(bc.StopCode, "codigo nao extraido"), T.Date(bc.Time));

            // Duas fontes independentes: log de eventos e arquivos de dump.
            Confidence conf = Confidence.Build().Authoritative();
            if (e.MinidumpCount.HasValue) conf = conf.AgreeingSource();
            int confidence = conf.Value;

            if (e.BugChecks.Count == 0)
            {
                if (e.MinidumpCount.HasValue && e.MinidumpCount.Value > 0)
                    return T.Info(r,
                        "Nenhuma tela azul nos ultimos " + e.WindowDays + " dias, mas existem " + e.MinidumpCount.Value +
                        " arquivo(s) de dump antigo(s) (mais recente em " + T.Date(e.LastMinidump) + ") - evidencia de travamentos anteriores a janela analisada.",
                        confidence);

                return T.Pass(r, "Nenhuma tela azul registrada nos ultimos " + e.WindowDays + " dias.", confidence);
            }

            List<string> codes = new List<string>();
            foreach (BugCheckEvent bc in e.BugChecks)
            {
                if (bc.StopCode != null && !codes.Contains(bc.StopCode)) codes.Add(bc.StopCode);
            }
            string codeText = codes.Count > 0 ? " Codigos de parada: " + string.Join(", ", codes.ToArray()) + "." : "";

            if (e.BugChecks.Count >= 3)
                return T.Critical(r,
                    e.BugChecks.Count + " telas azuis nos ultimos " + e.WindowDays + " dias." + codeText,
                    "Travamento recorrente. Analisar os minidumps em %SystemRoot%\\Minidump para identificar o driver responsavel. Cruzar com os testes de memoria, temperatura e saude de disco deste laudo antes de concluir.",
                    confidence);

            return T.Error(r, Severity.High,
                e.BugChecks.Count + " tela(s) azul(is) nos ultimos " + e.WindowDays + " dias." + codeText,
                "Analisar o minidump correspondente para identificar o driver ou componente envolvido.",
                confidence);
        }

        private TestResult UnexpectedShutdowns(Inventory inv)
        {
            TestResult r = T.Make("EVT-002", "Desligamentos inesperados", Category,
                "Reinicializacoes sem desligamento limpo (Kernel-Power 41 / EventLog 6008).");

            EventsInfo e = inv.Events;
            if (!e.Accessible) return T.NotTested(r, T.Name(e.InaccessibleReason, "Log de eventos indisponivel."));
            if (!e.UnexpectedShutdowns.HasValue) return T.NotTested(r, "A contagem de desligamentos inesperados nao pode ser apurada.");

            int count = e.UnexpectedShutdowns.Value;
            T.Ev(r, "EventLog", "Kernel-Power 41 / EventLog 6008 em " + e.WindowDays + " dias", count);

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (count >= 3)
                return T.Error(r, Severity.High,
                    count + " desligamentos inesperados nos ultimos " + e.WindowDays + " dias.",
                    "Desligamento abrupto recorrente costuma ter tres causas: fonte de alimentacao com problema, superaquecimento disparando protecao termica, ou queda de energia sem nobreak. Cruzar com temperatura e com os eventos WHEA deste laudo.",
                    confidence);

            if (count > 0)
                return T.Warn(r, Severity.Medium,
                    count + " desligamento(s) inesperado(s) nos ultimos " + e.WindowDays + " dias.",
                    "Um evento isolado normalmente e queda de energia. Se repetir, investigar fonte e temperatura.",
                    confidence);

            // count==0 sobre uma consulta truncada (teto de 400 eventos
            // atingido) nao prova ausencia na janela de WindowDays inteira -
            // so no que coube antes do corte. Como a consulta e por data
            // decrescente, o corte descarta justamente os eventos mais
            // ANTIGOS, entao a cobertura real pode ser bem menor que
            // WindowDays.
            if (e.SystemLogTruncated)
                return T.Unknown(r, "O log 'System' tem mais eventos do que o teto de leitura - a cobertura real vai ate " +
                    T.Date(e.SystemLogOldestCoveredUtc) + ", nao ate o inicio dos " + e.WindowDays +
                    " dias pedidos. Nenhum desligamento inesperado no periodo efetivamente coberto.");

            return T.Pass(r, "Nenhum desligamento inesperado nos ultimos " + e.WindowDays + " dias.", confidence);
        }

        private TestResult ErrorVolume(Inventory inv)
        {
            TestResult r = T.Make("EVT-003", "Volume de erros no log do sistema", Category,
                "Quantidade de eventos criticos e de erro no periodo analisado.");

            EventsInfo e = inv.Events;
            if (!e.Accessible) return T.NotTested(r, T.Name(e.InaccessibleReason, "Log de eventos indisponivel."));
            if (e.Buckets.Count == 0) return T.NotTested(r, "Nenhum log pode ser sumarizado.");

            int critical = 0, errors = 0, warnings = 0;
            foreach (EventBucket b in e.Buckets)
            {
                critical += b.Critical;
                errors += b.Error;
                warnings += b.Warning;
                T.Ev(r, "EventLog", b.LogName + " (criticos/erros/avisos)", b.Critical + "/" + b.Error + "/" + b.Warning);
            }

            if (e.ServiceFailures.HasValue) T.Ev(r, "EventLog", "falhas de servico", e.ServiceFailures.Value);
            if (e.AppCrashes.HasValue) T.Ev(r, "EventLog", "falhas de aplicativo", e.AppCrashes.Value);

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            // As contagens acima ja refletem fielmente o que FOI lido
            // (nunca inventam zero), mas o rotulo "ultimos N dias" mentiria
            // quando o teto de 400 eventos corta a consulta antes de
            // alcancar o inicio da janela pedida.
            string coverage = e.SystemLogTruncated
                ? "Desde " + T.Date(e.SystemLogOldestCoveredUtc) + " (log maior que o teto de leitura - nao cobre os " + e.WindowDays + " dias inteiros)"
                : "Ultimos " + e.WindowDays + " dias";
            string summary = coverage + ": " + critical + " criticos, " + errors + " erros, " + warnings + " avisos.";

            // Um volume moderado de erros e NORMAL em Windows. So o volume
            // muito alto indica algo sistematicamente errado.
            if (critical + errors >= 200)
                return T.Warn(r, Severity.Medium, summary,
                    "Volume alto de erros. Os eventos mais recentes estao nas evidencias; vale identificar o provedor que mais repete e tratar a causa raiz.",
                    confidence);

            return T.Pass(r, summary + " Volume dentro do normal para uso cotidiano do Windows.", confidence);
        }
    }
}
