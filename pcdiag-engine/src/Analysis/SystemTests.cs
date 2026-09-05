using System;
using System.Collections.Generic;
using System.Globalization;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Analysis
{
    public sealed class SystemTests : IDiagnosticTest
    {
        public string Category { get { return "Sistema"; } }

        public IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv)
        {
            List<TestResult> results = new List<TestResult>();
            results.Add(Activation(ctx, inv));
            results.Add(FirmwareMode(ctx, inv));
            results.Add(SecureBoot(ctx, inv));
            results.Add(Tpm(ctx, inv));
            results.Add(BiosAge(ctx, inv));
            results.Add(Uptime(ctx, inv));
            results.Add(WindowsUpdate(ctx, inv));
            return results;
        }

        private TestResult Activation(ScanContext ctx, Inventory inv)
        {
            TestResult r = T.Make("SYS-001", "Ativacao do Windows", Category,
                "Verifica se a licenca do Windows esta ativa e valida.");

            OsInfo os = inv.Os;
            if (os.ActivationStatus == null || os.ActivationStatus == "Nao determinado")
                return T.Unknown(r, "O provedor de licenciamento (SoftwareLicensingProduct) nao respondeu.");

            T.Ev(r, "WMI", "SoftwareLicensingProduct.LicenseStatus", os.ActivationStatus);
            if (os.LicenseChannel != null) T.Ev(r, "WMI", "SoftwareLicensingProduct.Description", os.LicenseChannel);

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (os.IsActivated == true)
                return T.Pass(r, "Windows ativado" + (os.LicenseChannel == null ? "" : " (canal " + os.LicenseChannel + ")") + ".", confidence);

            return T.Warn(r, Severity.Medium,
                "Windows nao esta ativado. Status reportado: " + os.ActivationStatus + ".",
                "Ativar com uma licenca valida. Sem ativacao o Windows bloqueia personalizacao e passa a exibir marca d'agua, mas continua recebendo atualizacoes de seguranca.",
                confidence);
        }

        private TestResult FirmwareMode(ScanContext ctx, Inventory inv)
        {
            TestResult r = T.Make("SYS-002", "Modo de firmware (UEFI x Legacy)", Category,
                "Identifica se a maquina inicializa em UEFI ou em modo Legacy (CSM/BIOS).");

            FirmwareInfo f = inv.Firmware;
            if (f.FirmwareType == null || f.FirmwareType == "Desconhecido")
                return T.Unknown(r, "Nem a API nativa nem o registro permitiram determinar o modo de firmware.");

            // A evidencia e a confianca refletem a fonte real gravada em
            // f.FirmwareTypeSource, em vez de citar incondicionalmente
            // "GetFirmwareType()" mesmo quando o valor veio do fallback de
            // registro (SystemCollector.cs) - so ha
            // Authoritative()+AgreeingSource() quando a API nativa de fato
            // respondeu.
            bool fromNativeApi = f.FirmwareTypeSource != null &&
                f.FirmwareTypeSource.IndexOf("API nativa", StringComparison.OrdinalIgnoreCase) >= 0;

            T.Ev(r, fromNativeApi ? "Native" : "Fonte", fromNativeApi ? "GetFirmwareType()" : "metodo de deteccao",
                fromNativeApi ? f.FirmwareType : T.Name(f.FirmwareTypeSource, "?") + " -> " + f.FirmwareType);

            Confidence confBuilder = fromNativeApi
                ? Confidence.Build().Authoritative().AgreeingSource()
                : Confidence.Build().UnreliableSource();
            int confidence = confBuilder.Value;

            if (f.FirmwareType == "UEFI")
                return T.Pass(r, "Equipamento inicializa em modo UEFI.", confidence);

            return T.Warn(r, Severity.Low,
                "Equipamento operando em modo Legacy (BIOS/CSM).",
                "Modo Legacy impede Secure Boot e nao atende ao requisito do Windows 11. A conversao de MBR para GPT (mbr2gpt) permite migrar sem reinstalar, mas exige backup previo e ajuste na configuracao da placa-mae.",
                confidence);
        }

        private TestResult SecureBoot(ScanContext ctx, Inventory inv)
        {
            TestResult r = T.Make("SYS-003", "Secure Boot", Category,
                "Verifica o estado do Secure Boot, distinguindo desativado de nao suportado.");

            string state = inv.Firmware.SecureBootState;
            if (state == null) return T.Unknown(r, "Estado do Secure Boot nao pode ser lido.");

            T.Ev(r, "Registry", @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled", state);
            int confidence = Confidence.Build().Authoritative().Value;

            if (state == "Ativado") return T.Pass(r, "Secure Boot ativado.", confidence);
            if (state == "RequerAdministrador") return T.RequiresAdmin(r, "Ler o estado do Secure Boot");
            if (state.StartsWith("NaoSuportado", StringComparison.Ordinal))
                return T.Info(r, "Secure Boot nao esta disponivel neste equipamento (" + state + ").", confidence);
            if (state == "Desconhecido") return T.Unknown(r, "A chave de Secure Boot existe mas nao expos o valor.");

            return T.Warn(r, Severity.Low,
                "Secure Boot esta desativado, embora o equipamento suporte.",
                "Ativar Secure Boot na configuracao UEFI aumenta a protecao contra bootkits. Requer que o sistema esteja instalado em GPT/UEFI.",
                confidence);
        }

        private TestResult Tpm(ScanContext ctx, Inventory inv)
        {
            TestResult r = T.Make("SYS-004", "TPM", Category,
                "Verifica presenca, versao e estado do modulo TPM.");

            FirmwareInfo f = inv.Firmware;

            if (f.TpmVersion == "RequerAdministrador") return T.RequiresAdmin(r, "Consultar o TPM");
            if (!f.TpmPresent.HasValue) return T.Unknown(r, "O provedor de TPM nao respondeu.");

            if (f.TpmPresent.Value == false)
            {
                T.Ev(r, "WMI", "Win32_Tpm", "nenhuma instancia");
                return T.Info(r, "Nenhum TPM detectado. O Windows 11 exige TPM 2.0.",
                    Confidence.Build().Authoritative().Value);
            }

            T.Ev(r, "WMI", "Win32_Tpm.SpecVersion", T.Name(f.TpmVersion, "desconhecida"));
            T.Ev(r, "WMI", "Win32_Tpm.IsEnabled_InitialValue", f.TpmEnabled);

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;
            bool is20 = f.TpmVersion != null && f.TpmVersion.StartsWith("2.", StringComparison.Ordinal);

            if (f.TpmEnabled == false)
                return T.Warn(r, Severity.Low,
                    "TPM presente (versao " + T.Name(f.TpmVersion, "desconhecida") + ") mas desativado.",
                    "Ativar o TPM na configuracao UEFI. Necessario para BitLocker e para o Windows 11.",
                    confidence);

            if (!is20)
                return T.Info(r, "TPM presente na versao " + T.Name(f.TpmVersion, "desconhecida") + " (o Windows 11 exige 2.0).", confidence);

            return T.Pass(r, "TPM " + f.TpmVersion + " presente e ativo.", confidence);
        }

        // Idade de BIOS NAO e defeito. Classificado como INFO ate 8 anos e
        // como recomendacao acima disso - nunca como erro, conforme item 9 do
        // briefing.
        private TestResult BiosAge(ScanContext ctx, Inventory inv)
        {
            TestResult r = T.Make("SYS-005", "Idade do firmware (BIOS/UEFI)", Category,
                "Avalia ha quanto tempo o firmware nao e atualizado.");

            FirmwareInfo f = inv.Firmware;
            if (!f.AgeYears.HasValue)
                return T.Unknown(r, "A data de lancamento do firmware nao foi informada pelo SMBIOS ou e invalida.");

            T.Ev(r, "WMI", "Win32_BIOS.ReleaseDate", T.Date(f.ReleaseDate));
            T.Ev(r, "WMI", "Win32_BIOS.SMBIOSBIOSVersion", T.Name(f.Version, "desconhecida"));

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;
            double years = f.AgeYears.Value;

            if (years >= 8)
                return T.Info(r,
                    "Firmware com " + T.Num(years, 1) + " anos (versao " + T.Name(f.Version, "?") + ").",
                    confidence);

            return T.Pass(r, "Firmware de " + T.Date(f.ReleaseDate) + " (" + T.Num(years, 1) + " anos), dentro do normal.", confidence);
        }

        private TestResult Uptime(ScanContext ctx, Inventory inv)
        {
            TestResult r = T.Make("SYS-006", "Tempo ligado sem reiniciar", Category,
                "Uptime muito alto adia atualizacoes e acumula vazamento de memoria de drivers.");

            if (!inv.Os.UptimeHours.HasValue)
                return T.Unknown(r, "O horario do ultimo boot nao foi informado.");

            double hours = inv.Os.UptimeHours.Value;
            T.Ev(r, "WMI", "Win32_OperatingSystem.LastBootUpTime", T.Date(inv.Os.LastBootTime));

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;
            double days = hours / 24.0;

            if (days >= 30)
                return T.Warn(r, Severity.Low,
                    "Maquina ligada ha " + T.Num(days, 0) + " dias sem reiniciar.",
                    "Reiniciar para aplicar atualizacoes pendentes e liberar recursos retidos por drivers.",
                    confidence);

            return T.Pass(r, "Ligada ha " + T.Num(days, 1) + " dias.", confidence);
        }

        private TestResult WindowsUpdate(ScanContext ctx, Inventory inv)
        {
            TestResult r = T.Make("SYS-007", "Atualizacoes do Windows", Category,
                "Verifica ha quanto tempo a ultima atualizacao foi instalada.");

            OsInfo os = inv.Os;
            if (!os.LastUpdateInstalled.HasValue)
            {
                if (os.UpdatesInstalledCount.HasValue && os.UpdatesInstalledCount.Value == 0)
                    return T.Warn(r, Severity.Medium,
                        "Nenhuma atualizacao registrada no historico do sistema.",
                        "Verificar o Windows Update. Historico vazio pode indicar instalacao recente ou servico de atualizacao quebrado.",
                        Confidence.Build().Authoritative().Value);

                return T.Unknown(r, "O historico de atualizacoes (Win32_QuickFixEngineering) nao pode ser lido.");
            }

            // Teste nunca le o relogio do SO diretamente (regra da
            // ARQUITETURA) - usar DateTime.Now tornaria SYS-007 nao
            // reprodutivel entre execucoes do mesmo laudo salvo.
            // ctx.StartedAt e capturado uma unica vez, fora da camada de
            // analise, no inicio do scan.
            double days = (ctx.StartedAt - os.LastUpdateInstalled.Value).TotalDays;
            T.Ev(r, "WMI", "Win32_QuickFixEngineering.InstalledOn", T.Date(os.LastUpdateInstalled));
            if (os.LastUpdateId != null) T.Ev(r, "WMI", "Win32_QuickFixEngineering.HotFixID", os.LastUpdateId);
            T.Ev(r, "WMI", "Win32_QuickFixEngineering (total)", T.Num(os.UpdatesInstalledCount));

            // A janela de 90 dias corresponde a tres ciclos mensais perdidos:
            // e o ponto em que a defasagem deixa de ser normal.
            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (days >= 180)
                return T.Error(r, Severity.High,
                    "Ultima atualizacao instalada ha " + T.Num(days, 0) + " dias (" + T.Date(os.LastUpdateInstalled) + ").",
                    "Executar o Windows Update. Defasagem desse tamanho normalmente indica servico de atualizacao quebrado, e deixa vulnerabilidades conhecidas sem correcao.",
                    confidence);

            if (days >= 90)
                return T.Warn(r, Severity.Medium,
                    "Ultima atualizacao instalada ha " + T.Num(days, 0) + " dias (" + T.Date(os.LastUpdateInstalled) + ").",
                    "Executar o Windows Update e verificar se ha erro no servico.",
                    confidence);

            return T.Pass(r, "Ultima atualizacao em " + T.Date(os.LastUpdateInstalled) +
                " (" + T.Num(os.UpdatesInstalledCount) + " no historico).", confidence);
        }
    }
}
