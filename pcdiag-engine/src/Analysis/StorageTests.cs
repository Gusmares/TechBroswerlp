using System;
using System.Collections.Generic;
using System.Globalization;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Analysis
{
    public sealed class StorageTests : IDiagnosticTest
    {
        public string Category { get { return "Armazenamento"; } }

        public IEnumerable<TestResult> Run(ScanContext ctx, Inventory inv)
        {
            List<TestResult> list = new List<TestResult>();

            if (inv.Disks.Count == 0)
            {
                TestResult none = T.Make("STO-001", "Discos fisicos", Category, "Enumera os discos instalados.");
                list.Add(T.Unknown(none, "Nenhum disco fisico foi enumerado - o provedor de storage pode estar indisponivel."));
            }

            int n = 0;
            foreach (DiskInfo d in inv.Disks)
            {
                n++;
                list.Add(Health(ctx, d, n));
                list.Add(Smart(ctx, d, n));
                list.Add(Wear(ctx, d, n));
                list.Add(Temperature(ctx, d, n));
                list.Add(UncorrectedErrors(ctx, d, n));
            }

            foreach (VolumeInfo v in inv.Volumes)
            {
                list.Add(FreeSpace(v));
                list.Add(DirtyBit(v));
            }

            list.Add(ControllerEvents(inv));
            list.Add(SystemEncryption(inv));
            return list;
        }

        private static string DiskLabel(DiskInfo d, int n)
        {
            string model = T.Name(d.Model, "disco " + n);
            string letters = d.VolumeLetters.Count > 0 ? " (" + string.Join(", ", d.VolumeLetters.ToArray()) + ")" : "";
            return model + letters;
        }

        private TestResult Health(ScanContext ctx, DiskInfo d, int n)
        {
            string suffix = "-" + n.ToString("D2", CultureInfo.InvariantCulture);
            TestResult r = T.Make("STO-001" + suffix, "Saude do disco: " + DiskLabel(d, n), Category,
                "Estado de saude reportado pela camada de armazenamento do Windows.");

            T.Ev(r, "WMI", "MSFT_PhysicalDisk.FriendlyName", T.Name(d.Model, "?"));
            T.Ev(r, "WMI", "MSFT_PhysicalDisk.Size", T.Bytes(d.SizeBytes));
            if (d.BusType != null) T.Ev(r, "WMI", "MSFT_PhysicalDisk.BusType", d.BusType);
            if (d.MediaType != null) T.Ev(r, "WMI", "MSFT_PhysicalDisk.MediaType", d.MediaType);

            if (d.HealthStatus == null)
                return T.Unknown(r, "A camada de storage nao reportou estado de saude para este disco (fonte: " +
                    T.Name(d.MediaTypeSource, "desconhecida") + ").");

            T.Ev(r, "WMI", "MSFT_PhysicalDisk.HealthStatus", d.HealthStatus);
            if (d.OperationalStatus != null) T.Ev(r, "WMI", "MSFT_PhysicalDisk.OperationalStatus", d.OperationalStatus);

            // A fonte primaria aqui e WMI (MSFT_PhysicalDisk), nao API
            // nativa nem contador do kernel - nao reivindica
            // Authoritative(). AgreeingSource() so e concedido quando
            // StorageCollector.CrossCheckLegacy de fato confirmou que
            // Win32_DiskDrive.Status concorda com HealthStatus - nunca
            // incondicionalmente.
            Confidence confBuilder = Confidence.Build().PlausibleRange();
            if (d.HealthConfirmedByLegacyStatus) confBuilder = confBuilder.AgreeingSource();
            int confidence = confBuilder.Value;

            if (string.Equals(d.HealthStatus, "Healthy", StringComparison.OrdinalIgnoreCase))
            {
                string kind = d.MediaType == null ? "" : d.MediaType + " ";
                return T.Pass(r, kind + T.Bytes(d.SizeBytes) + " via " + T.Name(d.BusType, "?") + ", saude reportada como Healthy.", confidence);
            }

            if (string.Equals(d.HealthStatus, "Unknown", StringComparison.OrdinalIgnoreCase))
                return T.Unknown(r, "O disco nao reportou estado de saude (comum em disco USB e em alguns controladores RAID).");

            // Qualquer valor diferente de "Healthy" (Unhealthy, Warning, ou
            // um enum futuro que a WMI venha a expor e que o codigo ainda
            // nao conheca por nome) cai aqui - nunca num Pass generico que
            // nao comparou com "Healthy" de verdade. Alinhado com
            // ARQUITETURA.md 5 ("Saude de disco != Healthy ->
            // CRITICAL/CRITICAL"): Warning tambem vira Critical, igual a
            // Unhealthy.
            return T.Critical(r,
                "Disco em estado de saude '" + d.HealthStatus + "' (status operacional: " + T.Name(d.OperationalStatus, "?") +
                ") - diferente de Healthy.",
                "Fazer backup imediato dos dados deste disco antes de qualquer outra intervencao. O Windows so sai desse estado quando o proprio disco reporta funcionamento normal.",
                confidence);
        }

        private TestResult Smart(ScanContext ctx, DiskInfo d, int n)
        {
            string suffix = "-" + n.ToString("D2", CultureInfo.InvariantCulture);
            TestResult r = T.Make("STO-002" + suffix, "Predicao SMART: " + DiskLabel(d, n), Category,
                "Verifica se o disco esta prevendo falha iminente pelo mecanismo SMART.");
            r.Requires = Requirement.Admin;

            if (!d.SmartPredictFailure.HasValue)
            {
                if (!ctx.IsElevated) return T.RequiresAdmin(r, "Consultar a predicao de falha SMART");
                return T.NotTested(r, T.Name(d.SmartSource,
                    "O driver do controlador nao expoe predicao SMART para este disco."));
            }

            T.Ev(r, "WMI", "MSStorageDriver_FailurePredictStatus.PredictFailure", d.SmartPredictFailure.Value);
            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (d.SmartPredictFailure.Value)
                return T.Critical(r,
                    "O disco esta reportando FALHA IMINENTE pelo SMART.",
                    "Backup imediato e substituicao do disco. Predicao SMART positiva significa que o proprio firmware do disco ultrapassou um limiar critico de atributo.",
                    confidence);

            return T.Pass(r, "SMART nao preve falha iminente para este disco.", confidence);
        }

        private TestResult Wear(ScanContext ctx, DiskInfo d, int n)
        {
            string suffix = "-" + n.ToString("D2", CultureInfo.InvariantCulture);
            TestResult r = T.Make("STO-003" + suffix, "Desgaste do SSD: " + DiskLabel(d, n), Category,
                "Percentual de vida util consumida, quando o disco expoe esse contador.");
            r.Requires = Requirement.Admin;

            if (d.MediaType == "HDD")
                return T.NotApplicable(r, "Disco mecanico (HDD) nao possui contador de desgaste por escrita.");

            if (!d.WearPercent.HasValue)
            {
                if (!ctx.IsElevated) return T.RequiresAdmin(r, "Ler os contadores de confiabilidade do disco");
                return T.NotTested(r, "Este disco/controlador nao expoe o contador de desgaste ao Windows.");
            }

            int wear = d.WearPercent.Value;
            T.Ev(r, "WMI", "MSFT_StorageReliabilityCounter.Wear", wear.ToString(CultureInfo.InvariantCulture) + "%");
            if (d.PowerOnHours.HasValue)
                T.Ev(r, "WMI", "MSFT_StorageReliabilityCounter.PowerOnHours",
                    d.PowerOnHours.Value + " h (" + (d.PowerOnHours.Value / 24) + " dias)");

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (wear >= 80)
                return T.Error(r, Severity.High,
                    "SSD com " + wear + "% da vida util consumida.",
                    "Acima de 80% o fabricante ja nao garante retencao de dados. Planejar substituicao e manter backup em dia.",
                    confidence);

            if (wear >= 50)
                return T.Warn(r, Severity.Medium,
                    "SSD com " + wear + "% da vida util consumida.",
                    "Metade da vida util gasta. Acompanhar a evolucao em atendimentos futuros comparando com este laudo.",
                    confidence);

            if (wear >= 20)
                return T.Info(r, "SSD com " + wear + "% da vida util consumida - dentro do esperado para uso normal.", confidence);

            return T.Pass(r, "SSD com " + wear + "% da vida util consumida.", confidence);
        }

        // Erro nao corrigido significa que o controlador desistiu de
        // recuperar o setor: e evidencia de falha ja ocorrida, nao de
        // risco futuro.
        private TestResult UncorrectedErrors(ScanContext ctx, DiskInfo d, int n)
        {
            string suffix = "-" + n.ToString("D2", CultureInfo.InvariantCulture);
            TestResult r = T.Make("STO-009" + suffix, "Erros de leitura/escrita nao corrigidos: " + DiskLabel(d, n), Category,
                "Contador de operacoes de E/S que o controlador nao conseguiu corrigir - evidencia de perda de dado ja consumada.");
            r.Requires = Requirement.Admin;

            if (!d.ReadErrorsUncorrected.HasValue && !d.WriteErrorsUncorrected.HasValue)
            {
                if (!ctx.IsElevated) return T.RequiresAdmin(r, "Ler os contadores de confiabilidade do disco");
                return T.NotTested(r, "Este disco/controlador nao expoe contadores de erro nao corrigido ao Windows.");
            }

            ulong readErrors = d.ReadErrorsUncorrected.HasValue ? d.ReadErrorsUncorrected.Value : 0;
            ulong writeErrors = d.WriteErrorsUncorrected.HasValue ? d.WriteErrorsUncorrected.Value : 0;
            T.Ev(r, "WMI", "MSFT_StorageReliabilityCounter.ReadErrorsUncorrected", readErrors.ToString(CultureInfo.InvariantCulture));
            T.Ev(r, "WMI", "MSFT_StorageReliabilityCounter.WriteErrorsUncorrected", writeErrors.ToString(CultureInfo.InvariantCulture));

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (readErrors > 0 || writeErrors > 0)
                return T.Critical(r,
                    "Disco reportou " + readErrors + " erro(s) de leitura e " + writeErrors +
                    " erro(s) de escrita NAO CORRIGIDOS pelo controlador.",
                    "Isso e perda de dado ja ocorrida, nao um risco futuro. Fazer backup imediato e considerar substituicao do disco, independentemente do que os outros testes de saude mostrarem.",
                    confidence);

            return T.Pass(r, "Nenhum erro de leitura ou escrita nao corrigido reportado pelo controlador.", confidence);
        }

        private TestResult Temperature(ScanContext ctx, DiskInfo d, int n)
        {
            string suffix = "-" + n.ToString("D2", CultureInfo.InvariantCulture);
            TestResult r = T.Make("STO-004" + suffix, "Temperatura do disco: " + DiskLabel(d, n), Category,
                "Temperatura do disco, quando exposta pelo controlador ou por sensor.");
            r.Requires = Requirement.Sensors;

            if (!d.TemperatureC.HasValue)
            {
                if (!ctx.IsElevated) return T.RequiresAdmin(r, "Ler a temperatura do disco");
                return T.NotTested(r, "Nem o contador de confiabilidade nem os sensores expuseram a temperatura deste disco.");
            }

            double temp = d.TemperatureC.Value;
            T.Ev(r, T.Name(d.TemperatureSource, "Sensor"), "temperatura do disco", T.Num(temp, 1) + " C");

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            // NVMe opera quente por natureza; 70 C e o ponto em que a maioria
            // comeca a fazer throttling termico.
            if (temp >= 70)
                return T.Warn(r, Severity.Medium,
                    "Disco a " + T.Num(temp, 1) + " C.",
                    "Acima de 70 C o SSD reduz desempenho para se proteger. Verificar fluxo de ar e, em NVMe, a presenca do dissipador.",
                    confidence);

            return T.Pass(r, "Disco a " + T.Num(temp, 1) + " C.", confidence);
        }

        private TestResult FreeSpace(VolumeInfo v)
        {
            TestResult r = T.Make("STO-005-" + T.Name(v.DriveLetter, "?").Replace(":", ""),
                "Espaco livre em " + T.Name(v.DriveLetter, "?"), Category,
                "Espaco livre no volume; pouco espaco degrada desempenho e impede atualizacoes.");

            if (!v.FreePercent.HasValue || !v.SizeBytes.HasValue)
                return T.Unknown(r, "Tamanho ou espaco livre do volume nao foi reportado.");

            T.Ev(r, "WMI", "Win32_LogicalDisk.Size", T.Bytes(v.SizeBytes));
            T.Ev(r, "WMI", "Win32_LogicalDisk.FreeSpace", T.Bytes(v.FreeBytes));
            if (v.FileSystem != null) T.Ev(r, "WMI", "Win32_LogicalDisk.FileSystem", v.FileSystem);

            double pct = v.FreePercent.Value;
            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;
            bool isSystem = v.IsBootVolume == true;
            string what = isSystem ? "volume do sistema" : "volume de dados";

            if (pct <= 5)
                return T.Error(r, Severity.High,
                    T.Name(v.DriveLetter, "?") + " (" + what + ") com apenas " + T.Num(pct, 1) + "% livres (" + T.Bytes(v.FreeBytes) + ").",
                    isSystem
                        ? "Espaco critico no volume do Windows: impede atualizacoes, quebra o arquivo de paginacao e causa lentidao severa. Liberar espaco com a Limpeza de Disco e mover dados do usuario."
                        : "Liberar espaco ou mover dados para outro volume.",
                    confidence);

            if (pct <= 10)
                return T.Warn(r, Severity.Medium,
                    T.Name(v.DriveLetter, "?") + " com " + T.Num(pct, 1) + "% livres (" + T.Bytes(v.FreeBytes) + ").",
                    "Manter pelo menos 10-15% livres, especialmente em SSD, onde o espaco livre e usado para nivelamento de escrita.",
                    confidence);

            return T.Pass(r, T.Name(v.DriveLetter, "?") + " com " + T.Num(pct, 1) + "% livres (" +
                T.Bytes(v.FreeBytes) + " de " + T.Bytes(v.SizeBytes) + ").", confidence);
        }

        // STO-006 e emitido sempre: PASS quando confirmado limpo, WARNING
        // quando sujo, e NotTested quando a leitura nao respondeu - nunca
        // omitido da lista, para a cobertura sempre refletir esta
        // verificacao.
        private TestResult DirtyBit(VolumeInfo v)
        {
            TestResult r = T.Make("STO-006-" + T.Name(v.DriveLetter, "?").Replace(":", ""),
                "Sinalizador de volume sujo em " + T.Name(v.DriveLetter, "?"), Category,
                "O dirty bit indica que o volume nao foi desmontado corretamente ou tem inconsistencia pendente.");

            if (!v.DirtyBit.HasValue)
                return T.NotTested(r, "Win32_Volume.DirtyBitSet nao foi reportado para o volume " + T.Name(v.DriveLetter, "?") + ".");

            T.Ev(r, "WMI", "Win32_Volume.DirtyBitSet", v.DirtyBit.Value);
            int confidence = Confidence.Build().Authoritative().Value;

            if (!v.DirtyBit.Value)
                return T.Pass(r, "O volume " + T.Name(v.DriveLetter, "?") + " nao esta marcado como sujo.", confidence);

            return T.Warn(r, Severity.Medium,
                "O volume " + T.Name(v.DriveLetter, "?") + " esta marcado como 'sujo' (dirty bit ativo).",
                "O Windows vai executar verificacao automatica no proximo boot. Se o sinalizador reaparecer depois disso, ha problema de hardware ou de desligamento abrupto recorrente. Verificacao sob demanda: 'chkdsk " +
                T.Name(v.DriveLetter, "C:") + "' somente leitura, sem /f, antes de qualquer reparo.",
                confidence);
        }

        private TestResult ControllerEvents(Inventory inv)
        {
            TestResult r = T.Make("STO-007", "Erros de disco no log do sistema", Category,
                "Erros reportados pelos drivers de disco, NTFS e controladores.");

            EventsInfo e = inv.Events;
            if (!e.Accessible) return T.NotTested(r, T.Name(e.InaccessibleReason, "Log de eventos indisponivel."));
            if (!e.DiskControllerErrors.HasValue) return T.NotTested(r, "A contagem de erros de disco nao pode ser apurada.");

            int count = e.DiskControllerErrors.Value;
            T.Ev(r, "EventLog", "System, provedores de disco/NTFS/controlador (" + e.WindowDays + " dias)", count);

            foreach (EventSummaryItem item in e.DiskEvents)
                T.Ev(r, "EventLog", T.Name(item.Provider, "?") + " id " + item.Id, T.Date(item.Time) + " - " + Html.Truncate(item.Message, 160));

            int confidence = Confidence.Build().Authoritative().PlausibleRange().Value;

            if (count >= 10)
                return T.Error(r, Severity.High,
                    count + " erros de disco/controlador nos ultimos " + e.WindowDays + " dias.",
                    "Volume desse tipo de erro costuma indicar cabo SATA com mau contato, fonte instabilizando o disco, ou o proprio disco falhando. Cruzar com a saude SMART do disco correspondente.",
                    confidence);

            if (count > 0)
                return T.Warn(r, Severity.Medium,
                    count + " erro(s) de disco/controlador nos ultimos " + e.WindowDays + " dias.",
                    "Acompanhar. Erros isolados podem vir de remocao abrupta de dispositivo USB.",
                    confidence);

            // Teto de 400 eventos atingido = os eventos mais ANTIGOS da
            // janela pedida nao foram lidos - count==0 so vale para o que
            // foi de fato coberto.
            if (e.SystemLogTruncated)
                return T.Unknown(r, "O log 'System' tem mais eventos do que o teto de leitura - a cobertura real vai ate " +
                    T.Date(e.SystemLogOldestCoveredUtc) + ", nao ate o inicio dos " + e.WindowDays +
                    " dias pedidos. Nenhum erro de disco/controlador no periodo efetivamente coberto.");

            return T.Pass(r, "Nenhum erro de disco ou controlador nos ultimos " + e.WindowDays + " dias.", confidence);
        }

        private TestResult SystemEncryption(Inventory inv)
        {
            TestResult r = T.Make("STO-008", "Criptografia do volume do sistema", Category,
                "Estado do BitLocker no volume onde o Windows esta instalado.");

            string state = inv.Security.BitLockerSystemDrive;
            if (state == null || state == "NaoDeterminado")
            {
                string reason = null;
                foreach (VolumeInfo v in inv.Volumes)
                {
                    if (v.BitLockerSource != null) { reason = v.BitLockerSource; break; }
                }
                if (reason != null && reason.IndexOf("Administrador", StringComparison.OrdinalIgnoreCase) >= 0)
                    return T.RequiresAdmin(r, "Consultar o estado do BitLocker");
                return T.NotTested(r, T.Name(reason, "O provedor de criptografia de volume nao respondeu."));
            }

            T.Ev(r, "WMI", "Win32_EncryptableVolume.ProtectionStatus", state);
            int confidence = Confidence.Build().Authoritative().Value;

            if (state == "Criptografado")
                return T.Pass(r, "Volume do sistema protegido por BitLocker.", confidence);

            // Ausencia de BitLocker e uma constatacao, nao um defeito: na
            // maioria das maquinas domesticas nao ha requisito de criptografia.
            return T.Info(r, "Volume do sistema nao esta criptografado (" + state +
                "). Relevante se o equipamento sair da empresa ou guardar dado sensivel.", confidence);
        }
    }
}
