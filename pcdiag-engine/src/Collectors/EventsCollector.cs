using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    public sealed class EventsCollector : ICollector
    {
        public string Name { get { return "Events"; } }

        private readonly int _days;

        public EventsCollector(int days)
        {
            _days = days < 1 ? 7 : days;
        }

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            EventsInfo e = inv.Events;
            e.WindowDays = _days;
            TimeSpan window = TimeSpan.FromDays(_days);

            // Niveis 1/2/3 (critico/erro/aviso) usam consultas com tetos
            // separados de proposito: numa maquina barulhenta (muitos avisos
            // de nivel 3 - comum e normalmente inofensivo), compartilhar um
            // unico teto deixaria os avisos consumirem o orcamento inteiro e
            // empurrar para fora da janela lida os eventos de nivel 1/2
            // (critico/erro) mais ANTIGOS - justamente os que mais importam
            // para EVT-001/EVT-002/STO-007. Separar em duas consultas com
            // tetos proprios garante que critico/erro tem seu proprio
            // orcamento, independente de quantos avisos existirem.
            bool criticalErrorTruncated, warningTruncated;
            IList<EventRecordLite> criticalError = QueryLog(ctx, src, "System",
                EventLogSource.XPathLevelsSince(new int[] { 1, 2 }, window), 400, e, out criticalErrorTruncated);

            if (criticalError == null)
            {
                e.Accessible = false;
                return;
            }

            IList<EventRecordLite> warningOnly = QueryLog(ctx, src, "System",
                EventLogSource.XPathLevelsSince(new int[] { 3 }, window), 200, e, out warningTruncated);

            e.Accessible = true;

            List<EventRecordLite> system = new List<EventRecordLite>(criticalError);
            if (warningOnly != null) system.AddRange(warningOnly);

            // Log recem-limpo ou com retencao curta demais para cobrir a
            // janela pedida devolve MENOS eventos que o teto, sem nunca
            // acionar o corte por teto (truncated fica false) - mas "zero
            // encontrado" tambem nao e um fato sobre os WindowDays inteiros,
            // so sobre o que a retencao de fato guardou.
            // ReverseDirection=true: o ULTIMO item lido e o mais ANTIGO -
            // compara contra o inicio nominal da janela com uma folga de 1
            // dia (log real raramente comeca exatamente no segundo pedido).
            DateTime? oldestCovered = null;
            if (criticalError.Count > 0) oldestCovered = criticalError[criticalError.Count - 1].TimeCreated;
            if (warningOnly != null && warningOnly.Count > 0)
            {
                DateTime? warningOldest = warningOnly[warningOnly.Count - 1].TimeCreated;
                // A cobertura garantida e a mais RECENTE (menor alcance) das
                // duas consultas - alem desse ponto, uma delas pode ja estar
                // incompleta.
                if (warningOldest.HasValue && (!oldestCovered.HasValue || warningOldest.Value > oldestCovered.Value))
                    oldestCovered = warningOldest;
            }

            // Zero eventos em AMBAS as consultas e o caso ambiguo que o
            // corte por teto nao cobre: pode ser "7 dias tranquilos" (bom
            // sinal, nao mexer) ou "log foi limpo ha 2 dias" (nada garante
            // os outros 5). So um evento mais antigo IGNORANDO nivel/data -
            // OldestEventTime, sem filtro nenhum - distingue os dois casos.
            if (!oldestCovered.HasValue)
                oldestCovered = Try.Get(ctx, Name, "OldestEventTime(System)", delegate { return src.EventLog.OldestEventTime("System"); });

            e.SystemLogOldestCoveredUtc = oldestCovered;

            bool retentionGap = oldestCovered.HasValue &&
                (DateTime.Now - oldestCovered.Value) < TimeSpan.FromDays(Math.Max(0, _days - 1));

            e.SystemLogTruncated = criticalErrorTruncated || warningTruncated || retentionGap;
            SummarizeBuckets(e, "System", system);
            CollectTopEvents(e, system);
            CollectDiskEvents(e, system);
            CountUnexpectedShutdowns(e, system);

            bool appTruncated;
            IList<EventRecordLite> app = QueryLog(ctx, src, "Application",
                EventLogSource.XPathLevelsSince(new int[] { 1, 2 }, window), 200, e, out appTruncated);
            if (app != null)
            {
                SummarizeBuckets(e, "Application", app);
                int crashes = 0;
                foreach (EventRecordLite r in app)
                {
                    if (r.Id == 1000 || r.Id == 1002) crashes++;
                }
                e.AppCrashes = crashes;
            }

            CollectWhea(ctx, src, e, window);
            CollectBugChecks(ctx, src, e, window);
            CollectMinidumps(ctx, e);
            CountServiceFailures(e, system);
        }

        private IList<EventRecordLite> QueryLog(ScanContext ctx, SourceSet src, string logName, string xpath, int max, EventsInfo e, out bool truncated)
        {
            truncated = false;
            try
            {
                return src.EventLog.Query(logName, xpath, max, out truncated);
            }
            catch (UnauthorizedAccessException)
            {
                e.InaccessibleReason = "Leitura do log '" + logName + "' negada - requer privilegio de Administrador.";
                ctx.Log.Warn(Name, e.InaccessibleReason);
                return null;
            }
            catch (System.Diagnostics.Eventing.Reader.EventLogException ex)
            {
                // Deteccao de acesso negado por HRESULT (independente de
                // idioma), nao por substring da mensagem localizada da
                // excecao - o texto da mensagem varia com o idioma do
                // Windows instalado, mas o HRESULT que o runtime deriva do
                // erro Win32 subjacente via HRESULT_FROM_WIN32 e estavel:
                // ERROR_ACCESS_DENIED (5) e ERROR_PRIVILEGE_NOT_HELD (1314)
                // sao os dois codigos que o EventLogReader devolve para
                // canal sem privilegio (Security, principalmente). A
                // negacao em canal padrao chega como
                // UnauthorizedAccessException, capturada no catch acima,
                // antes deste.
                const int HResultAccessDenied = unchecked((int)0x80070005);
                const int HResultPrivilegeNotHeld = unchecked((int)0x80070522);
                bool denied = ex.HResult == HResultAccessDenied || ex.HResult == HResultPrivilegeNotHeld;

                e.InaccessibleReason = denied
                    ? "Leitura do log '" + logName + "' negada - requer privilegio de Administrador."
                    : "Falha lendo o log '" + logName + "': " + ex.Message;
                ctx.Log.Warn(Name, e.InaccessibleReason);
                return null;
            }
            catch (Exception ex)
            {
                e.InaccessibleReason = "Falha lendo o log '" + logName + "': " + ex.Message;
                ctx.Log.Error(Name, e.InaccessibleReason);
                return null;
            }
        }

        private static void SummarizeBuckets(EventsInfo e, string logName, IList<EventRecordLite> records)
        {
            EventBucket b = new EventBucket();
            b.LogName = logName;

            foreach (EventRecordLite r in records)
            {
                if (r.Level == 1) b.Critical++;
                else if (r.Level == 2) b.Error++;
                else if (r.Level == 3) b.Warning++;
            }

            e.Buckets.Add(b);
        }

        private static void CollectTopEvents(EventsInfo e, IList<EventRecordLite> records)
        {
            int added = 0;
            foreach (EventRecordLite r in records)
            {
                if (r.Level != 1 && r.Level != 2) continue;
                if (added >= 25) break;

                EventSummaryItem item = new EventSummaryItem();
                item.Time = r.TimeCreated;
                item.Provider = r.ProviderName;
                item.Id = r.Id;
                item.Level = r.LevelName;
                item.Message = Trim(r.Message, 400);
                e.TopEvents.Add(item);
                added++;
            }
        }

        // WHEA separado por severidade REAL.
        //
        // O provedor WHEA-Logger emite eventos informativos e de aviso para
        // erros CORRIGIDOS (AER de PCIe, cache de CPU), que sao rotineiros em
        // hardware saudavel. O coletor antigo consultava o provedor sem filtro
        // de nivel nem de data e contava tudo como "erro de hardware na
        // memoria" - falso positivo que ainda derrubava o score no dashboard.
        private void CollectWhea(ScanContext ctx, SourceSet src, EventsInfo e, TimeSpan window)
        {
            bool uncorrectedTruncated, correctedTruncated;
            IList<EventRecordLite> uncorrected = QueryLog(ctx, src, "System",
                EventLogSource.XPathProviderLevelsSince("Microsoft-Windows-WHEA-Logger", new int[] { 1, 2 }, window), 50, e, out uncorrectedTruncated);

            IList<EventRecordLite> corrected = QueryLog(ctx, src, "System",
                EventLogSource.XPathProviderLevelsSince("Microsoft-Windows-WHEA-Logger", new int[] { 3, 4 }, window), 50, e, out correctedTruncated);

            if (uncorrected != null)
            {
                e.WheaUncorrectedCount = uncorrected.Count;
                foreach (EventRecordLite r in uncorrected)
                {
                    EventSummaryItem item = new EventSummaryItem();
                    item.Time = r.TimeCreated;
                    item.Provider = r.ProviderName;
                    item.Id = r.Id;
                    item.Level = r.LevelName;
                    item.Message = Trim(r.Message, 400);
                    e.WheaEvents.Add(item);
                }
            }

            if (corrected != null) e.WheaCorrectedCount = corrected.Count;
        }

        private void CollectBugChecks(ScanContext ctx, SourceSet src, EventsInfo e, TimeSpan window)
        {
            // EventID 1001 do provedor de relatorio de erro do sistema e o
            // registro oficial de uma tela azul, com o codigo de parada.
            bool truncated;
            IList<EventRecordLite> bugchecks = QueryLog(ctx, src, "System",
                EventLogSource.XPathProviderLevelsSince("Microsoft-Windows-WER-SystemErrorReporting",
                    new int[] { 1, 2, 3, 4 }, window), 30, e, out truncated);

            if (bugchecks == null) return;

            foreach (EventRecordLite r in bugchecks)
            {
                if (r.Id != 1001) continue;

                BugCheckEvent bc = new BugCheckEvent();
                bc.Time = r.TimeCreated;
                bc.Detail = Trim(r.Message, 500);
                bc.StopCode = ExtractStopCode(r.Message);
                e.BugChecks.Add(bc);
            }

            // So marcado ao final, com a consulta ja concluida sem
            // excecao. EVT-001 usa esta flag (nao e.Accessible, que ja vira
            // true bem antes) para decidir se BugChecks.Count==0 significa
            // "zero telas azuis" ou "nao coletado" (timeout do modulo entre
            // os dois pontos, por exemplo).
            e.BugChecksCollected = true;
        }

        // A mensagem tem a forma "O computador foi reinicializado apos uma
        // verificacao de erros. A verificacao de erros foi: 0x0000009f (...)".
        // Extrai o codigo sem depender do idioma do Windows.
        public static string ExtractStopCode(string message)
        {
            if (string.IsNullOrEmpty(message)) return null;

            int idx = message.IndexOf("0x", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;

            int end = idx + 2;
            while (end < message.Length && Uri.IsHexDigit(message[end])) end++;

            int digits = end - idx - 2;
            if (digits < 4) return null;
            return message.Substring(idx, end - idx).ToLowerInvariant();
        }

        // Kernel-Power 41 e EventLog 6008 sao gravados pelo Windows no boot
        // SEGUINTE para o MESMO desligamento abrupto (um pelo provedor
        // Kernel-Power, outro pelo servico EventLog) - somar os dois
        // contaria cada desligamento real DUAS vezes. Agrupa por
        // proximidade temporal (10 minutos, os dois eventos sao gravados a
        // poucos segundos um do outro) e conta OCORRENCIAS distintas, nao
        // eventos.
        private static void CountUnexpectedShutdowns(EventsInfo e, IList<EventRecordLite> records)
        {
            List<DateTime> times = new List<DateTime>();
            foreach (EventRecordLite r in records)
            {
                bool isKernelPower = r.Id == 41 && r.ProviderName != null &&
                    r.ProviderName.IndexOf("Kernel-Power", StringComparison.OrdinalIgnoreCase) >= 0;
                bool isEventLog6008 = r.Id == 6008;
                if (!isKernelPower && !isEventLog6008) continue;
                if (r.TimeCreated.HasValue) times.Add(r.TimeCreated.Value);
            }

            times.Sort();
            int occurrences = 0;
            DateTime? last = null;
            foreach (DateTime t in times)
            {
                if (!last.HasValue || (t - last.Value) > TimeSpan.FromMinutes(10)) occurrences++;
                last = t;
            }
            e.UnexpectedShutdowns = occurrences;
        }

        private static void CountServiceFailures(EventsInfo e, IList<EventRecordLite> records)
        {
            int count = 0;
            foreach (EventRecordLite r in records)
            {
                if (r.Id == 7000 || r.Id == 7001 || r.Id == 7009 || r.Id == 7011 || r.Id == 7031 || r.Id == 7034) count++;
            }
            e.ServiceFailures = count;
        }

        private static void CollectDiskEvents(EventsInfo e, IList<EventRecordLite> records)
        {
            int controllerErrors = 0;

            foreach (EventRecordLite r in records)
            {
                string provider = r.ProviderName == null ? "" : r.ProviderName.ToLowerInvariant();
                bool isDiskProvider = provider == "disk" || provider == "ntfs" || provider == "volmgr" ||
                                      provider.IndexOf("storahci", StringComparison.Ordinal) >= 0 ||
                                      provider.IndexOf("stornvme", StringComparison.Ordinal) >= 0 ||
                                      provider.IndexOf("iastor", StringComparison.Ordinal) >= 0;

                if (!isDiskProvider) continue;
                if (r.Level != 1 && r.Level != 2) continue;

                controllerErrors++;

                if (e.DiskEvents.Count < 20)
                {
                    EventSummaryItem item = new EventSummaryItem();
                    item.Time = r.TimeCreated;
                    item.Provider = r.ProviderName;
                    item.Id = r.Id;
                    item.Level = r.LevelName;
                    item.Message = Trim(r.Message, 400);
                    e.DiskEvents.Add(item);
                }
            }

            e.DiskControllerErrors = controllerErrors;
        }

        // Presenca e data de minidumps: evidencia independente do log de
        // eventos para confirmar historico de tela azul.
        private void CollectMinidumps(ScanContext ctx, EventsInfo e)
        {
            Try.Do(ctx, Name, "Minidump", delegate
            {
                string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Minidump");
                if (!Directory.Exists(dir))
                {
                    e.MinidumpCount = 0;
                    return;
                }

                string[] files = Directory.GetFiles(dir, "*.dmp");
                e.MinidumpCount = files.Length;

                DateTime? newest = null;
                foreach (string f in files)
                {
                    DateTime t = File.GetLastWriteTime(f);
                    if (!newest.HasValue || t > newest.Value) newest = t;
                }
                e.LastMinidump = newest;
            });
        }

        // Caminho de perfil de usuario dentro de texto livre ("C:\Users\joao.silva\...").
        // Usado para nao gravar o nome de usuario nas mensagens do laudo.
        private static readonly Regex UserProfilePathInText =
            new Regex(@"\\Users\\[^\\/:*?""<>|\r\n]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static string Trim(string s, int max)
        {
            if (s == null) return null;
            s = s.Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ').Trim();

            // EventSummaryItem.Message (ate 400 chars) e BugCheckEvent.Detail
            // (ate 500 chars) sao texto livre do log de eventos, gravados no
            // laudo sem nenhuma classificacao de campo - o dado pessoal (nome
            // da conta no caminho do perfil) fica dentro do texto livre, nao
            // num campo isolado que um atributo no modelo pudesse mascarar
            // sozinho. Por isso o caminho de perfil de usuario e normalizado
            // SEMPRE (nao so em modo privacy-safe) - o nome da conta dentro
            // do caminho nao acrescenta nada ao diagnostico.
            s = UserProfilePathInText.Replace(s, @"\Users\[usuario]");

            if (s.Length <= max) return s;
            return s.Substring(0, max) + "...";
        }
    }
}
