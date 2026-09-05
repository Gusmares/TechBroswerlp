using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;

namespace PcDiag.Sources
{
    public sealed class EventLogSource : IEventLogSource
    {
        public IList<EventRecordLite> Query(string logName, string xpath, int maxEvents, out bool truncated)
        {
            List<EventRecordLite> list = new List<EventRecordLite>();
            truncated = false;

            EventLogQuery q = new EventLogQuery(logName, PathType.LogName, xpath);
            q.ReverseDirection = true; // mais recentes primeiro

            using (EventLogReader reader = new EventLogReader(q))
            {
                int i;
                for (i = 0; i < maxEvents; i++)
                {
                    EventRecord rec;
                    try
                    {
                        rec = reader.ReadEvent();
                    }
                    catch (EventLogException)
                    {
                        // Um canal que falha NO
                        // MEIO da leitura (log corrompido, entrada
                        // ilegivel) devolvia so o que tinha sido lido ate
                        // ali, indistinguivel de "acabaram os eventos que
                        // batem no filtro" - um log com defeito na terceira
                        // leitura produzia "nenhum desligamento inesperado"
                        // com apenas 2 eventos realmente conferidos.
                        // truncated=true propaga que a lista NAO e prova de
                        // completude, reusando o mesmo sinal que ja existe
                        // para o corte por teto - os consumidores (EVT-002,
                        // EVT-003, STO-007) ja tratam truncated como "nao
                        // afirmar ausencia com confianca".
                        truncated = true;
                        break;
                    }

                    if (rec == null) break;

                    using (rec)
                    {
                        EventRecordLite lite = new EventRecordLite();
                        lite.LogName = logName;
                        try { lite.TimeCreated = rec.TimeCreated; } catch { }
                        try { lite.Id = rec.Id; } catch { }
                        try { lite.ProviderName = rec.ProviderName; } catch { }
                        try { lite.Level = rec.Level.HasValue ? rec.Level.Value : -1; } catch { lite.Level = -1; }
                        lite.LevelName = LevelName(lite.Level);

                        // FormatDescription lanca quando o provider que gerou o
                        // evento nao esta mais instalado (driver removido, por
                        // exemplo). Nesse caso a mensagem fica nula e o
                        // relatorio mostra "sem descricao" - nao some a linha.
                        try { lite.Message = rec.FormatDescription(); }
                        catch { lite.Message = null; }

                        list.Add(lite);
                    }
                }

                // O laco acima para em
                // maxEvents SEM checar se havia mais - lista com exatamente
                // maxEvents itens era indistinguivel de "acabou por coincidencia
                // bem nesse numero". Le mais um evento (descartado, so para
                // confirmar) para saber se o corte realmente cortou algo.
                if (i >= maxEvents)
                {
                    try
                    {
                        EventRecord extra = reader.ReadEvent();
                        if (extra != null)
                        {
                            truncated = true;
                            extra.Dispose();
                        }
                    }
                    catch (EventLogException)
                    {
                        // Nao deu para confirmar - fica truncated=false. O
                        // cenario tipico (log grande, varios milhares de
                        // eventos) sempre vai ter pelo menos mais um evento
                        // alem do teto.
                    }
                }
            }

            return list;
        }

        // Le o evento mais ANTIGO do log inteiro
        // (sem filtro), para permitir distinguir "zero eventos porque a
        // maquina esta saudavel" de "zero eventos porque o log foi limpo
        // ha pouco tempo". ReverseDirection=false le do inicio (mais antigo
        // primeiro); maxEvents=1 basta.
        public DateTime? OldestEventTime(string logName)
        {
            try
            {
                EventLogQuery q = new EventLogQuery(logName, PathType.LogName, "*");
                q.ReverseDirection = false;

                using (EventLogReader reader = new EventLogReader(q))
                {
                    EventRecord rec;
                    try { rec = reader.ReadEvent(); }
                    catch (EventLogException) { return null; }

                    if (rec == null) return null;
                    using (rec)
                    {
                        try { return rec.TimeCreated; }
                        catch { return null; }
                    }
                }
            }
            catch { return null; }
        }

        public static string LevelName(int level)
        {
            switch (level)
            {
                case 1: return "Critical";
                case 2: return "Error";
                case 3: return "Warning";
                case 4: return "Information";
                case 5: return "Verbose";
                case 0: return "LogAlways";
                default: return "Unknown";
            }
        }

        // Monta XPath por nivel e janela de tempo. O coletor antigo consultava
        // o provider WHEA SEM filtro de nivel nem de data, e por isso contava
        // eventos informativos de erro CORRIGIDO (rotineiros) como se fossem
        // defeito de memoria.
        public static string XPathLevelsSince(int[] levels, TimeSpan window)
        {
            string levelClause = "";
            for (int i = 0; i < levels.Length; i++)
            {
                if (i > 0) levelClause += " or ";
                levelClause += "Level=" + levels[i];
            }
            long ms = (long)window.TotalMilliseconds;
            return "*[System[(" + levelClause + ") and TimeCreated[timediff(@SystemTime) <= " + ms + "]]]";
        }

        // O nome do provedor entra numa expressao XPath. Hoje so vem de
        // constantes do proprio codigo, mas validar aqui garante que isso
        // continue verdade se alguem passar a monta-lo a partir de dado
        // coletado - um apostrofo bastaria para quebrar (ou desviar) a
        // consulta.
        public static bool IsSafeProviderName(string provider)
        {
            if (string.IsNullOrEmpty(provider)) return false;
            foreach (char c in provider)
            {
                if (char.IsLetterOrDigit(c)) continue;
                if (c == '-' || c == '_' || c == '.' || c == ' ' || c == '/') continue;
                return false;
            }
            return true;
        }

        public static string XPathProviderLevelsSince(string provider, int[] levels, TimeSpan window)
        {
            if (!IsSafeProviderName(provider))
                throw new ArgumentException("Nome de provedor invalido para consulta XPath: " + provider, "provider");

            string levelClause = "";
            for (int i = 0; i < levels.Length; i++)
            {
                if (i > 0) levelClause += " or ";
                levelClause += "Level=" + levels[i];
            }
            long ms = (long)window.TotalMilliseconds;
            return "*[System[Provider[@Name='" + provider + "'] and (" + levelClause + ") and TimeCreated[timediff(@SystemTime) <= " + ms + "]]]";
        }

        public static string XPathIdsSince(int[] ids, TimeSpan window)
        {
            string idClause = "";
            for (int i = 0; i < ids.Length; i++)
            {
                if (i > 0) idClause += " or ";
                idClause += "EventID=" + ids[i];
            }
            long ms = (long)window.TotalMilliseconds;
            return "*[System[(" + idClause + ") and TimeCreated[timediff(@SystemTime) <= " + ms + "]]]";
        }
    }
}
