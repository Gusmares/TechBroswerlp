using System;
using System.Collections.Generic;
using System.Globalization;

namespace PcDiag.Sources
{
    // Linha generica de resultado (WMI/CIM ou registro). Getters devolvem
    // tipos ANULAVEIS: null significa "campo ausente ou ilegivel", nunca 0.
    // Essa distincao e a base para o relatorio nunca confundir "zero" com
    // "nao consegui ler".
    public sealed class DataRow
    {
        private readonly Dictionary<string, object> _values;

        public DataRow()
        {
            _values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        }

        public DataRow(Dictionary<string, object> values)
        {
            _values = new Dictionary<string, object>(values, StringComparer.OrdinalIgnoreCase);
        }

        public void Set(string key, object value)
        {
            _values[key] = value;
        }

        public bool Has(string key)
        {
            object v;
            return _values.TryGetValue(key, out v) && v != null;
        }

        public object Raw(string key)
        {
            object v;
            return _values.TryGetValue(key, out v) ? v : null;
        }

        public IEnumerable<string> Keys { get { return _values.Keys; } }

        public string Str(string key)
        {
            object v = Raw(key);
            if (v == null) return null;
            string s = v as string;
            if (s == null)
            {
                string[] arr = v as string[];
                if (arr != null) return string.Join(", ", arr);
                s = Convert.ToString(v, CultureInfo.InvariantCulture);
            }
            if (s == null) return null;
            s = s.Trim();
            return s.Length == 0 ? null : s;
        }

        public int? Int(string key)
        {
            object v = Raw(key);
            if (v == null) return null;
            try { return Convert.ToInt32(v, CultureInfo.InvariantCulture); }
            catch { return null; }
        }

        public long? Long(string key)
        {
            object v = Raw(key);
            if (v == null) return null;
            try { return Convert.ToInt64(v, CultureInfo.InvariantCulture); }
            catch { return null; }
        }

        public ulong? ULong(string key)
        {
            object v = Raw(key);
            if (v == null) return null;
            try { return Convert.ToUInt64(v, CultureInfo.InvariantCulture); }
            catch { return null; }
        }

        public double? Double(string key)
        {
            object v = Raw(key);
            if (v == null) return null;
            try { return Convert.ToDouble(v, CultureInfo.InvariantCulture); }
            catch { return null; }
        }

        public bool? Bool(string key)
        {
            object v = Raw(key);
            if (v == null) return null;
            try { return Convert.ToBoolean(v, CultureInfo.InvariantCulture); }
            catch { return null; }
        }

        public DateTime? Date(string key)
        {
            object v = Raw(key);
            if (v == null) return null;
            if (v is DateTime) return (DateTime)v;
            string s = v as string;
            if (string.IsNullOrEmpty(s)) return null;

            // CIM_DATETIME: yyyyMMddHHmmss.ffffff+UUU
            if (s.Length >= 14)
            {
                try
                {
                    int year = int.Parse(s.Substring(0, 4), CultureInfo.InvariantCulture);
                    int month = int.Parse(s.Substring(4, 2), CultureInfo.InvariantCulture);
                    int day = int.Parse(s.Substring(6, 2), CultureInfo.InvariantCulture);
                    int hour = int.Parse(s.Substring(8, 2), CultureInfo.InvariantCulture);
                    int min = int.Parse(s.Substring(10, 2), CultureInfo.InvariantCulture);
                    int sec = int.Parse(s.Substring(12, 2), CultureInfo.InvariantCulture);
                    if (year >= 1601 && year <= 9999 && month >= 1 && month <= 12 && day >= 1 && day <= 31)
                        return new DateTime(year, month, day, hour, min, sec);
                }
                catch { }
            }

            DateTime parsed;
            if (DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed)) return parsed;
            return null;
        }

        public string[] StrArray(string key)
        {
            object v = Raw(key);
            if (v == null) return null;
            string[] arr = v as string[];
            if (arr != null) return arr;
            string s = v as string;
            if (s != null) return new string[] { s };
            return null;
        }
    }

    public interface IWmiSource
    {
        IList<DataRow> Query(string scope, string wql);
    }

    public interface IRegistrySource
    {
        // hive: "HKLM" ou "HKCU". Devolve null se a chave nao existir.
        object GetValue(string hive, string subKey, string valueName);
        IList<string> GetSubKeyNames(string hive, string subKey);
        IList<string> GetValueNames(string hive, string subKey);
        bool KeyExists(string hive, string subKey);
    }

    public sealed class EventRecordLite
    {
        public DateTime? TimeCreated { get; set; }
        public int Id { get; set; }
        public string ProviderName { get; set; }
        public string LevelName { get; set; }
        public int Level { get; set; }
        public string Message { get; set; }
        public string LogName { get; set; }
    }

    public interface IEventLogSource
    {
        // Query XPath sobre um log. maxEvents limita o custo em maquinas com
        // log gigante. Lanca UnauthorizedAccessException se faltar privilegio.
        //
        // truncated: true quando existem MAIS eventos correspondentes alem de
        // maxEvents - a consulta e ReverseDirection (mais recentes primeiro),
        // entao o corte descarta justamente os eventos mais ANTIGOS da janela
        // pedida. Sem esse sinal, o chamador nao tem como distinguir "sem
        // ocorrencia na janela inteira" de "sem ocorrencia no que coube em
        // maxEvents".
        IList<EventRecordLite> Query(string logName, string xpath, int maxEvents, out bool truncated);

        // Um log recem-limpo ou com retencao mais curta que a janela pedida
        // devolve MENOS eventos que o teto, sem nunca acionar "truncated"
        // (nao ha teto cortando nada) - mas "zero ocorrencias" tambem nao
        // prova nada sobre os WindowDays inteiros, so sobre o que a retencao
        // de fato guardou. Devolve o TimeCreated do evento mais ANTIGO ainda
        // presente no log inteiro (sem filtro de nivel/data), ou null se o
        // log estiver vazio ou inacessivel - permite comparar contra o
        // inicio nominal da janela antes de aceitar "zero" como um fato
        // sobre o periodo pedido.
        DateTime? OldestEventTime(string logName);
    }

    public sealed class ProcessResult
    {
        public int ExitCode { get; set; }
        public string StandardOutput { get; set; }
        public string StandardError { get; set; }
        public bool TimedOut { get; set; }
        public bool Started { get; set; }
        public string FailureReason { get; set; }
    }

    public interface IProcessRunner
    {
        // executableName e resolvido para %SystemRoot%\System32\<nome> - nunca
        // pelo PATH. args e um array; a montagem da linha de comando faz o
        // quoting correto. Isso fecha command injection, argument injection e
        // PATH hijacking de uma vez.
        ProcessResult RunSystem32(string executableName, string[] args, int timeoutMs);
    }
}
