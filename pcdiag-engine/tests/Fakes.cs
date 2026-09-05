using System;
using System.Collections.Generic;
using PcDiag.Collectors;
using PcDiag.Core;
using PcDiag.Sources;

namespace PcDiag.Testing
{
    // Fontes falsas: e o que permite testar coleta e diagnostico sem hardware,
    // sem privilegio e de forma deterministica (itens 63 a 66 do briefing).

    // FakeWmi indexa cada fixture por (scope, classe): consultar a classe
    // certa pelo scope errado devolve lista vazia, exatamente como uma
    // conexao real devolveria para uma classe que nao existe naquele
    // namespace - nunca a fixture de outro namespace por engano. Isso
    // espelha WmiSource.cs, que usa cinco namespaces distintos, e permite
    // simular ManagementScope.Connect() falhando para o namespace inteiro
    // (via DenyScope) quando o namespace nao existe numa maquina real
    // (ex.: Defender desinstalado, edicao N, Server SKU).
    public sealed class FakeWmi : IWmiSource
    {
        // Espelha WmiSource.cs: cada classe usada pelos coletores de
        // producao mora num namespace fixo. Existe para que On(classe,...)/
        // Fail(classe,...) sem scope explicito - a maioria esmagadora dos
        // testes - continuem funcionando exatamente como antes.
        private static readonly Dictionary<string, string> KnownScopes = BuildKnownScopes();

        private static Dictionary<string, string> BuildKnownScopes()
        {
            Dictionary<string, string> m = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string[] cimv2 = new string[]
            {
                "Win32_ComputerSystem", "Win32_SystemEnclosure", "Win32_BaseBoard", "Win32_BIOS",
                "Win32_OperatingSystem", "SoftwareLicensingProduct", "Win32_QuickFixEngineering",
                "Win32_Processor", "Win32_Service", "Win32_DiskDrive", "Win32_LogicalDisk", "Win32_Volume",
                "Win32_DiskPartition", "Win32_LogicalDiskToPartition", "Win32_NetworkAdapter",
                "Win32_NetworkAdapterConfiguration", "Win32_VideoController", "Win32_PnPEntity",
                "Win32_PnPSignedDriver", "Win32_PhysicalMemory", "Win32_PhysicalMemoryArray",
                "Win32_PageFileUsage", "Win32_UserAccount", "Win32_Battery"
            };
            foreach (string c in cimv2) m[c] = WmiSource.CimV2;

            m["MSFT_PhysicalDisk"] = WmiSource.Storage;
            m["MSFT_StorageReliabilityCounter"] = WmiSource.Storage;
            m["MSStorageDriver_FailurePredictStatus"] = WmiSource.Wmi;
            m["MSAcpi_ThermalZoneTemperature"] = WmiSource.Wmi;
            m["MSFT_MpComputerStatus"] = WmiSource.Defender;
            m["AntiVirusProduct"] = WmiSource.SecurityCenter;
            m["Win32_Tpm"] = @"root\CIMV2\Security\MicrosoftTpm";
            m["Win32_EncryptableVolume"] = @"root\CIMV2\Security\MicrosoftVolumeEncryption";
            return m;
        }

        private readonly Dictionary<string, List<DataRow>> _responses =
            new Dictionary<string, List<DataRow>>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Exception> _failures =
            new Dictionary<string, Exception>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Exception> _deniedScopes =
            new Dictionary<string, Exception>(StringComparer.OrdinalIgnoreCase);

        public int QueryCount { get; private set; }

        // Casamento por nome de classe, resolvendo o scope real pelo
        // catalogo acima - o uso tipico, quando o teste nao precisa simular
        // um namespace ausente ou uma classe fora do catalogo.
        public FakeWmi On(string className, params DataRow[] rows)
        {
            return On(ScopeFor(className), className, rows);
        }

        public FakeWmi Fail(string className, Exception ex)
        {
            return Fail(ScopeFor(className), className, ex);
        }

        // Uso explicito: necessario para reproduzir o proprio cenario da
        // mutacao (producao consultando o scope errado) ou uma classe fora
        // do catalogo.
        public FakeWmi On(string scope, string className, params DataRow[] rows)
        {
            _responses[Key(scope, className)] = new List<DataRow>(rows);
            return this;
        }

        public FakeWmi Fail(string scope, string className, Exception ex)
        {
            _failures[Key(scope, className)] = ex;
            return this;
        }

        // Simula ManagementScope.Connect() falhando antes de qualquer WQL
        // rodar - o namespace inteiro nao existe nesta maquina.
        public FakeWmi DenyScope(string scope, Exception ex)
        {
            _deniedScopes[Normalize(scope)] = ex;
            return this;
        }

        public IList<DataRow> Query(string scope, string wql)
        {
            QueryCount++;

            Exception scopeFailure;
            if (_deniedScopes.TryGetValue(Normalize(scope), out scopeFailure)) throw scopeFailure;

            string normalizedScope = Normalize(scope);

            foreach (KeyValuePair<string, Exception> kv in _failures)
            {
                if (ScopeOf(kv.Key) == normalizedScope && wql.IndexOf(ClassOf(kv.Key), StringComparison.OrdinalIgnoreCase) >= 0)
                    throw kv.Value;
            }

            foreach (KeyValuePair<string, List<DataRow>> kv in _responses)
            {
                if (ScopeOf(kv.Key) == normalizedScope && wql.IndexOf(ClassOf(kv.Key), StringComparison.OrdinalIgnoreCase) >= 0)
                    return kv.Value;
            }

            return new List<DataRow>();
        }

        private static string ScopeFor(string className)
        {
            string scope;
            return KnownScopes.TryGetValue(className, out scope) ? scope : WmiSource.CimV2;
        }

        private static string Normalize(string scope)
        {
            return scope == null ? "" : scope.Trim().ToLowerInvariant();
        }

        private static string Key(string scope, string className)
        {
            return Normalize(scope) + "|" + className;
        }

        private static string ScopeOf(string key) { return key.Substring(0, key.IndexOf('|')); }
        private static string ClassOf(string key) { return key.Substring(key.IndexOf('|') + 1); }

        public static DataRow Row(params object[] keyValuePairs)
        {
            DataRow r = new DataRow();
            for (int i = 0; i + 1 < keyValuePairs.Length; i += 2)
                r.Set(Convert.ToString(keyValuePairs[i]), keyValuePairs[i + 1]);
            return r;
        }
    }

    public sealed class FakeRegistry : IRegistrySource
    {
        private readonly Dictionary<string, object> _values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, List<string>> _subKeys = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _denied = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public FakeRegistry Value(string hive, string key, string name, object value)
        {
            _values[hive + "|" + key + "|" + name] = value;
            return this;
        }

        public FakeRegistry SubKeys(string hive, string key, params string[] names)
        {
            _subKeys[hive + "|" + key] = new List<string>(names);
            return this;
        }

        public FakeRegistry Deny(string hive, string key)
        {
            _denied.Add(hive + "|" + key);
            return this;
        }

        public object GetValue(string hive, string subKey, string valueName)
        {
            if (_denied.Contains(hive + "|" + subKey)) throw new UnauthorizedAccessException("acesso negado (fake)");
            object v;
            return _values.TryGetValue(hive + "|" + subKey + "|" + valueName, out v) ? v : null;
        }

        public IList<string> GetSubKeyNames(string hive, string subKey)
        {
            if (_denied.Contains(hive + "|" + subKey)) throw new UnauthorizedAccessException("acesso negado (fake)");
            List<string> v;
            return _subKeys.TryGetValue(hive + "|" + subKey, out v) ? v : new List<string>();
        }

        public IList<string> GetValueNames(string hive, string subKey)
        {
            if (_denied.Contains(hive + "|" + subKey)) throw new UnauthorizedAccessException("acesso negado (fake)");

            List<string> names = new List<string>();
            string prefix = hive + "|" + subKey + "|";
            foreach (string k in _values.Keys)
            {
                if (k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) names.Add(k.Substring(prefix.Length));
            }
            return names;
        }

        public bool KeyExists(string hive, string subKey)
        {
            if (_denied.Contains(hive + "|" + subKey)) return false;
            if (_subKeys.ContainsKey(hive + "|" + subKey)) return true;

            string prefix = hive + "|" + subKey + "|";
            foreach (string k in _values.Keys)
            {
                if (k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }

    public sealed class FakeEventLog : IEventLogSource
    {
        private readonly Dictionary<string, List<EventRecordLite>> _logs =
            new Dictionary<string, List<EventRecordLite>>(StringComparer.OrdinalIgnoreCase);
        private Exception _failure;

        public FakeEventLog On(string logName, params EventRecordLite[] records)
        {
            List<EventRecordLite> list;
            if (!_logs.TryGetValue(logName, out list))
            {
                list = new List<EventRecordLite>();
                _logs[logName] = list;
            }
            list.AddRange(records);
            return this;
        }

        public FakeEventLog FailWith(Exception ex)
        {
            _failure = ex;
            return this;
        }

        // Retorna o menor TimeCreated entre todos os registros do log (sem
        // filtro de nivel/provedor), espelhando o que a versao real
        // (EventLogSource.OldestEventTime) faz sobre o log de verdade.
        public DateTime? OldestEventTime(string logName)
        {
            List<EventRecordLite> list;
            if (!_logs.TryGetValue(logName, out list) || list.Count == 0) return null;

            DateTime? oldest = null;
            foreach (EventRecordLite r in list)
            {
                if (!r.TimeCreated.HasValue) continue;
                if (!oldest.HasValue || r.TimeCreated.Value < oldest.Value) oldest = r.TimeCreated;
            }
            return oldest;
        }

        public IList<EventRecordLite> Query(string logName, string xpath, int maxEvents, out bool truncated)
        {
            truncated = false;
            if (_failure != null) throw _failure;

            List<EventRecordLite> list;
            if (!_logs.TryGetValue(logName, out list)) return new List<EventRecordLite>();

            // Filtragem minima para respeitar a semantica do XPath usado pelo
            // coletor: por provedor e por nivel.
            List<EventRecordLite> result = new List<EventRecordLite>();
            foreach (EventRecordLite r in list)
            {
                if (xpath != null && xpath.IndexOf("Provider[@Name='", StringComparison.Ordinal) >= 0)
                {
                    int start = xpath.IndexOf("Provider[@Name='", StringComparison.Ordinal) + 16;
                    int end = xpath.IndexOf('\'', start);
                    string provider = xpath.Substring(start, end - start);
                    if (!string.Equals(provider, r.ProviderName, StringComparison.OrdinalIgnoreCase)) continue;
                }

                if (xpath != null && xpath.IndexOf("Level=", StringComparison.Ordinal) >= 0)
                {
                    if (xpath.IndexOf("Level=" + r.Level, StringComparison.Ordinal) < 0) continue;
                }

                if (result.Count >= maxEvents)
                {
                    // Ha pelo menos mais um evento que bate no filtro alem do
                    // teto - mesmo sinal que EventLogSource real detecta lendo
                    // um evento extra.
                    truncated = true;
                    break;
                }
                result.Add(r);
            }
            return result;
        }

        public static EventRecordLite Rec(int id, string provider, int level, DateTime when, string message)
        {
            EventRecordLite r = new EventRecordLite();
            r.Id = id;
            r.ProviderName = provider;
            r.Level = level;
            r.LevelName = EventLogSource.LevelName(level);
            r.TimeCreated = when;
            r.Message = message;
            return r;
        }
    }

    public sealed class FakeProcessRunner : IProcessRunner
    {
        private readonly Dictionary<string, ProcessResult> _results =
            new Dictionary<string, ProcessResult>(StringComparer.OrdinalIgnoreCase);

        public List<string> Invocations = new List<string>();

        public FakeProcessRunner On(string exe, ProcessResult result)
        {
            _results[exe] = result;
            return this;
        }

        public ProcessResult RunSystem32(string executableName, string[] args, int timeoutMs)
        {
            Invocations.Add(executableName + " " + ProcessRunner.BuildArguments(args));

            ProcessResult r;
            if (_results.TryGetValue(executableName, out r)) return r;

            ProcessResult notFound = new ProcessResult();
            notFound.FailureReason = "fake: sem resposta configurada para " + executableName;
            return notFound;
        }
    }

    public static class Fixture
    {
        public static ScanContext Context(bool elevated)
        {
            ScanOptions options = ScanOptions.Defaults();
            options.OpenReport = false;
            ScanContext ctx = new ScanContext(options, new Logger(false));

            // IsElevated e detectado do processo real; os testes precisam
            // controlar esse estado para exercitar os dois caminhos.
            ctx.OverrideElevationForTesting(elevated);
            return ctx;
        }

        public static SourceSet Sources(IWmiSource wmi, IRegistrySource registry, IEventLogSource events, IProcessRunner processes)
        {
            SourceSet s = new SourceSet();
            s.Wmi = wmi != null ? wmi : new FakeWmi();
            s.Registry = registry != null ? registry : new FakeRegistry();
            s.EventLog = events != null ? events : new FakeEventLog();
            s.Processes = processes != null ? processes : new FakeProcessRunner();
            s.Sensors = null;
            return s;
        }
    }
}
