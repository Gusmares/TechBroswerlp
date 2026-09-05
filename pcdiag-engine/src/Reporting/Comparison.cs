using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using PcDiag.Analysis;
using PcDiag.Core;
using PcDiag.Model;

namespace PcDiag.Reporting
{
    public sealed class ChangeEntry
    {
        public string Key { get; set; }
        public string Label { get; set; }
        public string Before { get; set; }
        public string After { get; set; }
        public string Kind { get; set; } // Added | Removed | Changed
    }

    public sealed class ComparisonResult
    {
        public ComparisonResult()
        {
            Changes = new List<ChangeEntry>();
        }

        public bool Available { get; set; }
        public string Note { get; set; }
        public string BaselineScanId { get; set; }
        public DateTime? BaselineDate { get; set; }
        public int? ScoreBefore { get; set; }
        public int? ScoreAfter { get; set; }
        public List<ChangeEntry> Changes { get; set; }
    }

    // Comparacao entre execucoes (itens 61/62).
    //
    // Em vez de comparar a arvore JSON inteira (que geraria ruido a cada
    // milissegundo de uptime diferente), extrai-se uma IMPRESSAO DIGITAL com
    // os fatos que realmente importam para assistencia tecnica: hardware
    // trocado, driver atualizado, disco novo, erro que apareceu ou sumiu.
    public static class Comparison
    {
        public static Dictionary<string, string> Fingerprint(DiagnosticReport report)
        {
            Dictionary<string, string> f = new Dictionary<string, string>(StringComparer.Ordinal);
            if (report == null || report.Inventory == null) return f;

            Inventory inv = report.Inventory;

            // Identifica a MAQUINA (nao so o modelo dela), para que a
            // comparacao nao trate hardware parecido de equipamentos
            // diferentes do mesmo modelo como se fosse o mesmo computador.
            // O hash (nao o serial cru - mesma logica de DiskFingerprintId,
            // serial e dado [Sensitive] e nao pode virar valor de
            // fingerprint em texto claro) e comparado em Compare() antes de
            // aceitar a baseline.
            string identity = MachineIdentity(inv.Machine);
            if (identity != null) Put(f, "machine.identity", identity);

            Put(f, "os.caption", inv.Os.Caption);
            Put(f, "os.build", Str(inv.Os.BuildNumber));
            Put(f, "os.displayVersion", inv.Os.DisplayVersion);
            Put(f, "machine.model", inv.Machine.Model);
            Put(f, "machine.board", inv.Machine.BoardProduct);
            Put(f, "firmware.version", inv.Firmware.Version);
            Put(f, "firmware.type", inv.Firmware.FirmwareType);

            Put(f, "cpu.name", inv.Cpu.Name);
            Put(f, "cpu.cores", Str(inv.Cpu.PhysicalCores));
            Put(f, "cpu.threads", Str(inv.Cpu.LogicalProcessors));

            Put(f, "memory.installedBytes", Str(inv.Memory.InstalledBytes));
            Put(f, "memory.moduleCount", Str(inv.Memory.SlotsUsed));
            int mi = 0;
            foreach (MemoryModule m in inv.Memory.Modules)
            {
                string key = "memory.module." + (m.Slot == null ? "idx" + mi : m.Slot);
                Put(f, key, T.Bytes(m.CapacityBytes) + " @ " + Str(m.ConfiguredSpeedMhz) + "MHz " + m.MemoryType);
                mi++;
            }

            foreach (GpuInfo g in inv.Gpus)
            {
                string key = "gpu." + (g.PciDeviceId == null ? T.Name(g.Name, "?") : g.PciVendorId + ":" + g.PciDeviceId);
                Put(f, key + ".name", g.Name);
                Put(f, key + ".driver", g.DriverVersion);
            }

            foreach (DiskInfo d in inv.Disks)
            {
                string key = "disk." + DiskFingerprintId(d);
                Put(f, key + ".model", d.Model);
                Put(f, key + ".sizeBytes", Str(d.SizeBytes));
                Put(f, key + ".health", d.HealthStatus);
                Put(f, key + ".wearPercent", Str(d.WearPercent));
                Put(f, key + ".powerOnHours", Str(d.PowerOnHours));
                Put(f, key + ".firmware", d.FirmwareVersion);
            }

            foreach (VolumeInfo v in inv.Volumes)
            {
                if (v.DriveLetter == null) continue;
                Put(f, "volume." + v.DriveLetter + ".freePercent", v.FreePercent.HasValue
                    ? v.FreePercent.Value.ToString("F0", CultureInfo.InvariantCulture) : null);
            }

            if (inv.Battery != null)
                Put(f, "battery.healthPercent", inv.Battery.HealthPercent.HasValue
                    ? inv.Battery.HealthPercent.Value.ToString("F0", CultureInfo.InvariantCulture) : null);

            Put(f, "software.count", inv.Software.Count.ToString(CultureInfo.InvariantCulture));

            // Estado de cada teste: e assim que "erro que sumiu" e "erro novo"
            // aparecem na comparacao.
            foreach (TestResult t in report.Tests)
                Put(f, "test." + t.Id, t.Status.ToString());

            return f;
        }

        private static void Put(Dictionary<string, string> f, string key, string value)
        {
            if (string.IsNullOrEmpty(value)) return;
            f[key] = value;
        }

        private static string Str(object v)
        {
            if (v == null) return null;
            return Convert.ToString(v, CultureInfo.InvariantCulture);
        }

        // A chave usa um hash truncado do numero de serie do disco, nunca o
        // serial cru: serial e dado [Sensitive] (Inventory.cs classifica
        // DiskInfo.SerialNumber como SensitiveSystem) e nao deveria aparecer
        // em texto claro em uma chave de dicionario, em nenhum modo. O hash
        // preserva a unica propriedade que a chave precisa ter (o MESMO
        // disco produz a MESMA chave em dois scans, mesmo se a ordem dos
        // discos mudar) sem carregar o dado sensivel.
        // Identificador estavel da MAQUINA (nao do modelo dela) - serial do
        // chassi + serial da placa-mae. Nulo quando nenhum dos dois foi
        // obtido (ja filtrados de placeholder tipo "To Be Filled By O.E.M."
        // rio acima, em SystemCollector) - nesse caso Compare() nao tem como
        // verificar identidade e segue sem essa checagem, em vez de recusar
        // toda comparacao por falta de dado.
        private static string MachineIdentity(MachineInfo m)
        {
            if (m == null) return null;
            string chassis = m.SerialNumber;
            string board = m.BoardSerialNumber;
            if (string.IsNullOrEmpty(chassis) && string.IsNullOrEmpty(board)) return null;
            return ShortHash((chassis ?? "") + "|" + (board ?? ""));
        }

        private static string DiskFingerprintId(DiskInfo d)
        {
            if (!string.IsNullOrEmpty(d.SerialNumber)) return "sn" + ShortHash(d.SerialNumber);
            if (!string.IsNullOrEmpty(d.Model)) return T.Name(d.Model, "?");
            return "idx" + Str(d.Index);
        }

        private static string ShortHash(string value)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(value));
                StringBuilder sb = new StringBuilder(12);
                for (int i = 0; i < 6; i++) sb.Append(hash[i].ToString("x2", CultureInfo.InvariantCulture));
                return sb.ToString();
            }
        }

        public static ComparisonResult Compare(DiagnosticReport current, string baselineJsonPath, Logger log)
        {
            ComparisonResult result = new ComparisonResult();

            if (string.IsNullOrEmpty(baselineJsonPath))
            {
                result.Available = false;
                result.Note = "Nenhuma linha de base informada (use --baseline <report.json> de um scan anterior).";
                return result;
            }

            if (!File.Exists(baselineJsonPath))
            {
                result.Available = false;
                result.Note = "Arquivo de linha de base nao encontrado: " + baselineJsonPath;
                return result;
            }

            object parsed;
            try
            {
                parsed = JsonParser.Parse(File.ReadAllText(baselineJsonPath));
            }
            catch (Exception ex)
            {
                result.Available = false;
                result.Note = "Linha de base ilegivel (" + ex.Message + ").";
                if (log != null) log.Error("Comparison", result.Note);
                return result;
            }

            Dictionary<string, string> before = FingerprintFromJson(parsed);
            if (before.Count == 0)
            {
                result.Available = false;
                result.Note = "A linha de base nao contem uma impressao digital comparavel (gerada por versao anterior da ferramenta?).";
                return result;
            }

            // Recusa a comparacao quando os dois lados TEM identidade de
            // maquina (nem sempre tem - serial ausente/placeholder e comum)
            // e ela DIVERGE, para que uma baseline de outro equipamento do
            // mesmo modelo (parque corporativo, por exemplo) nao seja
            // comparada como se fosse a mesma maquina.
            string identityBefore;
            string identityAfter = MachineIdentity(current.Inventory != null ? current.Inventory.Machine : null);
            if (before.TryGetValue("machine.identity", out identityBefore) &&
                identityAfter != null && !string.Equals(identityBefore, identityAfter, StringComparison.Ordinal))
            {
                result.Available = false;
                result.Note = "A linha de base informada e de OUTRO equipamento (identificador de maquina nao bate) - comparacao recusada para nao apresentar diferencas de hardware entre computadores diferentes como se fossem evolucao do mesmo atendimento.";
                if (log != null) log.Warn("Comparison", result.Note);
                return result;
            }

            // Alem da identidade da MAQUINA, a comparacao tambem precisa
            // validar se as duas execucoes sao COMPARAVEIS entre si: uma
            // baseline gerada com --stress (que adiciona testes penalizaveis
            // que o scan normal nunca roda) ou com um schemaVersion antigo
            // (estrutura do fingerprint pode ter mudado de significado)
            // produziria um "Score: X -> Y" que parece evolucao do mesmo
            // atendimento mas na verdade compara coisas diferentes.
            // schemaVersion e mode divergentes recusam a comparacao;
            // toolVersion divergente so vira nota informativa, porque
            // atualizar a ferramenta entre atendimentos e rotina e nao muda
            // o que foi medido.
            object baselineSchemaVersion = JsonParser.Path(parsed, "metadata.schemaVersion");
            int? schemaBefore = baselineSchemaVersion is double ? (int?)(double)baselineSchemaVersion : null;
            if (schemaBefore.HasValue && current.Metadata != null && schemaBefore.Value != current.Metadata.SchemaVersion)
            {
                result.Available = false;
                result.Note = "A linha de base foi gerada com outra versao de schema (schemaVersion " + schemaBefore.Value +
                    " contra " + current.Metadata.SchemaVersion + " deste scan) - comparacao recusada porque a estrutura dos dados pode ter mudado de significado.";
                if (log != null) log.Warn("Comparison", result.Note);
                return result;
            }

            string modeBefore = Str(JsonParser.Path(parsed, "metadata.mode"));
            string modeAfter = current.Metadata != null ? current.Metadata.Mode : null;
            if (!string.IsNullOrEmpty(modeBefore) && !string.IsNullOrEmpty(modeAfter) &&
                !string.Equals(modeBefore, modeAfter, StringComparison.Ordinal))
            {
                result.Available = false;
                result.Note = "A linha de base foi gerada em outro modo de execucao (" + modeBefore + " contra " + modeAfter +
                    " deste scan) - comparacao recusada porque testes adicionais (ex.: --stress) mudam o que e penalizado no score, e o delta cruzaria execucoes nao comparaveis.";
                if (log != null) log.Warn("Comparison", result.Note);
                return result;
            }

            // metadata.mode (ScanMode.Diagnostic/Repair) nao captura sozinho
            // se o teste de carga rodou: --stress adiciona testes
            // penalizaveis (STR-*) sem mudar o "modo" da enum. StressExecuted
            // e o campo que de fato diz se aquela execucao rodou o modulo de
            // carga, e e o que esta checagem usa para recusar comparar uma
            // baseline --stress contra um scan normal.
            object stressBefore = JsonParser.Path(parsed, "metadata.stressExecuted");
            bool? stressBeforeBool = stressBefore is bool ? (bool?)stressBefore : null;
            bool stressAfter = current.Metadata != null && current.Metadata.StressExecuted;
            if (stressBeforeBool.HasValue && stressBeforeBool.Value != stressAfter)
            {
                result.Available = false;
                result.Note = "A linha de base e este scan divergem quanto ao teste de carga (--stress) - comparacao recusada porque testes adicionais penalizaveis mudam o que e descontado no score entre as duas execucoes.";
                if (log != null) log.Warn("Comparison", result.Note);
                return result;
            }

            result.Available = true;
            result.BaselineScanId = Str(JsonParser.Path(parsed, "metadata.scanId"));

            string toolVersionBefore = Str(JsonParser.Path(parsed, "metadata.toolVersion"));
            string toolVersionAfter = current.Metadata != null ? current.Metadata.ToolVersion : null;
            if (!string.IsNullOrEmpty(toolVersionBefore) && !string.IsNullOrEmpty(toolVersionAfter) &&
                !string.Equals(toolVersionBefore, toolVersionAfter, StringComparison.Ordinal))
            {
                result.Note = "Linha de base gerada com outra versao da ferramenta (" + toolVersionBefore + " -> " + toolVersionAfter + ").";
            }

            object scoreBefore = JsonParser.Path(parsed, "summary.healthScore");
            if (scoreBefore is double) result.ScoreBefore = (int)(double)scoreBefore;
            result.ScoreAfter = current.Summary.HealthScore;

            object startedAt = JsonParser.Path(parsed, "metadata.startedAt");
            DateTime parsedDate;
            if (startedAt is string && DateTime.TryParse((string)startedAt, CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind, out parsedDate)) result.BaselineDate = parsedDate;

            Dictionary<string, string> after = Fingerprint(current);
            result.Changes = Diff(before, after);
            return result;
        }

        // A impressao digital e gravada no proprio report.json, entao a
        // comparacao nao depende de reconstruir o inventario do arquivo antigo.
        public static Dictionary<string, string> FingerprintFromJson(object root)
        {
            Dictionary<string, string> f = new Dictionary<string, string>(StringComparer.Ordinal);
            Dictionary<string, object> fp = JsonParser.Path(root, "fingerprint") as Dictionary<string, object>;
            if (fp == null) return f;

            foreach (KeyValuePair<string, object> kv in fp)
            {
                if (kv.Value == null) continue;
                f[kv.Key] = Convert.ToString(kv.Value, CultureInfo.InvariantCulture);
            }
            return f;
        }

        public static List<ChangeEntry> Diff(Dictionary<string, string> before, Dictionary<string, string> after)
        {
            List<ChangeEntry> changes = new List<ChangeEntry>();

            foreach (KeyValuePair<string, string> kv in after)
            {
                string old;
                if (!before.TryGetValue(kv.Key, out old))
                {
                    changes.Add(Entry(kv.Key, null, kv.Value, "Added"));
                }
                else if (!string.Equals(old, kv.Value, StringComparison.Ordinal))
                {
                    changes.Add(Entry(kv.Key, old, kv.Value, "Changed"));
                }
            }

            foreach (KeyValuePair<string, string> kv in before)
            {
                if (after.ContainsKey(kv.Key)) continue;

                // Uma chave some de `after` por dois motivos bem diferentes
                // - (a) a ENTIDADE (o disco, a GPU) foi removida de
                // verdade, ou (b) so este ATRIBUTO nao
                // pode ser medido desta vez (SMART sem elevacao, WMI que
                // falhou, timeout de modulo), mas o disco/GPU continua
                // presente. disk.<id>.* e gpu.<id>.* tem varios atributos
                // por entidade (model, sizeBytes, health, wearPercent...) -
                // se OUTRO atributo da MESMA entidade ainda esta em `after`,
                // a entidade nao sumiu; so paramos de saber um dado sobre
                // ela. Suprime o "Removed" nesse caso em vez de afirmar
                // "Disco removido" sobre um disco que continua no laudo.
                if (EntityStillPresent(kv.Key, after)) continue;

                changes.Add(Entry(kv.Key, kv.Value, null, "Removed"));
            }

            changes.Sort(delegate(ChangeEntry a, ChangeEntry b) { return string.CompareOrdinal(a.Key, b.Key); });
            return changes;
        }

        private static bool EntityStillPresent(string key, Dictionary<string, string> after)
        {
            // So disk.<id>.* e gpu.<id>.* tem essa estrutura de varios
            // atributos por entidade (ver Fingerprint acima). Aplicar a
            // mesma logica a "test.<id>" ou "os.<campo>" suprimiria
            // incorretamente - QUALQUER outra chave "test.*" bateria com um
            // prefixo generico demais, escondendo um teste que realmente
            // sumiu.
            string entityPrefix;
            if (key.StartsWith("disk.", StringComparison.Ordinal)) entityPrefix = ExtractEntityPrefix(key, "disk.".Length);
            else if (key.StartsWith("gpu.", StringComparison.Ordinal)) entityPrefix = ExtractEntityPrefix(key, "gpu.".Length);
            else return false;

            if (entityPrefix == null) return false;

            foreach (string otherKey in after.Keys)
            {
                if (otherKey.StartsWith(entityPrefix, StringComparison.Ordinal)) return true;
            }
            return false;
        }

        // "disk.<id>.model" -> "disk.<id>." (o proximo ponto depois do
        // prefixo do tipo marca o fim do identificador da entidade).
        private static string ExtractEntityPrefix(string key, int afterTypePrefix)
        {
            int nextDot = key.IndexOf('.', afterTypePrefix);
            if (nextDot < 0) return null;
            return key.Substring(0, nextDot + 1);
        }

        private static ChangeEntry Entry(string key, string before, string after, string kind)
        {
            ChangeEntry e = new ChangeEntry();
            e.Key = key;
            e.Before = before;
            e.After = after;
            e.Kind = kind;
            e.Label = Humanize(key, kind);
            return e;
        }

        public static string Humanize(string key, string kind)
        {
            if (key.StartsWith("test.", StringComparison.Ordinal))
                return "Resultado do teste " + key.Substring(5);
            if (key.StartsWith("disk.", StringComparison.Ordinal))
                return kind == "Added" ? "Disco adicionado" : (kind == "Removed" ? "Disco removido" : "Disco alterado");
            if (key.StartsWith("memory.module", StringComparison.Ordinal))
                return kind == "Added" ? "Modulo de memoria adicionado" : (kind == "Removed" ? "Modulo de memoria removido" : "Modulo de memoria alterado");
            if (key.EndsWith(".driver", StringComparison.Ordinal))
                return "Driver alterado";
            if (key.StartsWith("gpu.", StringComparison.Ordinal))
                return "Placa de video";
            if (key.StartsWith("os.", StringComparison.Ordinal))
                return "Sistema operacional";
            if (key.StartsWith("firmware.", StringComparison.Ordinal))
                return "Firmware";
            if (key.StartsWith("volume.", StringComparison.Ordinal))
                return "Espaco livre em volume";
            if (key.StartsWith("battery.", StringComparison.Ordinal))
                return "Saude da bateria";
            if (key.StartsWith("software.", StringComparison.Ordinal))
                return "Inventario de software";
            return key;
        }
    }
}
