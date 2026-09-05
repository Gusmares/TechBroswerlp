using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text;

namespace PcDiag.Core
{
    // Serializador JSON proprio.
    //
    // Por que nao usar JavaScriptSerializer/DataContractJsonSerializer: o
    // relatorio precisa de cultura invariante (senao "0,5" vira separador
    // decimal errado em maquina pt-BR e quebra o parse do outro lado), ordem
    // deterministica de campos (para diff entre scans) e mascaramento por
    // atributo no modo privacy-safe. Escrever os ~150 linhas da e mais barato
    // do que contornar as tres coisas.
    public sealed class JsonWriter
    {
        private readonly StringBuilder _sb = new StringBuilder();
        private readonly bool _privacySafe;
        private readonly bool _indent;
        private readonly Logger _log;

        public JsonWriter(bool privacySafe, bool indent) : this(privacySafe, indent, null)
        {
        }

        // Construtor adicional que aceita um Logger opcional, para
        // registrar truncagem por profundidade maxima e falha de getter em
        // vez de fazer isso desaparecer em silencio. Sobrecarga aditiva -
        // nao muda o construtor/Serialize existentes, que os demais
        // chamadores (JsonReport.cs, Entry.cs) continuam usando sem Logger.
        public JsonWriter(bool privacySafe, bool indent, Logger log)
        {
            _privacySafe = privacySafe;
            _indent = indent;
            _log = log;
        }

        public static string Serialize(object value, bool privacySafe, bool indent)
        {
            return Serialize(value, privacySafe, indent, null);
        }

        public static string Serialize(object value, bool privacySafe, bool indent, Logger log)
        {
            JsonWriter w = new JsonWriter(privacySafe, indent, log);
            w.WriteValue(value, 0, DataClass.Public);
            return w._sb.ToString();
        }

        public const string Mask = "[REDACTED]";

        private void WriteValue(object value, int depth, DataClass dataClass)
        {
            // Emitir null em vez de uma string como "[max depth]" preserva o
            // contrato de tipo quando a profundidade maxima e excedida (um
            // array/objeto virar texto confundiria um consumidor que espera
            // array, como "child", com dado real) - o campo so fica
            // "ausente", igual a qualquer outro valor nao obtido no resto do
            // modelo.
            if (depth > 24)
            {
                if (_log != null) _log.Warn("JsonWriter", "Profundidade maxima (24) excedida - valor truncado para null.");
                _sb.Append("null");
                return;
            }

            if (value == null)
            {
                _sb.Append("null");
                return;
            }

            // Para colecoes sensiveis (exceto string, que ja e
            // IEnumerable<char>), emitimos um array com uma mascara por
            // elemento, preservando comprimento e tipo - trocar um campo
            // sensivel do tipo array (ex.: iPv4Addresses) pela string
            // "[REDACTED]" quebraria o contrato de tipo do schema mesmo sem
            // revelar nenhum valor.
            if (_privacySafe && dataClass != DataClass.Public)
            {
                IEnumerable maskSeq = (value is string) ? null : value as IEnumerable;
                if (maskSeq != null && !(value is IDictionary))
                {
                    WriteMaskedArray(maskSeq, depth);
                    return;
                }
                WriteString(Mask);
                return;
            }

            Type t = value.GetType();
            Type under = Nullable.GetUnderlyingType(t);
            if (under != null) t = under;

            if (value is string) { WriteString((string)value); return; }
            if (value is bool) { _sb.Append(((bool)value) ? "true" : "false"); return; }
            if (value is DateTime) { WriteString(((DateTime)value).ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)); return; }
            if (value is TimeSpan) { WriteString(((TimeSpan)value).ToString()); return; }
            if (t.IsEnum) { WriteString(value.ToString()); return; }

            if (value is float || value is double)
            {
                double d = Convert.ToDouble(value, CultureInfo.InvariantCulture);
                if (double.IsNaN(d) || double.IsInfinity(d)) { _sb.Append("null"); return; }
                _sb.Append(d.ToString("R", CultureInfo.InvariantCulture));
                return;
            }
            if (value is decimal) { _sb.Append(((decimal)value).ToString(CultureInfo.InvariantCulture)); return; }
            if (value is byte || value is sbyte || value is short || value is ushort ||
                value is int || value is uint || value is long || value is ulong)
            {
                _sb.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
                return;
            }

            IDictionary dict = value as IDictionary;
            if (dict != null) { WriteDictionary(dict, depth, dataClass); return; }

            IEnumerable seq = value as IEnumerable;
            if (seq != null) { WriteArray(seq, depth, dataClass); return; }

            WriteObject(value, depth);
        }

        // A CHAVE e o VALOR propagam a mesma dataClass que WriteObject leu
        // do atributo do membro dono do dicionario (ex.: um futuro
        // Dictionary<,> marcado [Sensitive] fica mascarado aqui tambem, nao
        // so no resto do relatorio).
        private void WriteDictionary(IDictionary dict, int depth, DataClass dataClass)
        {
            bool maskEntries = _privacySafe && dataClass != DataClass.Public;
            _sb.Append('{');
            bool first = true;
            foreach (DictionaryEntry e in dict)
            {
                if (!first) _sb.Append(',');
                first = false;
                NewLine(depth + 1);
                string key = Convert.ToString(e.Key, CultureInfo.InvariantCulture);
                WriteString(maskEntries ? Mask : key);
                _sb.Append(':');
                if (_indent) _sb.Append(' ');
                WriteValue(e.Value, depth + 1, dataClass);
            }
            if (!first) NewLine(depth);
            _sb.Append('}');
        }

        private void WriteMaskedArray(IEnumerable seq, int depth)
        {
            _sb.Append('[');
            bool first = true;
            foreach (object item in seq)
            {
                if (!first) _sb.Append(',');
                first = false;
                NewLine(depth + 1);
                WriteString(Mask);
            }
            if (!first) NewLine(depth);
            _sb.Append(']');
        }

        private void WriteArray(IEnumerable seq, int depth, DataClass dataClass)
        {
            _sb.Append('[');
            bool first = true;
            foreach (object item in seq)
            {
                if (!first) _sb.Append(',');
                first = false;
                NewLine(depth + 1);
                WriteValue(item, depth + 1, dataClass);
            }
            if (!first) NewLine(depth);
            _sb.Append(']');
        }

        private void WriteObject(object value, int depth)
        {
            _sb.Append('{');
            bool first = true;
            foreach (PropertyInfo p in GetProperties(value.GetType()))
            {
                object v;
                bool getterFailed = false;
                try { v = p.GetValue(value, null); }
                catch (Exception ex)
                {
                    // Um getter que lanca nao pode fazer a chave inteira
                    // desaparecer do JSON sem nenhum registro - ficaria
                    // indistinguivel de um campo que nunca existiu. Emitimos
                    // a chave com null (mesmo contrato de "nao obtido" usado
                    // em todo o resto do modelo) e registramos a falha
                    // quando ha Logger disponivel, em vez de engolir.
                    v = null;
                    getterFailed = true;
                    if (_log != null)
                        _log.Warn("JsonWriter", "Getter de " + value.GetType().Name + "." + p.Name +
                            " lancou " + ex.GetType().Name + ": " + ex.Message);
                }

                if (!first) _sb.Append(',');
                first = false;
                NewLine(depth + 1);
                WriteString(CamelCase(p.Name));
                _sb.Append(':');
                if (_indent) _sb.Append(' ');

                if (getterFailed)
                {
                    _sb.Append("null");
                    continue;
                }

                DataClass cls = DataClass.Public;
                object[] attrs = p.GetCustomAttributes(typeof(SensitiveAttribute), true);
                if (attrs.Length > 0) cls = ((SensitiveAttribute)attrs[0]).Class;

                WriteValue(v, depth + 1, cls);
            }
            if (!first) NewLine(depth);
            _sb.Append('}');
        }

        private void NewLine(int depth)
        {
            if (!_indent) return;
            _sb.Append('\n');
            _sb.Append(' ', depth * 2);
        }

        // Ordem deterministica: MetadataToken segue a ordem de declaracao no
        // arquivo fonte. Sem isso, dois scans da mesma maquina poderiam gerar
        // JSONs com chaves em ordens diferentes e poluir o diff.
        private static readonly Dictionary<Type, PropertyInfo[]> PropCache = new Dictionary<Type, PropertyInfo[]>();

        private static PropertyInfo[] GetProperties(Type t)
        {
            lock (PropCache)
            {
                PropertyInfo[] cached;
                if (PropCache.TryGetValue(t, out cached)) return cached;

                PropertyInfo[] props = t.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                    .Where(p => p.CanRead && p.GetIndexParameters().Length == 0)
                    .OrderBy(p => p.MetadataToken)
                    .ToArray();
                PropCache[t] = props;
                return props;
            }
        }

        // A sequencia inicial de maiusculas de um nome de propriedade e
        // tratada como prefixo: um prefixo de exatamente 2 letras (o caso
        // comum de sigla de 2 letras seguida de palavra minuscula, como
        // "IPv4"/"IDCard") e rebaixado por inteiro; um prefixo mais longo
        // (ex.: "HTTPServer") mantem a ultima maiuscula como inicio da
        // proxima palavra ("httpServer"), preservando o padrao ja usado no
        // resto do relatorio.
        public static string CamelCase(string name)
        {
            if (string.IsNullOrEmpty(name)) return name;
            if (name.Length == 1) return name.ToLowerInvariant();
            if (!char.IsUpper(name[0])) return name;

            int prefixLen = 1;
            while (prefixLen < name.Length && char.IsUpper(name[prefixLen])) prefixLen++;

            if (prefixLen == 1)
                return char.ToLowerInvariant(name[0]) + name.Substring(1);

            if (prefixLen >= name.Length || prefixLen == 2)
            {
                // Prefixo cobre o nome inteiro, ou tem exatamente 2 letras:
                // rebaixa tudo (ex.: "IP" de "IPv4Addresses" -> "ip").
                return name.Substring(0, prefixLen).ToLowerInvariant() + name.Substring(prefixLen);
            }

            // Prefixo de 3+ letras seguido de palavra em minusculas: mantem
            // a ultima maiuscula do prefixo como inicio da proxima palavra.
            return name.Substring(0, prefixLen - 1).ToLowerInvariant() + name.Substring(prefixLen - 1);
        }

        private void WriteString(string s)
        {
            _sb.Append('"');
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                switch (c)
                {
                    case '"': _sb.Append("\\\""); break;
                    case '\\': _sb.Append("\\\\"); break;
                    case '\b': _sb.Append("\\b"); break;
                    case '\f': _sb.Append("\\f"); break;
                    case '\n': _sb.Append("\\n"); break;
                    case '\r': _sb.Append("\\r"); break;
                    case '\t': _sb.Append("\\t"); break;
                    // Caractere nulo (codigo zero): nunca carrega informacao de
                    // verdade, e sempre sobra de um terminador embutido num
                    // valor lido cru do sistema (exemplo real: um REG_SZ de
                    // instalador de terceiro com um terminador extra no fim).
                    // Escapa-lo como "\u0000" seria JSON valido, mas o Postgres
                    // se recusa a guardar esse caractere em texto/JSON (erro
                    // 22P05 - "unsupported Unicode escape sequence"). Como a
                    // gravacao do diagnostico no dashboard e uma unica
                    // transacao, um unico campo assim derruba o diagnostico
                    // inteiro sem aviso nenhum. Descartamos aqui, no unico
                    // lugar por onde toda string do relatorio passa, em vez de
                    // deixar isso vazar ate o servidor.
                    case '\0':
                        break;
                    default:
                        // Escapa os demais controles e tambem U+2028/U+2029,
                        // que quebram parsers JS quando o JSON e embutido em
                        // <script>.
                        if (c < 0x20 || c == '\u2028' || c == '\u2029')
                            _sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else
                            _sb.Append(c);
                        break;
                }
            }
            _sb.Append('"');
        }
    }

    // Parser minimo, usado para ler o report.json de um scan anterior e
    // produzir a comparacao entre execucoes (itens 61/62).
    public static class JsonParser
    {
        // Sem limite de profundidade, ParseObject/ParseArray recursam
        // indefinidamente sobre entrada hostil (JSON aninhado de forma
        // maliciosa). Isso pode terminar o processo com
        // StackOverflowException - excecao que o .NET Framework NAO deixa
        // capturar por try/catch desde a versao 2.0, entao um try/catch em
        // volta da chamada a este parser (por exemplo em Comparison.Compare,
        // que le --baseline) seria inutil contra isso. O JsonWriter ja tem
        // um limite equivalente (Json.cs, "depth > 24") do lado da escrita;
        // este e o limite do lado da leitura.
        private const int MaxParseDepth = 64;

        public static object Parse(string text)
        {
            int pos = 0;
            object v = ParseValue(text, ref pos, 0);
            SkipWs(text, ref pos);
            if (pos != text.Length) throw new FormatException("Conteudo extra apos o fim do JSON (posicao " + pos + ").");
            return v;
        }

        private static void SkipWs(string s, ref int i)
        {
            while (i < s.Length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++;
        }

        private static object ParseValue(string s, ref int i, int depth)
        {
            if (depth > MaxParseDepth)
                throw new FormatException("JSON aninhado alem do limite de " + MaxParseDepth + " niveis (posicao " + i + ") - rejeitado por seguranca.");

            SkipWs(s, ref i);
            if (i >= s.Length) throw new FormatException("JSON truncado.");
            char c = s[i];
            if (c == '{') return ParseObject(s, ref i, depth);
            if (c == '[') return ParseArray(s, ref i, depth);
            if (c == '"') return ParseString(s, ref i);
            if (c == 't') { Expect(s, ref i, "true"); return true; }
            if (c == 'f') { Expect(s, ref i, "false"); return false; }
            if (c == 'n') { Expect(s, ref i, "null"); return null; }
            return ParseNumber(s, ref i);
        }

        private static void Expect(string s, ref int i, string literal)
        {
            if (i + literal.Length > s.Length || string.CompareOrdinal(s, i, literal, 0, literal.Length) != 0)
                throw new FormatException("Esperado '" + literal + "' na posicao " + i + ".");
            i += literal.Length;
        }

        private static Dictionary<string, object> ParseObject(string s, ref int i, int depth)
        {
            Dictionary<string, object> obj = new Dictionary<string, object>(StringComparer.Ordinal);
            i++; // '{'
            SkipWs(s, ref i);
            if (i < s.Length && s[i] == '}') { i++; return obj; }
            while (true)
            {
                SkipWs(s, ref i);
                string key = ParseString(s, ref i);
                SkipWs(s, ref i);
                if (i >= s.Length || s[i] != ':') throw new FormatException("Esperado ':' na posicao " + i + ".");
                i++;
                obj[key] = ParseValue(s, ref i, depth + 1);
                SkipWs(s, ref i);
                if (i >= s.Length) throw new FormatException("Objeto JSON nao fechado.");
                if (s[i] == ',') { i++; continue; }
                if (s[i] == '}') { i++; return obj; }
                throw new FormatException("Esperado ',' ou '}' na posicao " + i + ".");
            }
        }

        private static List<object> ParseArray(string s, ref int i, int depth)
        {
            List<object> list = new List<object>();
            i++; // '['
            SkipWs(s, ref i);
            if (i < s.Length && s[i] == ']') { i++; return list; }
            while (true)
            {
                list.Add(ParseValue(s, ref i, depth + 1));
                SkipWs(s, ref i);
                if (i >= s.Length) throw new FormatException("Array JSON nao fechado.");
                if (s[i] == ',') { i++; continue; }
                if (s[i] == ']') { i++; return list; }
                throw new FormatException("Esperado ',' ou ']' na posicao " + i + ".");
            }
        }

        private static string ParseString(string s, ref int i)
        {
            if (i >= s.Length || s[i] != '"') throw new FormatException("Esperado string na posicao " + i + ".");
            i++;
            StringBuilder sb = new StringBuilder();
            while (i < s.Length)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                if (i >= s.Length) break;
                char e = s[i++];
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        // Convert.ToInt32(str, 16) aceita e ignora um
                        // prefixo "0x"/"0X" dentro dos 4 caracteres, entao
                        // validamos os 4 caracteres como hex explicitamente
                        // antes de converter, sem essa tolerancia - um
                        // escape como "\u0x41" (o 'x' nao e digito hex de
                        // verdade) deve ser rejeitado, nao aceito como se
                        // fosse 'A'.
                        if (i + 4 > s.Length) throw new FormatException("Escape \\u truncado.");
                        int code = 0;
                        for (int k = 0; k < 4; k++)
                        {
                            char hc = s[i + k];
                            int digit;
                            if (hc >= '0' && hc <= '9') digit = hc - '0';
                            else if (hc >= 'a' && hc <= 'f') digit = hc - 'a' + 10;
                            else if (hc >= 'A' && hc <= 'F') digit = hc - 'A' + 10;
                            else throw new FormatException("Escape \\u com digito hexadecimal invalido na posicao " + (i + k) + ".");
                            code = (code << 4) | digit;
                        }
                        sb.Append((char)code);
                        i += 4;
                        break;
                    default: throw new FormatException("Escape invalido '\\" + e + "'.");
                }
            }
            throw new FormatException("String JSON nao fechada.");
        }

        // (1) JSON nao permite '+' inicial ("+5" e invalido pela gramatica -
        // RFC 8259), entao a extracao bruta acima (que aceita '+' e '-'
        // livremente) precisa ser validada contra a gramatica antes de
        // aceitar o numero. (2) Um numero sintaticamente valido porem fora
        // da faixa do double (ex.: 1e999) faz double.TryParse devolver
        // false; em vez de invalidar o JSON inteiro, saturamos para
        // +/-Infinity como o proprio double.Parse faria fora do
        // NumberStyles.Float combinado com overflow - tratado explicitamente
        // abaixo.
        private static object ParseNumber(string s, ref int i)
        {
            int start = i;
            if (i < s.Length && s[i] == '-') i++;
            while (i < s.Length && (char.IsDigit(s[i]) || s[i] == '.' || s[i] == 'e' || s[i] == 'E' || s[i] == '-' || s[i] == '+')) i++;
            string raw = s.Substring(start, i - start);

            double d;
            if (double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out d))
                return d;

            // TryParse falhou: pode ser overflow (sintaxe de numero valida,
            // magnitude fora da faixa do double) ou sintaxe realmente
            // invalida. Distinguimos validando a gramatica manualmente antes
            // de decidir entre +/-Infinity e erro fatal.
            if (IsSyntacticallyValidNumber(raw))
                return (raw.Length > 0 && raw[0] == '-') ? double.NegativeInfinity : double.PositiveInfinity;

            throw new FormatException("Numero invalido '" + raw + "' na posicao " + start + ".");
        }

        private static bool IsSyntacticallyValidNumber(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return false;
            int i = 0;
            int n = raw.Length;
            if (raw[i] == '-') i++;
            if (i >= n || !char.IsDigit(raw[i])) return false;
            if (raw[i] == '0' && i + 1 < n && char.IsDigit(raw[i + 1])) return false; // sem zero a esquerda
            while (i < n && char.IsDigit(raw[i])) i++;
            if (i < n && raw[i] == '.')
            {
                i++;
                if (i >= n || !char.IsDigit(raw[i])) return false;
                while (i < n && char.IsDigit(raw[i])) i++;
            }
            if (i < n && (raw[i] == 'e' || raw[i] == 'E'))
            {
                i++;
                if (i < n && (raw[i] == '+' || raw[i] == '-')) i++;
                if (i >= n || !char.IsDigit(raw[i])) return false;
                while (i < n && char.IsDigit(raw[i])) i++;
            }
            return i == n;
        }

        // Navegacao tolerante: caminho "device.hostname" devolve null se
        // qualquer nivel faltar, em vez de lancar.
        public static object Path(object root, string dottedPath)
        {
            object cur = root;
            foreach (string part in dottedPath.Split('.'))
            {
                Dictionary<string, object> obj = cur as Dictionary<string, object>;
                if (obj == null) return null;
                if (!obj.TryGetValue(part, out cur)) return null;
            }
            return cur;
        }
    }
}
