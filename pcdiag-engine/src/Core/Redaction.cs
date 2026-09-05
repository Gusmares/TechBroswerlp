using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Text.RegularExpressions;

namespace PcDiag.Core
{
    // Aplica uma UNICA mascara, em memoria, na arvore de objetos inteira -
    // reusando o mesmo atributo [Sensitive] que o JsonWriter ja consulta.
    // Chamada uma vez em Program.cs quando --privacy-safe esta ativo, antes
    // de qualquer formato de saida ser gerado: dai em diante, HTML e JSON
    // partem exatamente dos mesmos dados ja mascarados, e nao podem
    // divergir entre si.
    //
    // O nome do usuario Windows pode reaparecer em texto livre fora de
    // qualquer campo marcado [Sensitive] - caminho de instalacao
    // (C:\Users\<nome>\AppData\...), linha de comando de item de
    // inicializacao, ou ate no nome de algum software instalado. Marcar
    // campo por campo nunca fecha essa lacuna por completo - a mesma
    // informacao pode aparecer em qualquer string livre no futuro. Por
    // isso, alem da mascara por atributo, toda string do relatorio passa
    // por uma segunda varredura que apaga o nome de usuario literal
    // (comparacao sem distincao de maiusculas) e qualquer caminho no padrao
    // \Users\<alguem>\, inclusive de OUTRO usuario que nao o que rodou o
    // scan (ex.: elevacao de UAC com conta diferente da que esta logada).
    public static class Redaction
    {
        private const int MaxDepth = 30;

        private static readonly Regex UserProfilePath = new Regex(
            @"([A-Za-z]:\\Users\\|/Users/)([^\\/""<>|]+)",
            RegexOptions.IgnoreCase);

        // userNames: todo nome de usuario conhecido que deve ser apagado de
        // texto livre. Mais de um porque o processo elevado (Environment.
        // UserName) e a sessao interativa (inv.Machine.LoggedUser, lido via
        // WMI) podem ser CONTAS DIFERENTES quando o UAC e atendido com um
        // usuario diferente do que esta logado.
        public static void Apply(object root, params string[] userNames)
        {
            Regex userNameWord = null;
            List<string> distinct = new List<string>();
            if (userNames != null)
            {
                foreach (string n in userNames)
                {
                    if (!string.IsNullOrEmpty(n) && !distinct.Contains(n)) distinct.Add(n);
                }
            }
            if (distinct.Count > 0)
            {
                string[] escaped = new string[distinct.Count];
                for (int i = 0; i < distinct.Count; i++) escaped[i] = Regex.Escape(distinct[i]);
                userNameWord = new Regex("(?<![A-Za-z0-9])(" + string.Join("|", escaped) + ")(?![A-Za-z0-9])",
                    RegexOptions.IgnoreCase);
            }
            Visit(root, 0, userNameWord);
        }

        private static void Visit(object value, int depth, Regex userNameWord)
        {
            if (value == null || depth > MaxDepth) return;
            if (value is string) return;

            IDictionary dict = value as IDictionary;
            if (dict != null)
            {
                foreach (object v in dict.Values) Visit(v, depth + 1, userNameWord);
                return;
            }

            IEnumerable seq = value as IEnumerable;
            if (seq != null)
            {
                foreach (object item in seq) Visit(item, depth + 1, userNameWord);
                return;
            }

            Type t = value.GetType();
            // So percorre tipos do proprio modelo - evita reflexao inutil
            // (e potencialmente arriscada) sobre tipos do BCL/enums/structs.
            if (t.Namespace == null || t.Namespace.IndexOf("PcDiag", StringComparison.Ordinal) != 0) return;
            if (t.IsEnum) return;

            foreach (PropertyInfo p in t.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                if (!p.CanRead || p.GetIndexParameters().Length > 0) continue;

                object pv;
                try { pv = p.GetValue(value, null); }
                catch { continue; }
                if (pv == null) continue;

                bool sensitive = p.GetCustomAttributes(typeof(SensitiveAttribute), true).Length > 0;
                if (sensitive)
                {
                    if (p.PropertyType == typeof(string) && p.CanWrite)
                    {
                        p.SetValue(value, JsonWriter.Mask, null);
                        continue;
                    }

                    IList sensitiveList = pv as IList;
                    if (sensitiveList != null)
                    {
                        for (int i = 0; i < sensitiveList.Count; i++)
                        {
                            if (sensitiveList[i] is string) sensitiveList[i] = JsonWriter.Mask;
                        }
                        continue;
                    }
                }
                else if (p.PropertyType == typeof(string) && p.CanWrite)
                {
                    string original = (string)pv;
                    string scrubbed = ScrubFreeText(original, userNameWord);
                    if (!string.Equals(scrubbed, original, StringComparison.Ordinal))
                        p.SetValue(value, scrubbed, null);
                    continue;
                }

                Visit(pv, depth + 1, userNameWord);
            }
        }

        private static string ScrubFreeText(string s, Regex userNameWord)
        {
            if (string.IsNullOrEmpty(s)) return s;

            string result = s;
            if (result.IndexOf(@"\Users\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                result.IndexOf("/Users/", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                result = UserProfilePath.Replace(result, "$1" + JsonWriter.Mask);
            }

            if (userNameWord != null)
                result = userNameWord.Replace(result, JsonWriter.Mask);

            return result;
        }
    }
}
