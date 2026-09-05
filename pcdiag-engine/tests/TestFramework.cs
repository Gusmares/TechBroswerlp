using System;
using System.Collections.Generic;
using System.Globalization;

namespace PcDiag.Testing
{
    // Runner de testes proprio.
    //
    // Sem NuGet, sem xUnit, sem SDK: compila com o mesmo csc.exe in-box do
    // resto do projeto. Isso mantem a promessa de que qualquer maquina Windows
    // consegue compilar E validar a ferramenta sem instalar nada.
    public sealed class TestRunner
    {
        private int _passed;
        private int _failed;
        private string _suite = "(sem suite)";
        private readonly List<string> _failures = new List<string>();

        public int Passed { get { return _passed; } }
        public int Failed { get { return _failed; } }

        public void Suite(string name)
        {
            _suite = name;
            Console.WriteLine();
            Console.WriteLine("== " + name + " ==");
        }

        public void Check(string what, bool condition, string detail)
        {
            if (condition)
            {
                _passed++;
                Console.WriteLine("  [ok]   " + what);
            }
            else
            {
                _failed++;
                string message = _suite + " > " + what + (detail == null ? "" : " :: " + detail);
                _failures.Add(message);
                Console.WriteLine("  [FALHA] " + what + (detail == null ? "" : " :: " + detail));
            }
        }

        public void Equal(string what, object expected, object actual)
        {
            string e = Format(expected);
            string a = Format(actual);
            Check(what, string.Equals(e, a, StringComparison.Ordinal), "esperado <" + e + ">, obtido <" + a + ">");
        }

        public void True(string what, bool value)
        {
            Check(what, value, "esperado verdadeiro");
        }

        public void False(string what, bool value)
        {
            Check(what, !value, "esperado falso");
        }

        public void Null(string what, object value)
        {
            Check(what, value == null, "esperado null, obtido <" + Format(value) + ">");
        }

        public void NotNull(string what, object value)
        {
            Check(what, value != null, "esperado nao-null");
        }

        public void Contains(string what, string haystack, string needle)
        {
            bool ok = haystack != null && haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
            Check(what, ok, "esperado conter <" + needle + "> em <" + Truncate(haystack, 160) + ">");
        }

        public void DoesNotContain(string what, string haystack, string needle)
        {
            bool ok = haystack == null || haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase) < 0;
            Check(what, ok, "nao deveria conter <" + needle + ">");
        }

        // Injecao de falha: verifica que o codigo NAO lanca, mesmo com fonte
        // quebrada. O criterio de resiliencia do briefing e este.
        public void DoesNotThrow(string what, Action action)
        {
            try
            {
                action();
                Check(what, true, null);
            }
            catch (Exception ex)
            {
                Check(what, false, "lancou " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        public void Throws<TException>(string what, Action action) where TException : Exception
        {
            try
            {
                action();
                Check(what, false, "esperava " + typeof(TException).Name + ", nao lancou nada");
            }
            catch (TException)
            {
                Check(what, true, null);
            }
            catch (Exception ex)
            {
                Check(what, false, "esperava " + typeof(TException).Name + ", veio " + ex.GetType().Name);
            }
        }

        public int Report()
        {
            Console.WriteLine();
            Console.WriteLine("================================================");
            Console.WriteLine("  Testes: " + (_passed + _failed) + " | aprovados: " + _passed + " | falhas: " + _failed);
            Console.WriteLine("================================================");

            if (_failures.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine("Falhas:");
                foreach (string f in _failures) Console.WriteLine("  - " + f);
                return 1;
            }

            return 0;
        }

        private static string Format(object v)
        {
            if (v == null) return "(null)";
            if (v is double) return ((double)v).ToString("R", CultureInfo.InvariantCulture);
            if (v is float) return ((float)v).ToString("R", CultureInfo.InvariantCulture);
            return Convert.ToString(v, CultureInfo.InvariantCulture);
        }

        private static string Truncate(string s, int max)
        {
            if (s == null) return "(null)";
            return s.Length <= max ? s : s.Substring(0, max) + "...";
        }
    }
}
