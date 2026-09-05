using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace PcDiag.Sources
{
    public sealed class RegistrySource : IRegistrySource
    {
        private readonly RegistryView _view;

        public RegistrySource()
        {
            // Registry64 evita o redirecionamento WOW6432Node quando o
            // processo for 32 bits em SO 64 bits - senao o inventario de
            // software e drivers sai pela metade.
            _view = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default;
        }

        public RegistrySource(RegistryView view)
        {
            _view = view;
        }

        private RegistryKey OpenBase(string hive)
        {
            if (string.Equals(hive, "HKLM", StringComparison.OrdinalIgnoreCase))
                return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, _view);
            if (string.Equals(hive, "HKCU", StringComparison.OrdinalIgnoreCase))
                return RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, _view);
            if (string.Equals(hive, "HKU", StringComparison.OrdinalIgnoreCase))
                return RegistryKey.OpenBaseKey(RegistryHive.Users, _view);
            if (string.Equals(hive, "HKCR", StringComparison.OrdinalIgnoreCase))
                return RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, _view);
            throw new ArgumentException("Hive desconhecido: " + hive);
        }

        public object GetValue(string hive, string subKey, string valueName)
        {
            using (RegistryKey root = OpenBase(hive))
            using (RegistryKey k = root.OpenSubKey(subKey, false))
            {
                if (k == null) return null;
                return k.GetValue(valueName, null);
            }
        }

        public IList<string> GetSubKeyNames(string hive, string subKey)
        {
            using (RegistryKey root = OpenBase(hive))
            using (RegistryKey k = root.OpenSubKey(subKey, false))
            {
                if (k == null) return new List<string>();
                return new List<string>(k.GetSubKeyNames());
            }
        }

        public IList<string> GetValueNames(string hive, string subKey)
        {
            using (RegistryKey root = OpenBase(hive))
            using (RegistryKey k = root.OpenSubKey(subKey, false))
            {
                if (k == null) return new List<string>();
                return new List<string>(k.GetValueNames());
            }
        }

        public bool KeyExists(string hive, string subKey)
        {
            using (RegistryKey root = OpenBase(hive))
            using (RegistryKey k = root.OpenSubKey(subKey, false))
            {
                return k != null;
            }
        }
    }

    // Enumeracao de subchaves resistente a ACL: se uma subchave irma negar
    // acesso, as demais continuam sendo lidas.
    //
    // Esse era um bug real no coletor antigo (Get-ChildItem com -ErrorAction
    // Stop abortava a enumeracao inteira na primeira subchave negada).
    public static class RegistryWalk
    {
        public static IEnumerable<string> SubKeysSafe(IRegistrySource reg, string hive, string path)
        {
            IList<string> names;
            try { names = reg.GetSubKeyNames(hive, path); }
            catch { yield break; }

            foreach (string n in names) yield return n;
        }

        public static object ValueSafe(IRegistrySource reg, string hive, string path, string name)
        {
            try { return reg.GetValue(hive, path, name); }
            catch { return null; }
        }
    }
}
