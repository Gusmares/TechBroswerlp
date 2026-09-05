using System;
using System.Text;

namespace PcDiag.Core
{
    public static class Paths
    {
        // O nome do equipamento vira parte de um caminho de diretorio. Como
        // ele vem do sistema (e pode conter acentos, barras ou qualquer coisa
        // que o administrador tenha configurado), precisa ser reduzido a um
        // conjunto seguro antes de virar caminho - senao um hostname com "..\"
        // faria o laudo ser gravado fora da pasta pretendida.
        public static string SanitizeForFileName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "equipamento";

            StringBuilder sb = new StringBuilder();
            foreach (char c in name)
            {
                if (char.IsLetterOrDigit(c) || c == '-' || c == '_') sb.Append(c);
                else sb.Append('_');
            }

            string result = sb.ToString().Trim('_');
            if (result.Length == 0) return "equipamento";
            if (result.Length > 40) result = result.Substring(0, 40);
            return result;
        }
    }
}
