using System;
using System.Text;

namespace PcDiag.Core
{
    // Escape obrigatorio de tudo que entra no relatorio.
    //
    // No coletor antigo, nome de dispositivo, hostname, modelo de disco e
    // mensagem de evento do Windows iam crus para dentro de <td>. Um '<' em
    // qualquer um deles corrompia a tabela, e mensagem de evento e conteudo
    // que a ferramenta nao controla. Aqui nao existe caminho para HTML sem
    // passar por Text() ou Attr().
    public static class Html
    {
        public static string Text(object value)
        {
            if (value == null) return "";
            string s = value.ToString();
            StringBuilder sb = new StringBuilder(s.Length + 16);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                switch (c)
                {
                    case '&': sb.Append("&amp;"); break;
                    case '<': sb.Append("&lt;"); break;
                    case '>': sb.Append("&gt;"); break;
                    case '"': sb.Append("&quot;"); break;
                    case '\'': sb.Append("&#39;"); break;
                    default:
                        // Remove controles (exceto tab/CR/LF) que podem vir de
                        // mensagens de evento truncadas ou nomes de dispositivo
                        // mal formados.
                        if (c < 0x20 && c != '\t' && c != '\r' && c != '\n') sb.Append(' ');
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        public static string Attr(object value)
        {
            return Text(value);
        }

        // Valor ausente nunca vira string vazia silenciosa: o relatorio precisa
        // dizer explicitamente que o dado nao esta disponivel.
        public static string Value(object value, string whenNull)
        {
            if (value == null) return "<span class=\"na\">" + Text(whenNull) + "</span>";
            string s = value.ToString();
            if (s.Length == 0) return "<span class=\"na\">" + Text(whenNull) + "</span>";
            return Text(s);
        }

        public static string Value(object value)
        {
            return Value(value, "nao disponivel");
        }

        public static string Truncate(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return s;
            if (s.Length <= max) return s;
            return s.Substring(0, max) + "...";
        }
    }
}
