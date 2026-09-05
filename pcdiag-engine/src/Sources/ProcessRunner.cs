using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace PcDiag.Sources
{
    // Execucao de processo externo com superficie de ataque minima (item 39).
    //
    // Garantias:
    //  - o executavel e resolvido para %SystemRoot%\System32\<nome>.exe e o
    //    caminho e verificado antes de rodar. Nunca usa o PATH, entao nao ha
    //    PATH hijacking mesmo rodando de pendrive em maquina comprometida.
    //  - so nomes de um allowlist sao aceitos.
    //  - argumentos sao passados como array e escapados pelas regras do
    //    CommandLineToArgvW, entao nao ha argument injection.
    //  - UseShellExecute = false: nao ha shell, entao nao ha command injection.
    //  - timeout obrigatorio, com kill do processo criado.
    //
    //    Nota: o kill de timeout (p.Kill() abaixo) mata SO o processo filho
    //    direto - ferramentas do allowlist que criam subprocessos (dism.exe
    //    gera DismHost.exe; sfc.exe pode gerar helpers) podem deixar esses
    //    processos rodando na maquina do cliente apos o timeout. Kill de
    //    arvore de fato exigiria um Job Object (CreateJobObject +
    //    SetInformationJobObject(JOBOBJECT_LIMIT_KILL_ON_JOB_CLOSE) +
    //    AssignProcessToJobObject) - fora do escopo atual.
    public sealed class ProcessRunner : IProcessRunner
    {
        // Allowlist explicito. Adicionar aqui e uma decisao consciente, nao um
        // efeito colateral de escrever uma string em outro arquivo.
        private static readonly string[] Allowed = new string[]
        {
            "powercfg.exe",
            "bcdedit.exe",
            "dism.exe",
            "sfc.exe",
            "fltmc.exe",
            "manage-bde.exe",
            "wevtutil.exe",
            "systeminfo.exe",
            "driverquery.exe",
            "tasklist.exe"
        };

        public ProcessResult RunSystem32(string executableName, string[] args, int timeoutMs)
        {
            ProcessResult result = new ProcessResult();

            if (string.IsNullOrEmpty(executableName))
            {
                result.FailureReason = "Nome de executavel vazio.";
                return result;
            }

            bool allowed = false;
            foreach (string a in Allowed)
            {
                if (string.Equals(a, executableName, StringComparison.OrdinalIgnoreCase)) { allowed = true; break; }
            }
            if (!allowed)
            {
                result.FailureReason = "Executavel '" + executableName + "' nao esta no allowlist da ferramenta.";
                return result;
            }

            string system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System));
            string fullPath = Path.Combine(system32, executableName);

            if (!File.Exists(fullPath))
            {
                result.FailureReason = "Executavel nao encontrado em " + fullPath;
                return result;
            }

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = fullPath;
            psi.Arguments = BuildArguments(args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            // As ferramentas do allowlist (todas
            // em %SystemRoot%\System32) escrevem no console usando o CODE
            // PAGE OEM ativo do sistema (ex.: 850/860 em pt-BR), nao UTF-8.
            // Forcar StandardOutputEncoding=UTF8 fazia o .NET decodificar
            // bytes OEM como se fossem UTF-8, corrompendo qualquer acento
            // (c-cedilha, til, acento agudo) na saida - texto lixo em vez de
            // "nao corrigivel". Nao define encoding explicito: o
            // Process/ProcessStartInfo do .NET Framework ja usa o code page
            // OEM do console (Console.OutputEncoding) por padrao para saida
            // redirecionada quando nenhum encoding e forcado.
            psi.WorkingDirectory = system32;

            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();

            // ProcessResult.ExitCode e int (nao
            // int?, ver Sources/Interfaces.cs) - sem um sentinela explicito,
            // 0 e ao mesmo tempo "processo terminou com sucesso" e "o
            // processo nunca chegou a rodar" ou "foi morto por timeout", os
            // tres casos indistinguiveis para quem le so o ExitCode. O
            // chamador atual (BatteryCollector) escapa porque confere
            // !pr.Started antes - um chamador futuro que nao confira cairia
            // direto nessa armadilha. -1 nunca e um exit code real do
            // Windows para os executaveis do allowlist, e so e sobrescrito
            // abaixo no UNICO caminho onde o processo de fato terminou
            // dentro do prazo.
            result.ExitCode = -1;

            try
            {
                using (Process p = new Process())
                {
                    p.StartInfo = psi;
                    p.OutputDataReceived += delegate(object s, DataReceivedEventArgs e)
                    {
                        if (e.Data != null) stdout.AppendLine(e.Data);
                    };
                    p.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e)
                    {
                        if (e.Data != null) stderr.AppendLine(e.Data);
                    };

                    p.Start();
                    result.Started = true;
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();

                    if (!p.WaitForExit(timeoutMs))
                    {
                        result.TimedOut = true;
                        try { p.Kill(); } catch { }
                        try { p.WaitForExit(2000); } catch { }
                        result.FailureReason = "Timeout apos " + timeoutMs + "ms.";
                    }
                    else
                    {
                        // WaitForExit(timeoutMs)
                        // so garante que o PROCESSO terminou - as threads
                        // assincronas que entregam OutputDataReceived/
                        // ErrorDataReceived podem ainda ter dados em transito
                        // quando essa sobrecarga com timeout retorna true. A
                        // MSDN recomenda chamar WaitForExit() SEM parametro
                        // logo em seguida, que bloqueia ate os pipes
                        // redirecionados serem esvaziados de fato - sem isso,
                        // a ultima linha da saida de um comando do allowlist
                        // (wevtutil, dism, sfc) pode ficar de fora do
                        // StringBuilder lido abaixo, truncamento silencioso.
                        p.WaitForExit();
                        result.ExitCode = p.ExitCode;
                    }
                }
            }
            catch (Exception ex)
            {
                result.FailureReason = ex.GetType().Name + ": " + ex.Message;
            }

            result.StandardOutput = stdout.ToString();
            result.StandardError = stderr.ToString();
            return result;
        }

        // Quoting conforme as regras do CommandLineToArgvW: aspas viram \" e
        // barras invertidas imediatamente antes de uma aspa sao duplicadas.
        public static string BuildArguments(string[] args)
        {
            if (args == null || args.Length == 0) return "";
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < args.Length; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(QuoteArgument(args[i]));
            }
            return sb.ToString();
        }

        public static string QuoteArgument(string arg)
        {
            if (arg == null) arg = "";

            bool needsQuotes = arg.Length == 0;
            for (int i = 0; i < arg.Length && !needsQuotes; i++)
            {
                char c = arg[i];
                if (c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '"') needsQuotes = true;
            }

            if (!needsQuotes) return arg;

            StringBuilder sb = new StringBuilder();
            sb.Append('"');
            for (int i = 0; i < arg.Length; i++)
            {
                int backslashes = 0;
                while (i < arg.Length && arg[i] == '\\')
                {
                    backslashes++;
                    i++;
                }

                if (i == arg.Length)
                {
                    // Barras no fim: dobrar, pois a aspa de fechamento vem logo.
                    sb.Append('\\', backslashes * 2);
                    break;
                }

                if (arg[i] == '"')
                {
                    sb.Append('\\', backslashes * 2 + 1);
                    sb.Append('"');
                }
                else
                {
                    sb.Append('\\', backslashes);
                    sb.Append(arg[i]);
                }
            }
            sb.Append('"');
            return sb.ToString();
        }
    }
}
