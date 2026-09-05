using System;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Threading;

namespace PcDiag.Core
{
    // Isolamento e timeout por modulo (item 49).
    //
    // Uma chamada WMI travada nao pode ser abortada de fora com seguranca -
    // Thread.Abort corrompe estado do CLR. A abordagem honesta e: rodar o
    // modulo numa thread de background, esperar o timeout, e seguir em frente
    // reportando TIMEOUT. A thread orfa nao impede o processo de encerrar
    // (IsBackground = true) e o restante da varredura continua normalmente.
    public static class ModuleRunner
    {
        public static ModuleOutcome Run(ScanContext ctx, string moduleName, Action work)
        {
            return Run(ctx, moduleName, work, ctx.Options.ModuleTimeoutMs);
        }

        public static ModuleOutcome Run(ScanContext ctx, string moduleName, Action work, int timeoutMs)
        {
            ModuleOutcome outcome = new ModuleOutcome();
            outcome.Module = moduleName;

            Stopwatch sw = Stopwatch.StartNew();
            Exception captured = null;
            bool finished;

            Thread t = new Thread(delegate()
            {
                try
                {
                    work();
                }
                catch (Exception ex)
                {
                    captured = ex;
                }
            });
            t.IsBackground = true;
            t.Name = "mod-" + moduleName;

            try
            {
                t.Start();
                finished = t.Join(timeoutMs);
            }
            catch (Exception ex)
            {
                sw.Stop();
                outcome.Succeeded = false;
                outcome.Error = "Falha ao iniciar o modulo: " + ex.Message;
                outcome.DurationMs = sw.ElapsedMilliseconds;
                ctx.Log.Error(moduleName, outcome.Error);
                ctx.ModuleOutcomes.Add(outcome);
                return outcome;
            }

            sw.Stop();
            outcome.DurationMs = sw.ElapsedMilliseconds;

            if (!finished)
            {
                outcome.Succeeded = false;
                outcome.TimedOut = true;
                outcome.Error = "TIMEOUT apos " + timeoutMs + "ms - o modulo foi abandonado e a varredura continuou.";
                ctx.Log.Error(moduleName, outcome.Error);
            }
            else if (captured != null)
            {
                outcome.Succeeded = false;
                outcome.Error = captured.GetType().Name + ": " + captured.Message;
                // outcome.Error (curto, vai para o relatorio) nao e o unico
                // registro da falha - o log tambem recebe o stack trace
                // completo da excecao de MODULO. A ferramenta roda de
                // pendrive, offline, sem depurador e normalmente sem segunda
                // chance: sem stack trace, um NullReferenceException so
                // reproduzivel na maquina do cliente vira um misterio sem
                // pista nenhuma.
                ctx.Log.Error(moduleName, Try.ScrubIfPrivacySafe(ctx, captured.ToString()));
            }
            else
            {
                outcome.Succeeded = true;
                ctx.Log.Perf(moduleName, "modulo concluido", outcome.DurationMs);
            }

            ctx.ModuleOutcomes.Add(outcome);
            return outcome;
        }
    }

    // Substituto do Get-Safe do script antigo.
    //
    // Diferenca essencial: Get-Safe devolvia um VALOR DE FALLBACK plausivel
    // ("Nenhum erro encontrado"), que depois era interpretado como diagnostico
    // positivo. Aqui a falha devolve default(T) - que para tipo anulavel e
    // null, ou seja "nao disponivel" - e SEMPRE registra no log o que falhou.
    // Ausencia de dado nunca vira afirmacao de saude.
    public static class Try
    {
        public static T Get<T>(ScanContext ctx, string module, string what, Func<T> fn)
        {
            try
            {
                return fn();
            }
            catch (Exception ex)
            {
                ctx.Log.Write(LogLevel.Warn, LogChannel.Errors, module,
                    "Falha lendo '" + what + "': " + ex.GetType().Name + ": " + ScrubIfPrivacySafe(ctx, ex.Message));
                return default(T);
            }
        }

        public static bool Do(ScanContext ctx, string module, string what, Action fn)
        {
            try
            {
                fn();
                return true;
            }
            catch (Exception ex)
            {
                ctx.Log.Write(LogLevel.Warn, LogChannel.Errors, module,
                    "Falha executando '" + what + "': " + ex.GetType().Name + ": " + ScrubIfPrivacySafe(ctx, ex.Message));
                return false;
            }
        }

        // ex.Message (e ex.ToString(), usado pelo ModuleRunner acima) pode
        // conter um caminho sob C:\Users\<usuario> - por exemplo um
        // IOException de um arquivo dentro do perfil - por isso essas
        // mensagens passam por este scrub antes de ir para errors.log
        // quando --privacy-safe esta ativo. Mesma regex de UserProfilePath
        // usada em Core/Redaction.cs, replicada aqui porque esta classe nao
        // expoe a logica de mascaramento como API publica.
        private static readonly Regex UserProfilePath = new Regex(
            @"([A-Za-z]:\\Users\\|/Users/)([^\\/""<>|]+)", RegexOptions.IgnoreCase);

        internal static string ScrubIfPrivacySafe(ScanContext ctx, string text)
        {
            if (ctx == null || ctx.Options == null || !ctx.Options.PrivacySafe || string.IsNullOrEmpty(text))
                return text;

            if (text.IndexOf(@"\Users\", StringComparison.OrdinalIgnoreCase) < 0 &&
                text.IndexOf("/Users/", StringComparison.OrdinalIgnoreCase) < 0)
                return text;

            return UserProfilePath.Replace(text, "$1" + JsonWriter.Mask);
        }
    }
}
