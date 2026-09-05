using System;
using System.IO;
using PcDiag.Analysis;
using PcDiag.Collectors;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Reporting;
using PcDiag.Sources;

namespace PcDiag
{
    // Este arquivo existe so para ter um Main: toda a logica testavel
    // continua em Program.cs (com visibilidade internal onde e chamada
    // daqui), e o build da suite de testes exclui so este arquivo minimo.
    public static class Entry
    {
        public static int Main(string[] args)
        {
            // Primeira linha de verdade: tem que rodar antes de qualquer
            // P/Invoke do projeto (Native.EnumerateDevices chama cfgmgr32.dll,
            // que nao esta em KnownDLLs - ver Native.HardenDllSearchPath).
            Native.HardenDllSearchPath();

            try
            {
                Console.OutputEncoding = System.Text.Encoding.UTF8;
            }
            catch { }

            ScanOptions options = ScanOptions.Defaults();
            string error;
            bool testConnectivity = true;
            int eventDays = 7;

            if (!Program.ParseArguments(args, options, ref testConnectivity, ref eventDays, out error))
            {
                if (error != null) Console.Error.WriteLine("Erro: " + error);
                Program.PrintHelp();
                return error == null ? 0 : 2;
            }

            Logger log = new Logger(options.Verbose);
            ScanContext ctx = new ScanContext(options, log);

            Console.WriteLine("PC Diagnostic Engine v" + ScanContext.ToolVersion);
            Console.WriteLine("Scan " + ctx.ScanId + " | privilegio: " + (ctx.IsElevated ? "Administrador" : "Usuario padrao"));
            Console.WriteLine("Compatibilidade: " + ctx.Support + " - " + ctx.SupportReason);

            if (ctx.Support == SupportLevel.Unsupported)
            {
                Console.Error.WriteLine("Este sistema nao e suportado. Abortando para nao produzir um laudo enganoso.");
                return 3;
            }

            if (!ctx.IsElevated)
                Console.WriteLine("AVISO: sem elevacao, os testes que dependem de acesso privilegiado serao marcados como REQUER ADMIN (nunca como aprovados).");

            Console.WriteLine();

            Inventory inventory = new Inventory();
            SourceSet sources = Program.BuildSources(ctx, options);
            string outputDirectory = null;

            try
            {
                Program.RunCollection(ctx, sources, inventory, testConnectivity, eventDays);

                Console.WriteLine();
                Console.WriteLine("Analisando...");
                DiagnosticReport report = DiagnosticEngine.Analyze(ctx, inventory, Program.BuildSuites());

                ComparisonResult comparison = Comparison.Compare(report, options.BaselinePath, log);
                ReportEnvelope envelope = ReportEnvelope.From(report, comparison);

                // Mascarar AQUI, uma unica vez, antes de qualquer formato de
                // saida ser montado - assim HTML e JSON partem dos mesmos
                // dados ja mascarados e nao podem divergir entre si. Os dois
                // nomes de usuario precisam ser lidos ANTES da mascara, que
                // zera MachineInfo.LoggedUser; Environment.UserName cobre o
                // caso de elevacao com conta diferente da sessao interativa.
                if (ctx.Options.PrivacySafe)
                {
                    string interactiveUser = envelope.Inventory != null && envelope.Inventory.Machine != null
                        ? envelope.Inventory.Machine.LoggedUser : null;
                    Redaction.Apply(envelope, Environment.UserName, interactiveUser);
                }

                outputDirectory = Program.ResolveOutputDirectory(ctx, options, inventory);
                Program.WriteOutputs(ctx, envelope, outputDirectory);
                Program.PrintConsoleSummary(report);

                Program.OpenReport(ctx, outputDirectory);

                return report.Summary.CriticalIssues > 0 ? 1 : 0;
            }
            catch (Exception ex)
            {
                // Rede de seguranca: uma excecao nao prevista aqui (disco
                // cheio, pendrive removido, pasta somente leitura) nao pode
                // matar o processo sem deixar NENHUM artefato em disco. Aqui
                // a prioridade e salvar o que der: gravar os logs (que tem
                // tudo que rodou ate a falha) num lugar que sempre existe, e
                // devolver um codigo de saida proprio para quem rodou saber
                // que foi um erro inesperado, nao "0 problemas encontrados".
                Console.Error.WriteLine();
                Console.Error.WriteLine("ERRO INESPERADO: " + ex.GetType().Name + ": " + ex.Message);
                Console.Error.WriteLine("O diagnostico foi interrompido antes de terminar. Nenhum laudo confiavel foi gerado.");
                ctx.Log.Error("Main", "Excecao nao tratada: " + ex.GetType().Name + ": " + ex.Message +
                    Environment.NewLine + ex.StackTrace);

                string crashLogDir = outputDirectory;
                if (string.IsNullOrEmpty(crashLogDir))
                {
                    try { crashLogDir = Path.Combine(Path.GetTempPath(), "PcDiag_crash_" + ctx.ScanId); }
                    catch { crashLogDir = null; }
                }
                if (crashLogDir != null)
                {
                    try
                    {
                        ctx.Log.Flush(Path.Combine(crashLogDir, "logs"));
                        Console.Error.WriteLine("Logs parciais salvos em: " + Path.Combine(crashLogDir, "logs"));
                    }
                    catch { /* mesmo o log de emergencia pode falhar (disco cheio) - nao ha mais rede abaixo desta */ }
                }

                return 4;
            }
            finally
            {
                if (sources.Sensors != null) sources.Sensors.Dispose();
            }
        }
    }
}
