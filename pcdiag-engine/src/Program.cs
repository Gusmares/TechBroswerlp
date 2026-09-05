using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using PcDiag.Analysis;
using PcDiag.Collectors;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Reporting;
using PcDiag.Sources;

namespace PcDiag
{
    // Main mora em Entry.cs (arquivo minimo, excluido da suite de testes
    // por causa do Main duplicado). Tudo aqui e testavel; os metodos
    // chamados diretamente por Entry.Main sao internal em vez de private
    // para isso.
    public static class Program
    {
        // ---------- coleta ----------

        internal static SourceSet BuildSources(ScanContext ctx, ScanOptions options)
        {
            SourceSet s = new SourceSet();
            s.Wmi = new WmiSource(Math.Max(5, options.ModuleTimeoutMs / 1000));
            s.Registry = new RegistrySource();
            s.EventLog = new EventLogSource();
            s.Processes = new ProcessRunner();

            string libDirectory = Path.Combine(AppDirectory(), "lib");
            s.Sensors = SensorSource.TryOpen(libDirectory, ctx.IsElevated);
            ctx.SensorsAvailable = s.Sensors.Available;

            if (!s.Sensors.Available)
                ctx.Log.Warn("Sensors", "Sensores indisponiveis: " + s.Sensors.UnavailableReason);

            return s;
        }

        // Cada modulo roda isolado e com tempo limite. Um modulo que trava ou
        // lanca excecao nao impede os demais - a varredura continua e o que
        // faltou aparece como nao testado.
        internal static void RunCollection(ScanContext ctx, SourceSet sources, Inventory inventory,
            bool testConnectivity, int eventDays)
        {
            List<ICollector> collectors = new List<ICollector>();
            collectors.Add(new SystemCollector());
            collectors.Add(new CpuCollector());
            collectors.Add(new MemoryCollector());
            collectors.Add(new GpuCollector());
            collectors.Add(new StorageCollector());
            collectors.Add(new DeviceCollector());
            // Precisa rodar DEPOIS de DeviceCollector: le Inventory.Devices,
            // que so fica populado ali (ver comentario em ChipsetCollector).
            collectors.Add(new ChipsetCollector());
            collectors.Add(new NetworkCollector(testConnectivity));
            collectors.Add(new SecurityCollector());
            collectors.Add(new BatteryCollector());
            collectors.Add(new EventsCollector(eventDays));
            collectors.Add(new SoftwareCollector());
            collectors.Add(new SensorCollector());
            collectors.Add(new PerformanceCollector());
            collectors.Add(new StressCollector());

            foreach (ICollector collector in collectors)
            {
                ICollector current = collector;
                Console.Write("  " + current.Name.PadRight(14));

                int timeout = ctx.Options.ModuleTimeoutMs;
                // O modulo de carga tem orcamento proprio: o tempo pedido pelo
                // operador mais o custo das outras fases. O orcamento e um
                // teto de seguranca, nao uma previsao - por isso e calculado
                // com as taxas mais pessimistas (disco mecanico velho), senao
                // um teste legitimo e longo seria abortado como TIMEOUT.
                if (current is StressCollector && ctx.Options.AllowStress)
                    timeout = StressModuleBudgetMs(ctx.Options);

                ModuleOutcome outcome = ModuleRunner.Run(ctx, current.Name, delegate
                {
                    current.Collect(ctx, sources, inventory);
                }, timeout);

                if (outcome.Succeeded) Console.WriteLine("ok (" + outcome.DurationMs + " ms)");
                else if (outcome.TimedOut) Console.WriteLine("TIMEOUT - a varredura continua sem este modulo");
                else Console.WriteLine("falhou: " + outcome.Error);
            }
        }

        // Teto de tempo do modulo de carga, em milissegundos.
        public static int StressModuleBudgetMs(ScanOptions options)
        {
            long ms = 120000;                                  // base + resfriamento + folga
            ms += (long)options.StressSeconds * 1000L;

            // Fase de GPU: mesma duracao da carga de CPU, mais folga para a
            // criacao da janela/contexto e o Join de encerramento da thread
            // dedicada (ver RunGpuStress).
            if (options.AllowGpuStress) ms += (long)options.StressSeconds * 1000L + 60000L;

            // 10 MB/s e absurdamente pessimista para memoria, e e essa a
            // intencao: o teto so precisa nunca cortar um teste honesto.
            if (options.AllowMemoryTest) ms += (long)options.MemoryTestMegabytes * 100L;

            // Disco: escrita + leitura + IO aleatorio, ate quatro volumes.
            if (options.AllowDiskWriteBenchmark) ms += (long)options.DiskTestMegabytes * 200L * 4L;

            // O teto cobre o pior caso sem GPU (stress-seconds 7200 +
            // memory-test-mb 16384 + disk-benchmark-mb 8192 = 15.512.000 ms)
            // com folga.
            //
            // A fase de --gpu-stress soma outro "stress-seconds" inteiro
            // (roda depois da CPU, nao junto) - o pior caso com GPU chega a
            // 22.772.000 ms (120000 + 7200000 + 7260000 + 1638400 +
            // 6553600), por isso o teto abaixo cobre esse cenario tambem.
            if (ms > 23000000L) ms = 23000000L;
            return (int)ms;
        }

        internal static List<IDiagnosticTest> BuildSuites()
        {
            List<IDiagnosticTest> suites = new List<IDiagnosticTest>();
            suites.Add(new SystemTests());
            suites.Add(new CpuTests());
            suites.Add(new MemoryTests());
            suites.Add(new GpuTests());
            suites.Add(new StorageTests());
            suites.Add(new DeviceTests());
            suites.Add(new NetworkTests());
            suites.Add(new SecurityTests());
            suites.Add(new BatteryTests());
            suites.Add(new EventTests());
            suites.Add(new PerformanceTests());
            suites.Add(new StressTests());
            return suites;
        }

        // ---------- saida ----------

        internal static void WriteOutputs(ScanContext ctx, ReportEnvelope envelope, string directory)
        {
            Directory.CreateDirectory(directory);

            bool wantsJson = ctx.Options.Formats.Contains("json");
            bool wantsHtml = ctx.Options.Formats.Contains("html");

            if (wantsJson)
            {
                string jsonPath = Path.Combine(directory, "report.json");
                JsonReport.Write(jsonPath, envelope, ctx.Options.PrivacySafe);
                Console.WriteLine("  report.json  -> " + jsonPath);
            }

            if (wantsHtml)
            {
                string htmlPath = Path.Combine(directory, "report.html");
                HtmlReport.Write(htmlPath, envelope, ctx.Options.TechnicianReport);
                Console.WriteLine("  report.html  -> " + htmlPath);
            }

            ctx.Log.Flush(Path.Combine(directory, "logs"));
            Console.WriteLine("  logs/        -> " + Path.Combine(directory, "logs"));
        }

        // Grava ao lado do executavel por padrao.
        //
        // Usar a Area de Trabalho do usuario (como fazia o coletor antigo) e
        // uma armadilha: quando o UAC e atendido com OUTRA conta, USERPROFILE
        // aponta para o perfil do administrador, e o laudo vai parar numa Area
        // de Trabalho que o tecnico nao esta vendo.
        internal static string ResolveOutputDirectory(ScanContext ctx, ScanOptions options, Inventory inventory)
        {
            if (!string.IsNullOrEmpty(options.OutputDirectory))
            {
                // Aplica a mesma sonda IsWritable usada nos outros dois
                // destinos: se --out apontar para uma pasta que nao existe ou
                // nao pode ser criada, cai para a cadeia normal em vez de
                // deixar o processo inteiro morrer com uma excecao nao
                // tratada.
                string requested = options.OutputDirectory;
                try { Directory.CreateDirectory(requested); } catch { }
                if (IsWritable(requested))
                    return Path.Combine(requested, FolderName(ctx, inventory));

                ctx.Log.Warn("Output", "Pasta indicada em --out ('" + requested +
                    "') nao pode ser criada ou nao e gravavel; usando o destino padrao.");
            }

            string appDirectory = AppDirectory();
            string candidate = Path.Combine(appDirectory, "Relatorios");

            if (IsWritable(appDirectory)) return Path.Combine(candidate, FolderName(ctx, inventory));

            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            if (!string.IsNullOrEmpty(desktop) && IsWritable(desktop))
            {
                ctx.Log.Warn("Output", "Pasta do executavel nao e gravavel; usando a Area de Trabalho.");
                return Path.Combine(desktop, "Relatorios_Diagnostico", FolderName(ctx, inventory));
            }

            ctx.Log.Warn("Output", "Nem a pasta do executavel nem a Area de Trabalho sao gravaveis; usando a pasta temporaria.");
            return Path.Combine(Path.GetTempPath(), "PcDiag", FolderName(ctx, inventory));
        }

        private static string FolderName(ScanContext ctx, Inventory inventory)
        {
            string prefix;
            if (ctx.Options.PrivacySafe)
            {
                // Com --privacy-safe ativo, o nome da PASTA nao pode usar o
                // hostname real: ao zipar e compartilhar o laudo
                // "anonimizado", o hostname iria junto no nome do arquivo,
                // por fora de qualquer mascara de conteudo. ScanId e um
                // GUID e nao carrega identificacao nenhuma.
                prefix = "scan_" + ctx.ScanId;
            }
            else
            {
                string host = inventory.Machine != null && inventory.Machine.Hostname != null
                    ? inventory.Machine.Hostname : ctx.MachineNameRaw;
                prefix = Paths.SanitizeForFileName(host);
            }

            // O nome da pasta inclui segundos (nao so HHmm): uma segunda
            // execucao rapida (--json-only sem carga termina em bem menos de
            // um minuto) precisa de um nome distinto para nao sobrescrever
            // report.json/report.html/logs da execucao anterior.
            return prefix + "_" + ctx.StartedAt.ToString("yyyy-MM-dd_HHmmss", CultureInfo.InvariantCulture);
        }

        private static bool IsWritable(string directory)
        {
            try
            {
                if (!Directory.Exists(directory)) return false;
                string probe = Path.Combine(directory, "." + Guid.NewGuid().ToString("N").Substring(0, 8) + ".tmp");
                using (FileStream fs = new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 128, FileOptions.DeleteOnClose))
                {
                    fs.WriteByte(0);
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        internal static string AppDirectory()
        {
            try
            {
                string path = System.Reflection.Assembly.GetExecutingAssembly().Location;
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir)) return dir;
            }
            catch { }
            return Environment.CurrentDirectory;
        }

        internal static void PrintConsoleSummary(DiagnosticReport report)
        {
            ExecutiveSummary s = report.Summary;
            Console.WriteLine();
            Console.WriteLine("================================================");
            Console.WriteLine("  SCORE: " + s.HealthScore + "/100   " + s.Status);
            Console.WriteLine("  " + s.Headline);
            Console.WriteLine("------------------------------------------------");
            Console.WriteLine("  Criticos: " + s.CriticalIssues + " | Alta: " + s.HighIssues +
                              " | Media: " + s.MediumIssues + " | Baixa: " + s.LowIssues);
            Console.WriteLine("  Sem achado: " + s.TestsPassed + " | Nao executados: " + s.TestsNotExecuted +
                              " | Cobertura: " + s.CoveragePercent.ToString("F1", CultureInfo.InvariantCulture) + "%");
            if (s.InconsistenciesFound > 0)
                Console.WriteLine("  Divergencias entre fontes: " + s.InconsistenciesFound);
            Console.WriteLine("================================================");

            foreach (TestResult t in report.Tests)
            {
                if (t.Status != TestStatus.Critical) continue;
                Console.WriteLine("  [CRITICO] " + t.Name + ": " + t.Result);
            }
        }

        // Abre o laudo atraves do explorer.exe, e nao diretamente.
        //
        // Process.Start no arquivo, com o processo elevado, faria o NAVEGADOR
        // abrir elevado - o que e um problema de seguranca real. O explorer ja
        // roda como o usuario normal e repassa o arquivo para ele sem elevacao.
        internal static void OpenReport(ScanContext ctx, string directory)
        {
            if (!ctx.Options.OpenReport) return;

            string htmlPath = Path.Combine(directory, "report.html");
            if (!File.Exists(htmlPath)) return;

            try
            {
                string explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
                if (!File.Exists(explorer)) return;

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = explorer;
                psi.Arguments = ProcessRunner.QuoteArgument(htmlPath);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                ctx.Log.Warn("Output", "Nao foi possivel abrir o laudo automaticamente: " + ex.Message);
            }
        }

        // ---------- linha de comando ----------

        public static bool ParseArguments(string[] args, ScanOptions options,
            ref bool testConnectivity, ref int eventDays, out string error)
        {
            error = null;
            if (args == null) return true;

            // Os pisos do --extremo precisam ser aplicados depois que TODO o
            // parsing terminar, nao no momento em que a opcao e lida - senao
            // o resultado dependeria da ORDEM em que --extremo e
            // --stress-seconds/--memory-test-mb/--disk-benchmark-mb aparecem
            // na linha de comando, o que nao faz sentido para os MESMOS
            // argumentos. A flag abaixo so marca a intencao; os pisos sao
            // aplicados uma unica vez, mais abaixo.
            bool extremoRequested = false;

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                switch (a.ToLowerInvariant())
                {
                    case "-h":
                    case "--help":
                    case "/?":
                        return false;

                    case "--stress":
                        options.AllowStress = true;
                        break;

                    case "--disk-benchmark":
                        options.AllowStress = true;
                        options.AllowDiskWriteBenchmark = true;
                        break;

                    case "--memory-test":
                        options.AllowStress = true;
                        options.AllowMemoryTest = true;
                        break;

                    case "--gpu-stress":
                        options.AllowStress = true;
                        options.AllowGpuStress = true;
                        break;

                    // Perfil extremo: tudo ligado, com duracao suficiente para
                    // a temperatura estabilizar. Um teste curto nao prova nada
                    // sobre refrigeracao - equipamento com dissipador entupido
                    // costuma passar nos primeiros 30 segundos.
                    case "--extremo":
                    case "--extreme":
                        options.AllowStress = true;
                        options.AllowDiskWriteBenchmark = true;
                        options.AllowMemoryTest = true;
                        options.AllowGpuStress = true;
                        extremoRequested = true;
                        break;

                    case "--privacy-safe":
                        options.PrivacySafe = true;
                        break;

                    case "--user-report":
                        options.TechnicianReport = false;
                        break;

                    case "--no-open":
                        options.OpenReport = false;
                        break;

                    case "--no-connectivity":
                        testConnectivity = false;
                        break;

                    case "--verbose":
                        options.Verbose = true;
                        break;

                    case "--json-only":
                        options.Formats.Clear();
                        options.Formats.Add("json");
                        options.OpenReport = false;
                        break;

                    case "--stress-seconds":
                        {
                            int seconds;
                            if (!ReadIntValue(args, ref i, 5, 7200, out seconds, out error)) return false;
                            // Assim como --memory-test-mb e --disk-benchmark-mb
                            // ligam AllowMemoryTest/AllowDiskWriteBenchmark
                            // junto com o valor, --stress-seconds tambem
                            // precisa ligar AllowStress junto com o numero -
                            // senao o pedido do operador seria aceito sem
                            // erro e o teste de carga nunca rodaria.
                            options.AllowStress = true;
                            options.StressSeconds = seconds;
                            break;
                        }

                    case "--memory-test-mb":
                        {
                            int megabytes;
                            if (!ReadIntValue(args, ref i, 64, 16384, out megabytes, out error)) return false;
                            options.AllowStress = true;
                            options.AllowMemoryTest = true;
                            options.MemoryTestMegabytes = megabytes;
                            break;
                        }

                    case "--disk-benchmark-mb":
                        {
                            int megabytes;
                            if (!ReadIntValue(args, ref i, 64, 8192, out megabytes, out error)) return false;
                            options.AllowStress = true;
                            options.AllowDiskWriteBenchmark = true;
                            options.DiskTestMegabytes = megabytes;
                            break;
                        }

                    case "--timeout":
                        {
                            int seconds;
                            if (!ReadIntValue(args, ref i, 5, 600, out seconds, out error)) return false;
                            options.ModuleTimeoutMs = seconds * 1000;
                            break;
                        }

                    case "--event-days":
                        if (!ReadIntValue(args, ref i, 1, 90, out eventDays, out error)) return false;
                        break;

                    case "--cpu-warn":
                        {
                            int v;
                            if (!ReadIntValue(args, ref i, 40, 120, out v, out error)) return false;
                            options.CpuWarnC = v;
                            break;
                        }

                    case "--cpu-crit":
                        {
                            int v;
                            if (!ReadIntValue(args, ref i, 40, 130, out v, out error)) return false;
                            options.CpuCritC = v;
                            break;
                        }

                    case "--gpu-warn":
                        {
                            int v;
                            if (!ReadIntValue(args, ref i, 40, 110, out v, out error)) return false;
                            options.GpuWarnC = v;
                            break;
                        }

                    case "--gpu-crit":
                        {
                            int v;
                            if (!ReadIntValue(args, ref i, 40, 120, out v, out error)) return false;
                            options.GpuCritC = v;
                            break;
                        }

                    case "--out":
                        {
                            string dir;
                            if (!ReadString(args, ref i, out dir, out error)) return false;

                            string outReason;
                            if (IsDisallowedOutputPath(dir, out outReason))
                            {
                                error = "--out '" + dir + "' nao e permitido: " + outReason;
                                return false;
                            }

                            options.OutputDirectory = dir;
                            break;
                        }

                    case "--baseline":
                        {
                            string path;
                            if (!ReadString(args, ref i, out path, out error)) return false;
                            options.BaselinePath = path;
                            break;
                        }

                    default:
                        error = "argumento desconhecido '" + a + "'.";
                        return false;
                }
            }

            // Pisos do --extremo aplicados aqui, depois que TODO o parsing
            // terminou, junto com a validacao de cpu-warn/cpu-crit abaixo -
            // assim o resultado nao depende da ordem em que --extremo e
            // --stress-seconds/--memory-test-mb/--disk-benchmark-mb foram
            // digitados.
            if (extremoRequested)
            {
                if (options.StressSeconds < 600) options.StressSeconds = 600;
                if (options.MemoryTestMegabytes < 2048) options.MemoryTestMegabytes = 2048;
                if (options.DiskTestMegabytes < 1024) options.DiskTestMegabytes = 1024;
            }

            if (options.CpuCritC <= options.CpuWarnC)
            {
                error = "--cpu-crit deve ser maior que --cpu-warn.";
                return false;
            }

            if (options.GpuCritC <= options.GpuWarnC)
            {
                error = "--gpu-crit deve ser maior que --gpu-warn.";
                return false;
            }

            return true;
        }

        // Com o processo ELEVADO (o modo normal de uso, via UAC), --out sem
        // validacao gravaria o laudo inteiro - serial de BIOS/placa/discos,
        // MAC, IP, usuario logado, lista completa de software instalado,
        // eventos de seguranca - em qualquer caminho, inclusive
        // %SystemRoot%\System32 ou um compartilhamento de rede controlado
        // por outra pessoa.
        private static bool IsDisallowedOutputPath(string dir, out string reason)
        {
            reason = null;
            if (string.IsNullOrEmpty(dir)) return false;

            if (dir.StartsWith(@"\\", StringComparison.Ordinal))
            {
                reason = "caminhos de rede (UNC) nao sao permitidos.";
                return true;
            }

            string full;
            try
            {
                full = Path.GetFullPath(dir);
            }
            catch (Exception ex)
            {
                reason = "caminho invalido (" + ex.GetType().Name + ": " + ex.Message + ").";
                return true;
            }

            string[] forbidden = new string[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
            };

            foreach (string f in forbidden)
            {
                if (string.IsNullOrEmpty(f)) continue;
                if (string.Equals(full, f, StringComparison.OrdinalIgnoreCase) ||
                    full.StartsWith(f + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    reason = "nao e permitido gravar dentro de '" + f + "'.";
                    return true;
                }
            }

            return false;
        }

        private static bool ReadIntValue(string[] args, ref int i, int min, int max, out int value, out string error)
        {
            value = 0;
            error = null;

            if (i + 1 >= args.Length)
            {
                error = args[i] + " exige um valor numerico.";
                return false;
            }

            i++;
            if (!int.TryParse(args[i], NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
            {
                error = "'" + args[i] + "' nao e um numero valido.";
                return false;
            }

            if (value < min || value > max)
            {
                error = "valor fora da faixa permitida (" + min + " a " + max + ").";
                return false;
            }

            return true;
        }

        private static bool ReadString(string[] args, ref int i, out string value, out string error)
        {
            value = null;
            error = null;

            if (i + 1 >= args.Length)
            {
                error = args[i] + " exige um valor.";
                return false;
            }

            // Sem esta checagem, "--out --verbose" aceitaria "--verbose"
            // como VALOR de --out (o laudo iria parar numa pasta chamada
            // "--verbose" relativa ao diretorio atual) em vez de avisar que
            // faltou o valor de --out; e se o "valor" engolido fosse
            // invalido como caminho, o processo poderia morrer sem catch
            // mais adiante.
            string candidate = args[i + 1];
            if (candidate.Length > 0 && (candidate[0] == '-' || candidate[0] == '/'))
            {
                error = args[i] + " exige um valor (recebeu '" + candidate + "', que parece outra opcao).";
                return false;
            }

            i++;
            value = args[i];
            return true;
        }

        internal static void PrintHelp()
        {
            Console.WriteLine();
            Console.WriteLine("PC Diagnostic Engine v" + ScanContext.ToolVersion);
            Console.WriteLine();
            Console.WriteLine("  PcDiag.exe [opcoes]");
            Console.WriteLine();
            Console.WriteLine("Por padrao a ferramenta e SOMENTE LEITURA: nao escreve nada no equipamento");
            Console.WriteLine("fora da pasta de saida do laudo.");
            Console.WriteLine();
            Console.WriteLine("  --extremo               Perfil completo: carga de 10 min + memoria + disco + GPU.");
            Console.WriteLine("  --stress                Executa teste de carga de CPU (aquece o equipamento).");
            Console.WriteLine("  --stress-seconds <n>    Duracao do teste de carga, 5 a 7200 s (padrao 20).");
            Console.WriteLine("  --memory-test           Testa integridade da memoria com padroes de memtest.");
            Console.WriteLine("  --memory-test-mb <n>    Quanto testar da memoria, 64 a 16384 MB (padrao 512).");
            Console.WriteLine("  --disk-benchmark        Mede velocidade de disco ESCREVENDO arquivo temporario.");
            Console.WriteLine("  --disk-benchmark-mb <n> Tamanho do arquivo de teste, 64 a 8192 MB (padrao 256).");
            Console.WriteLine("  --gpu-stress            Aplica carga 3D real na GPU (janela OpenGL), alem da CPU.");
            Console.WriteLine("  --privacy-safe          Mascara serial, hostname, usuario, MAC e IP no laudo.");
            Console.WriteLine("  --user-report           Laudo simplificado, sem as secoes tecnicas.");
            Console.WriteLine("  --out <pasta>           Pasta de saida (padrao: ao lado do executavel).");
            Console.WriteLine("  --baseline <report.json>  Compara com um scan anterior.");
            Console.WriteLine("  --timeout <s>           Tempo limite por modulo, 5 a 600 s (padrao 30).");
            Console.WriteLine("  --event-days <n>        Janela de analise do log de eventos (padrao 7).");
            Console.WriteLine("  --cpu-warn <c>          Limiar de atencao da CPU em C (padrao 85).");
            Console.WriteLine("  --cpu-crit <c>          Limiar critico da CPU em C (padrao 95).");
            Console.WriteLine("  --gpu-warn <c>          Limiar de atencao da GPU em C (padrao 85).");
            Console.WriteLine("  --gpu-crit <c>          Limiar critico da GPU em C (padrao 92).");
            Console.WriteLine("  --no-connectivity       Nao executa os testes de rede externos.");
            Console.WriteLine("  --json-only             Gera apenas report.json.");
            Console.WriteLine("  --no-open               Nao abre o laudo ao final.");
            Console.WriteLine("  --verbose               Mostra o log detalhado no console.");
            Console.WriteLine("  --help                  Esta ajuda.");
            Console.WriteLine();
            Console.WriteLine("Execute como Administrador para o laudo completo. Sem elevacao a ferramenta");
            Console.WriteLine("funciona, mas marca como REQUER ADMIN tudo que nao pode verificar - e nunca");
            Console.WriteLine("apresenta um teste nao executado como aprovado.");
            Console.WriteLine();
        }
    }
}
