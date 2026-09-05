using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace PcDiag.Core
{
    public enum LogLevel
    {
        Debug,
        Info,
        Warn,
        Error
    }

    public enum LogChannel
    {
        Execution,
        Errors,
        Diagnostic,
        Security,
        Performance
    }

    public sealed class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public LogLevel Level { get; set; }
        public LogChannel Channel { get; set; }
        public string Module { get; set; }
        public string Message { get; set; }
        public long DurationMs { get; set; }
    }

    // Logs separados por canal (item 50). Escrita bufferizada em memoria e
    // despejada no final: se a maquina do cliente estiver lenta, o
    // diagnostico nao paga I/O a cada linha.
    //
    // Nunca registra segredo: o unico dado potencialmente sensivel que passa
    // por aqui e nome de modulo/consulta, nunca valor coletado.
    public sealed class Logger
    {
        private readonly List<LogEntry> _entries = new List<LogEntry>();
        private readonly object _lock = new object();
        private readonly bool _verbose;

        private string _crashFlushDirectory;
        private int _crashHandlersAttached;

        public Logger(bool verbose)
        {
            _verbose = verbose;
        }

        // Ate aqui o log so existia em memoria e so era gravado em disco no
        // caminho feliz (WriteOutputs no final do Main). Se a maquina
        // travar, sofrer BSOD, for desligada, ou o tecnico der Ctrl+C
        // durante o teste de carga (--extremo, o cenario com o resultado
        // diagnostico mais valioso), a trilha inteira some. Este metodo
        // registra dois ganchos - AppDomain.UnhandledException e
        // Console.CancelKeyPress - para tentar um Flush best-effort no
        // diretorio ja resolvido antes do processo morrer. Deve ser chamado
        // assim que o diretorio de saida for conhecido (o call site fica em
        // Program.cs).
        public void AttachCrashSafety(string logDirectory)
        {
            if (string.IsNullOrEmpty(logDirectory)) return;
            _crashFlushDirectory = logDirectory;

            if (System.Threading.Interlocked.Exchange(ref _crashHandlersAttached, 1) != 0)
                return; // ja anexado - evita registrar o handler duas vezes.

            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            Console.CancelKeyPress += OnCancelKeyPress;
        }

        private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            TryCrashFlush();
        }

        private void OnCancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            TryCrashFlush();
        }

        private void TryCrashFlush()
        {
            string dir = _crashFlushDirectory;
            if (string.IsNullOrEmpty(dir)) return;
            try { Flush(dir); } catch { /* best-effort: nunca lancar durante o crash. */ }
        }

        public IEnumerable<LogEntry> Entries
        {
            get { lock (_lock) { return _entries.ToArray(); } }
        }

        // Conta por CANAL (LogChannel.Errors), nao por NIVEL: Runner.cs e
        // StressCollector.cs registram timeout/modulo interrompido como
        // LogLevel.Warn dentro do canal LogChannel.Errors (para nao imprimir
        // como erro fatal no console), e contar so Level==Error deixaria
        // essas entradas de fora. Contar por canal reflete o que de fato vai
        // para errors.log.
        public int ErrorCount
        {
            get
            {
                lock (_lock)
                {
                    int n = 0;
                    foreach (LogEntry e in _entries) if (e.Channel == LogChannel.Errors) n++;
                    return n;
                }
            }
        }

        public void Write(LogLevel level, LogChannel channel, string module, string message)
        {
            Write(level, channel, module, message, 0);
        }

        public void Write(LogLevel level, LogChannel channel, string module, string message, long durationMs)
        {
            LogEntry e = new LogEntry();
            e.Timestamp = DateTime.Now;
            e.Level = level;
            e.Channel = channel;
            e.Module = module;
            e.Message = message;
            e.DurationMs = durationMs;
            lock (_lock) { _entries.Add(e); }

            if (_verbose || level == LogLevel.Error)
            {
                Console.Error.WriteLine("[" + level + "] " + module + ": " + message);
            }
        }

        public void Info(string module, string message) { Write(LogLevel.Info, LogChannel.Execution, module, message); }
        public void Debug(string module, string message) { Write(LogLevel.Debug, LogChannel.Execution, module, message); }
        public void Warn(string module, string message) { Write(LogLevel.Warn, LogChannel.Execution, module, message); }
        public void Error(string module, string message) { Write(LogLevel.Error, LogChannel.Errors, module, message); }
        public void Security(string module, string message) { Write(LogLevel.Info, LogChannel.Security, module, message); }
        public void Perf(string module, string message, long ms) { Write(LogLevel.Debug, LogChannel.Performance, module, message, ms); }

        public void Flush(string logDirectory)
        {
            Directory.CreateDirectory(logDirectory);
            WriteChannel(logDirectory, "execution.log", LogChannel.Execution);
            WriteChannel(logDirectory, "errors.log", LogChannel.Errors);
            WriteChannel(logDirectory, "diagnostic.log", LogChannel.Diagnostic);
            WriteChannel(logDirectory, "security.log", LogChannel.Security);
            WriteChannel(logDirectory, "performance.log", LogChannel.Performance);
        }

        private void WriteChannel(string dir, string fileName, LogChannel channel)
        {
            StringBuilder sb = new StringBuilder();
            LogEntry[] snapshot;
            lock (_lock) { snapshot = _entries.ToArray(); }

            foreach (LogEntry e in snapshot)
            {
                if (e.Channel != channel) continue;
                sb.Append(e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture));
                sb.Append(" | ").Append(e.Level.ToString().ToUpperInvariant().PadRight(5));
                sb.Append(" | ").Append((e.Module == null ? "-" : e.Module).PadRight(22));
                if (e.DurationMs > 0) sb.Append(" | ").Append(e.DurationMs.ToString(CultureInfo.InvariantCulture)).Append("ms");
                sb.Append(" | ").Append(e.Message);
                sb.Append(Environment.NewLine);
            }

            // UTF-8 SEM BOM e com nova linha explicita: o log e lido por
            // ferramentas variadas, e BOM em arquivo de log atrapalha grep.
            File.WriteAllText(Path.Combine(dir, fileName), sb.ToString(), new UTF8Encoding(false));
        }
    }
}
