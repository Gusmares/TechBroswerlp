using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace PcDiag.Sources
{
    public sealed class SensorReading
    {
        public string Hardware { get; set; }
        public string HardwareType { get; set; }
        public string SensorType { get; set; }
        public string Name { get; set; }
        public double Value { get; set; }
    }

    // Acesso aos sensores reais de hardware via LibreHardwareMonitorLib.
    //
    // Carregado por REFLEXAO, de proposito: se a pasta lib/ estiver faltando,
    // se o antivirus tiver colocado a DLL em quarentena, ou se a versao da
    // biblioteca mudar a API, a ferramenta continua rodando e reporta
    // "sensores nao disponiveis" - em vez de nao iniciar. Com referencia de
    // compilacao, a DLL ausente derrubaria o processo inteiro no primeiro uso.
    public sealed class SensorSource : IDisposable
    {
        private object _computer;
        private Type _computerType;
        private bool _open;

        // A biblioteca por baixo (LibreHardwareMonitorLib)
        // faz I/O de porta/registro sobre o mesmo objeto Computer e nao foi
        // desenhada para reentrancia - duas threads chamando Update() ao
        // mesmo tempo em hardwares diferentes (ou no mesmo) podem produzir
        // leitura cruzada (valor de um sensor atribuido a outro) ou lancar.
        // Dispose() tambem chamava Computer.Close() sem esperar nenhuma
        // leitura em andamento terminar. Um lock privado serializa Read() e
        // Dispose() entre si.
        private readonly object _sync = new object();

        public bool Available { get { return _open; } }
        public string UnavailableReason { get; private set; }

        // Pinagem de integridade: estas DLLs sao
        // carregadas por Assembly.LoadFrom/reflexao com o processo ELEVADO, e
        // nenhuma delas e assinada digitalmente - Get-AuthenticodeSignature
        // devolve NotSigned para LibreHardwareMonitorLib.dll nesta
        // distribuicao, entao exigir Authenticode quebraria a leitura de
        // sensores por completo. Na ausencia de assinatura, o hash SHA-256 e
        // a defesa possivel contra substituicao: um atacante com escrita na
        // pasta lib/ (pendrive FAT32 sem ACL, pasta de Downloads antes da
        // elevacao) nao consegue trocar o arquivo por um malicioso sem que o
        // hash mude e o carregamento seja recusado.
        //
        // Para atualizar apos trocar uma DLL legitima em lib/:
        //   Get-FileHash lib\NomeDoArquivo.dll -Algorithm SHA256
        // e colar o valor (maiusculo) abaixo.
        private static readonly Dictionary<string, string> TrustedHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "LibreHardwareMonitorLib.dll", "6EBC194316536BA61AF5BE24508AD9FCBB2ECC685E716C12E787C79530F66BF0" },
            { "System.Buffers.dll", "2D78D770C9CB997199154AE8C018B9F1D1EFBC86729F7264DDE6DBAD2A12CAC3" },
            { "System.Numerics.Vectors.dll", "20C2FA81B8C70D651099D762954F285FD4F942E63B2D7217C145DAB8D4B2F4C9" },
            { "System.Runtime.CompilerServices.Unsafe.dll", "08CBD7278B66F1E68425A82D4B97181A4130D93E3DD91831407ABA7212CCDACF" },
            { "System.Memory.dll", "D5E8E4866F9CFA66F7765660F84B210198893E55335487AFE5EBDA342C0E913D" },
            { "HidSharp.dll", "D86690EFDE30EA9179F669320F39148853793B743A98B531AFEAF30598E22F54" },
        };

        private static bool IsTrusted(string path)
        {
            string name = Path.GetFileName(path);
            string expected;
            if (!TrustedHashes.TryGetValue(name, out expected)) return false;

            using (SHA256 sha = SHA256.Create())
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] hash = sha.ComputeHash(fs);
                string actual = BitConverter.ToString(hash).Replace("-", "");
                return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
            }
        }

        public static SensorSource TryOpen(string libDirectory, bool isElevated)
        {
            SensorSource s = new SensorSource();

            if (!isElevated)
            {
                s.UnavailableReason = "Leitura de sensores exige privilegio de Administrador (o driver de acesso ao hardware nao carrega sem elevacao).";
                return s;
            }

            if (!Directory.Exists(libDirectory))
            {
                s.UnavailableReason = "Pasta de bibliotecas nao encontrada: " + libDirectory;
                return s;
            }

            string libPath = Path.Combine(libDirectory, "LibreHardwareMonitorLib.dll");
            if (!File.Exists(libPath))
            {
                s.UnavailableReason = "LibreHardwareMonitorLib.dll nao encontrada em " + libDirectory;
                return s;
            }

            if (!IsTrusted(libPath))
            {
                s.UnavailableReason = "LibreHardwareMonitorLib.dll nao corresponde ao hash esperado - arquivo pode ter sido substituido. Carregamento recusado por seguranca.";
                return s;
            }

            try
            {
                // Pre-carrega as dependencias que a lib usa, na ordem correta.
                // So carrega o que bate com o hash esperado - o mesmo motivo
                // do LoadFrom principal, so que aqui uma dependencia hostil
                // simplesmente nao entra no processo (fica como se o arquivo
                // nao existisse), em vez de abortar toda a leitura de sensores.
                string[] deps = new string[]
                {
                    "System.Buffers.dll",
                    "System.Numerics.Vectors.dll",
                    "System.Runtime.CompilerServices.Unsafe.dll",
                    "System.Memory.dll",
                    "HidSharp.dll"
                };
                foreach (string dep in deps)
                {
                    string p = Path.Combine(libDirectory, dep);
                    if (File.Exists(p) && IsTrusted(p))
                    {
                        TryUnblock(p);
                        try { Assembly.LoadFrom(p); }
                        catch { /* dependencia opcional */ }
                    }
                }

                // O pacote de download do dashboard serve estas DLLs por
                // HTTP (buildCollectorPackage -> /api/downloads/pcdiag) e o
                // Explorer marca todo arquivo extraido de um .zip baixado
                // com Zone.Identifier (Mark-of-the-Web), o que pode derrubar
                // silenciosamente toda a telemetria termica no caminho de
                // distribuicao mais comum da ferramenta - nao no build
                // local, so no pacote baixado.
                //
                // Apagar so o fluxo NTFS (TryUnblock, abaixo) nao basta
                // sozinho - Assembly.LoadFrom ainda pode recusar com
                // NotSupportedException pedindo loadFromRemoteSources. E
                // necessario as DUAS coisas juntas: o app.config com
                // <loadFromRemoteSources enabled="true"/> (emitido por
                // build.ps1) E o fluxo Zone.Identifier removido. TryUnblock
                // continua valendo por si so (evita o Windows tratar o
                // arquivo como baixado da internet para outros fins, ex.
                // SmartScreen) mas nao e suficiente sem o app.config - as
                // duas defesas sao complementares, nao redundantes.
                // TryUnblock so roda DEPOIS do IsTrusted acima, entao nao
                // abre brecha nenhuma - so remove um marcador de proveniencia
                // de um arquivo cujo conteudo ja foi verificado por hash.
                TryUnblock(libPath);

                Assembly asm = Assembly.LoadFrom(libPath);
                Type computerType = asm.GetType("LibreHardwareMonitor.Hardware.Computer");
                if (computerType == null)
                {
                    s.UnavailableReason = "Tipo Computer nao encontrado na biblioteca de sensores (versao incompativel).";
                    return s;
                }

                object computer = Activator.CreateInstance(computerType);
                SetBool(computerType, computer, "IsCpuEnabled", true);
                SetBool(computerType, computer, "IsGpuEnabled", true);
                SetBool(computerType, computer, "IsStorageEnabled", true);
                SetBool(computerType, computer, "IsMotherboardEnabled", true);
                SetBool(computerType, computer, "IsMemoryEnabled", true);

                MethodInfo open = computerType.GetMethod("Open", Type.EmptyTypes);
                if (open == null)
                {
                    s.UnavailableReason = "Metodo Open() nao encontrado (versao incompativel da biblioteca).";
                    return s;
                }
                open.Invoke(computer, null);

                s._computer = computer;
                s._computerType = computerType;
                s._open = true;
                return s;
            }
            catch (Exception ex)
            {
                Exception root = ex;
                while (root.InnerException != null) root = root.InnerException;

                // Se TryUnblock nao conseguiu
                // apagar o fluxo Zone.Identifier (volume nao-NTFS, permissao
                // negada), o FileLoadException 0x80131515 ainda pode
                // acontecer - dar o diagnostico certo em vez do texto
                // generico "falha ao inicializar".
                FileLoadException loadEx = root as FileLoadException;
                if (loadEx != null && unchecked((uint)loadEx.HResult) == 0x80131515)
                {
                    s.UnavailableReason = "DLL de sensores bloqueada pelo Windows (arquivo marcado como baixado da internet). " +
                        "Clique com o botao direito em cada .dll de lib\\, abra Propriedades e clique em Desbloquear; ou copie a pasta lib\\ inteira para um novo local antes de rodar.";
                    return s;
                }

                s.UnavailableReason = "Falha ao inicializar a biblioteca de sensores: " + root.GetType().Name + ": " + root.Message;
                return s;
            }
        }

        // Apaga o fluxo NTFS alternativo ":Zone.Identifier" que o Windows
        // grava em todo arquivo extraido de um download (Mark-of-the-Web) -
        // o mesmo efeito do botao "Desbloquear" em Propriedades do arquivo.
        // Silencioso de proposito: volume nao-NTFS (FAT32, comum em
        // pendrive) nao tem esse fluxo para apagar, e isso e normal, nao erro.
        private static void TryUnblock(string path)
        {
            try
            {
                string adsPath = path + ":Zone.Identifier";
                if (File.Exists(adsPath)) File.Delete(adsPath);
            }
            catch { /* nao-NTFS, permissao negada, ou arquivo ja desbloqueado - segue e deixa o LoadFrom decidir */ }
        }

        private static void SetBool(Type t, object instance, string prop, bool value)
        {
            PropertyInfo p = t.GetProperty(prop);
            if (p != null && p.CanWrite) p.SetValue(instance, value, null);
        }

        public IList<SensorReading> Read()
        {
            // Serializado com Dispose() (mesmo
            // lock) para que Computer.Close() nunca rode enquanto uma
            // leitura esta em andamento, e para que duas leituras
            // concorrentes nao pisem uma na outra dentro da lib nativa.
            lock (_sync)
            {
                List<SensorReading> readings = new List<SensorReading>();
                if (!_open) return readings;

                PropertyInfo hardwareProp = _computerType.GetProperty("Hardware");
                if (hardwareProp == null) return readings;

                System.Collections.IEnumerable hardware = hardwareProp.GetValue(_computer, null) as System.Collections.IEnumerable;
                if (hardware == null) return readings;

                foreach (object hw in hardware)
                {
                    CollectFrom(hw, null, readings);

                    PropertyInfo subProp = hw.GetType().GetProperty("SubHardware");
                    if (subProp == null) continue;
                    System.Collections.IEnumerable subs = subProp.GetValue(hw, null) as System.Collections.IEnumerable;
                    if (subs == null) continue;

                    string parentName = GetStringProp(hw, "Name");
                    foreach (object sub in subs) CollectFrom(sub, parentName, readings);
                }

                return readings;
            }
        }

        private static void CollectFrom(object hw, string parentName, List<SensorReading> readings)
        {
            try
            {
                MethodInfo update = hw.GetType().GetMethod("Update", Type.EmptyTypes);
                if (update != null) update.Invoke(hw, null);
            }
            catch { }

            string hwName = GetStringProp(hw, "Name");
            if (parentName != null) hwName = parentName + " / " + hwName;
            string hwType = GetStringProp(hw, "HardwareType");

            PropertyInfo sensorsProp = hw.GetType().GetProperty("Sensors");
            if (sensorsProp == null) return;

            System.Collections.IEnumerable sensors;
            try { sensors = sensorsProp.GetValue(hw, null) as System.Collections.IEnumerable; }
            catch { return; }
            if (sensors == null) return;

            foreach (object s in sensors)
            {
                try
                {
                    PropertyInfo valueProp = s.GetType().GetProperty("Value");
                    if (valueProp == null) continue;
                    object v = valueProp.GetValue(s, null);
                    if (v == null) continue;

                    SensorReading r = new SensorReading();
                    r.Hardware = hwName;
                    r.HardwareType = hwType;
                    r.SensorType = GetStringProp(s, "SensorType");
                    r.Name = GetStringProp(s, "Name");
                    r.Value = Math.Round(Convert.ToDouble(v, System.Globalization.CultureInfo.InvariantCulture), 1);
                    readings.Add(r);
                }
                catch { }
            }
        }

        private static string GetStringProp(object o, string name)
        {
            try
            {
                PropertyInfo p = o.GetType().GetProperty(name);
                if (p == null) return null;
                object v = p.GetValue(o, null);
                return v == null ? null : v.ToString();
            }
            catch { return null; }
        }

        // Busca um sensor por tipo de hardware + tipo de sensor + padrao de nome.
        //
        // "Distance to TjMax" NAO e temperatura - e quantos graus faltam para o
        // limite termico. Ler isso como se fosse temperatura inverte o
        // diagnostico: uma CPU a 15 graus do limite (quente) apareceria como
        // "15 C" (fria). O filtro e obrigatorio em toda busca.
        public static double? Find(IList<SensorReading> readings, string hardwareTypeContains, string sensorType, string[] namePreferences)
        {
            if (readings == null) return null;

            if (namePreferences != null)
            {
                foreach (string pref in namePreferences)
                {
                    foreach (SensorReading r in readings)
                    {
                        if (!Matches(r, hardwareTypeContains, sensorType)) continue;
                        if (r.Name == null) continue;
                        if (r.Name.IndexOf("Distance", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                        if (r.Name.IndexOf(pref, StringComparison.OrdinalIgnoreCase) >= 0) return r.Value;
                    }
                }
            }

            foreach (SensorReading r in readings)
            {
                if (!Matches(r, hardwareTypeContains, sensorType)) continue;
                if (r.Name != null && r.Name.IndexOf("Distance", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                return r.Value;
            }
            return null;
        }

        private static bool Matches(SensorReading r, string hardwareTypeContains, string sensorType)
        {
            if (r.HardwareType == null || r.SensorType == null) return false;
            if (!string.Equals(r.SensorType, sensorType, StringComparison.OrdinalIgnoreCase)) return false;
            return r.HardwareType.IndexOf(hardwareTypeContains, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public void Dispose()
        {
            // Mesmo lock de Read(), para nao
            // fechar o Computer no meio de uma leitura de outra thread.
            lock (_sync)
            {
                if (!_open || _computer == null) return;
                try
                {
                    MethodInfo close = _computerType.GetMethod("Close", Type.EmptyTypes);
                    if (close != null) close.Invoke(_computer, null);
                }
                catch { }
                _open = false;
            }
        }
    }
}
