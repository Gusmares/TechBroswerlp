using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Principal;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    // Inventario de software, servicos e itens de inicializacao.
    //
    // Nao usa Win32_Product: essa classe dispara uma reconfiguracao MSI de
    // cada pacote instalado ao ser consultada, o que e lento e pode alterar o
    // estado da maquina do cliente. As chaves de desinstalacao do registro dao
    // a mesma informacao sem efeito colateral.
    public sealed class SoftwareCollector : ICollector
    {
        public string Name { get { return "Software"; } }

        private const string Uninstall64 = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        private const string Uninstall32 = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            CollectFromUninstallKey(ctx, src, inv, "HKLM", Uninstall64, "Uninstall64", "64 bits");
            CollectFromUninstallKey(ctx, src, inv, "HKLM", Uninstall32, "Uninstall32", "32 bits");
            CollectFromUninstallKey(ctx, src, inv, "HKCU", Uninstall64, "UninstallUser", null);

            CollectServices(ctx, src, inv);
            CollectStartup(ctx, src, inv);
        }

        private void CollectFromUninstallKey(ScanContext ctx, SourceSet src, Inventory inv,
            string hive, string path, string source, string architecture)
        {
            foreach (string sub in RegistryWalk.SubKeysSafe(src.Registry, hive, path))
            {
                string full = path + "\\" + sub;

                string display = AsString(RegistryWalk.ValueSafe(src.Registry, hive, full, "DisplayName"));
                if (display == null) continue;

                // Atualizacoes e componentes de sistema poluem o inventario e
                // nao interessam ao laudo.
                object systemComponent = RegistryWalk.ValueSafe(src.Registry, hive, full, "SystemComponent");
                if (systemComponent != null && ToInt(systemComponent) == 1) continue;
                if (RegistryWalk.ValueSafe(src.Registry, hive, full, "ParentKeyName") != null) continue;

                SoftwareInfo s = new SoftwareInfo();
                s.Name = display;
                s.Publisher = AsString(RegistryWalk.ValueSafe(src.Registry, hive, full, "Publisher"));
                s.Version = AsString(RegistryWalk.ValueSafe(src.Registry, hive, full, "DisplayVersion"));
                s.InstallLocation = AsString(RegistryWalk.ValueSafe(src.Registry, hive, full, "InstallLocation"));
                s.Architecture = architecture;
                s.Source = source;
                s.InstallDate = ParseInstallDate(AsString(RegistryWalk.ValueSafe(src.Registry, hive, full, "InstallDate")));
                s.Category = Categorize(s.Name, s.Publisher);

                if (!AlreadyPresent(inv.Software, s)) inv.Software.Add(s);
            }
        }

        private static bool AlreadyPresent(List<SoftwareInfo> list, SoftwareInfo candidate)
        {
            foreach (SoftwareInfo s in list)
            {
                if (string.Equals(s.Name, candidate.Name, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(s.Version, candidate.Version, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        // Formato do registro: "yyyyMMdd".
        public static DateTime? ParseInstallDate(string raw)
        {
            if (string.IsNullOrEmpty(raw) || raw.Length != 8) return null;
            DateTime d;
            if (DateTime.TryParseExact(raw, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out d)) return d;
            return null;
        }

        // Categorias uteis ao tecnico: runtime faltando, navegador desatualizado,
        // ferramenta de acesso remoto instalada sem o cliente saber, etc.
        public static string Categorize(string name, string publisher)
        {
            string n = ((name == null ? "" : name) + " " + (publisher == null ? "" : publisher)).ToLowerInvariant();

            string[][] rules = new string[][]
            {
                new string[] { "office", "Office" },
                new string[] { "microsoft 365", "Office" },
                new string[] { "visual c++", "Runtime" },
                new string[] { ".net", "Runtime" },
                new string[] { "java", "Runtime" },
                new string[] { "python", "Runtime" },
                new string[] { "node.js", "Runtime" },
                new string[] { "directx", "Runtime" },
                new string[] { "chrome", "Browser" },
                new string[] { "firefox", "Browser" },
                new string[] { "edge", "Browser" },
                new string[] { "opera", "Browser" },
                new string[] { "brave", "Browser" },
                new string[] { "anydesk", "RemoteAccess" },
                new string[] { "teamviewer", "RemoteAccess" },
                new string[] { "rustdesk", "RemoteAccess" },
                new string[] { "ammyy", "RemoteAccess" },
                new string[] { "supremo", "RemoteAccess" },
                new string[] { "logmein", "RemoteAccess" },
                new string[] { "vnc", "RemoteAccess" },
                new string[] { "openvpn", "Vpn" },
                new string[] { "wireguard", "Vpn" },
                new string[] { "nordvpn", "Vpn" },
                new string[] { "expressvpn", "Vpn" },
                new string[] { "vmware", "Virtualization" },
                new string[] { "virtualbox", "Virtualization" },
                new string[] { "hyper-v", "Virtualization" },
                new string[] { "avast", "Security" },
                new string[] { "avg ", "Security" },
                new string[] { "kaspersky", "Security" },
                new string[] { "mcafee", "Security" },
                new string[] { "norton", "Security" },
                new string[] { "bitdefender", "Security" },
                new string[] { "eset", "Security" },
                new string[] { "malwarebytes", "Security" }
            };

            foreach (string[] rule in rules)
            {
                if (n.IndexOf(rule[0], StringComparison.Ordinal) >= 0) return rule[1];
            }

            return "Other";
        }

        private void CollectServices(ScanContext ctx, SourceSet src, Inventory inv)
        {
            IList<DataRow> rows = Try.Get(ctx, Name, "Win32_Service", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT Name, DisplayName, State, StartMode, StartName, PathName, ProcessId FROM Win32_Service");
            });

            if (rows == null) return;

            foreach (DataRow r in rows)
            {
                ServiceInfo s = new ServiceInfo();
                s.Name = r.Str("Name");
                s.DisplayName = r.Str("DisplayName");
                s.State = r.Str("State");
                s.StartMode = r.Str("StartMode");
                s.Account = r.Str("StartName");

                string pathName = r.Str("PathName");
                s.ExecutablePath = Helpers.ExtractExecutablePath(pathName);

                int? pid = r.Int("ProcessId");
                if (pid.HasValue && pid.Value > 0) s.ProcessId = pid.Value;

                if (s.ExecutablePath != null)
                {
                    // Binario ausente e um defeito concreto: o servico nunca
                    // vai iniciar. Se nao der para verificar (acesso negado),
                    // fica null em vez de false.
                    s.BinaryExists = Try.Get<bool?>(ctx, Name, "File.Exists(" + s.Name + ")", delegate
                    {
                        return File.Exists(Environment.ExpandEnvironmentVariables(s.ExecutablePath));
                    });

                    s.IsInUnusualLocation = Helpers.IsUnusualExecutableLocation(s.ExecutablePath);
                }

                inv.Services.Add(s);
            }
        }

        private void CollectStartup(ScanContext ctx, SourceSet src, Inventory inv)
        {
            CollectRunKey(ctx, src, inv, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run", "Machine");
            CollectRunKey(ctx, src, inv, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce", "Machine");
            CollectRunKey(ctx, src, inv, "HKLM", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Run (32 bits)", "Machine");
            CollectRunKey(ctx, src, inv, "HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run", "User");
            CollectRunKey(ctx, src, inv, "HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce", "User");

            // HKCU so cobre o usuario que RODOU o scan (mesmo elevado por
            // UAC, o processo continua na sessao desse usuario). Outra
            // conta com sessao carregada ao mesmo tempo (fast user
            // switching, RDP concorrente) tem o proprio Run/RunOnce em
            // HKEY_USERS\<SID>\..., por isso tambem precisa ser coberta. So
            // cobre hives CARREGADOS: um perfil totalmente deslogado nao
            // tem hive em HKU e continua fora do alcance sem montar o
            // NTUSER.DAT manualmente (RegLoadKey), o que fica fora do
            // escopo deste coletor.
            foreach (string sid in OtherLoadedUserSids(src))
            {
                CollectRunKey(ctx, src, inv, "HKU", sid + @"\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run", "User (" + sid + ")");
                CollectRunKey(ctx, src, inv, "HKU", sid + @"\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce", "User (" + sid + ")");
            }

            CollectStartupFolder(ctx, inv, Environment.GetFolderPath(Environment.SpecialFolder.Startup), "User");
            CollectStartupFolder(ctx, inv, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Machine");

            CheckWinlogon(ctx, src, inv);
        }

        // SIDs de conta de usuario real (S-1-5-21-...) com hive carregado em
        // HKEY_USERS agora, exceto a conta que rodou o scan (ja coberta via
        // HKCU acima - listar de novo duplicaria os mesmos itens).
        private static IEnumerable<string> OtherLoadedUserSids(SourceSet src)
        {
            List<string> result = new List<string>();
            string currentSid = null;
            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    if (id.User != null) currentSid = id.User.Value;
                }
            }
            catch { }

            foreach (string sid in RegistryWalk.SubKeysSafe(src.Registry, "HKU", ""))
            {
                if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;
                if (currentSid != null && string.Equals(sid, currentSid, StringComparison.OrdinalIgnoreCase)) continue;
                result.Add(sid);
            }
            return result;
        }

        private void CollectRunKey(ScanContext ctx, SourceSet src, Inventory inv,
            string hive, string path, string location, string scope)
        {
            IList<string> names;
            try { names = src.Registry.GetValueNames(hive, path); }
            catch (Exception ex)
            {
                ctx.Log.Warn(Name, "Nao foi possivel ler " + hive + "\\" + path + ": " + ex.Message);

                // Sem isto, a falha iria so para o log tecnico - o laudo
                // entregue ao cliente ficaria sem nenhum sinal de que esta
                // origem de inicializacao automatica nao pode ser lida, e
                // SEC-007 poderia concluir "nenhum item de inicializacao
                // encontrado" com confianca alta mesmo quando a leitura
                // falhou (nao quando a chave estava genuinamente vazia). Sem
                // um campo dedicado no modelo para status de leitura por
                // origem, a inconsistencia visivel no laudo e o jeito
                // disponivel de nao deixar essa falha desaparecer.
                ctx.AddInconsistency("Leitura de item de inicializacao (" + location + ", " + scope + ")",
                    "Nao foi possivel ler " + hive + "\\" + path + " (" + ex.GetType().Name + ": " + ex.Message + "). " +
                    "A ausencia de itens desta origem no inventario NAO significa que a chave esta vazia - a leitura falhou.",
                    Severity.Low,
                    Evidence.Of("Registry", hive + "\\" + path, "leitura falhou"));
                return;
            }

            foreach (string valueName in names)
            {
                string command = AsString(RegistryWalk.ValueSafe(src.Registry, hive, path, valueName));
                if (command == null) continue;

                StartupItem item = new StartupItem();
                item.Name = valueName;
                item.Command = command;
                item.Location = location;
                item.Scope = scope;

                string exe = Helpers.ExtractExecutablePath(command);
                item.IsInUnusualLocation = Helpers.IsUnusualExecutableLocation(exe);
                item.TargetExists = Try.Get<bool?>(ctx, Name, "startup target", delegate
                {
                    return File.Exists(Environment.ExpandEnvironmentVariables(exe));
                });

                inv.Startup.Add(item);
            }
        }

        private void CollectStartupFolder(ScanContext ctx, Inventory inv, string folder, string scope)
        {
            if (string.IsNullOrEmpty(folder)) return;

            bool ok = Try.Do(ctx, Name, "pasta de inicializacao " + scope, delegate
            {
                if (!Directory.Exists(folder)) return;

                foreach (string file in Directory.GetFiles(folder))
                {
                    string fileName = Path.GetFileName(file);
                    if (string.Equals(fileName, "desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;

                    StartupItem item = new StartupItem();
                    item.Name = fileName;
                    item.Command = file;
                    item.Location = "Pasta de Inicializacao";
                    item.Scope = scope;
                    item.TargetExists = true;
                    item.IsInUnusualLocation = false;
                    inv.Startup.Add(item);
                }
            });

            // Mesma logica de CollectRunKey acima - Try.Do ja loga a falha
            // no arquivo tecnico, mas sem isto o laudo nao teria nenhum
            // sinal de que a pasta de inicializacao nao pode ser listada
            // (ex.: ACL negada), e ficaria indistinguivel de "pasta vazia".
            if (!ok)
            {
                ctx.AddInconsistency("Leitura da pasta de inicializacao (" + scope + ")",
                    "Nao foi possivel listar o conteudo de " + folder + ". A ausencia de itens desta origem no inventario NAO significa que a pasta esta vazia - a leitura falhou.",
                    Severity.Low,
                    Evidence.Of("FileSystem", folder, "leitura falhou"));
            }
        }

        // Winlogon\Shell e Userinit sao pontos classicos de persistencia. O
        // valor esperado e conhecido; qualquer coisa alem disso e um achado
        // que merece verificacao manual - e reportado como tal, nunca como
        // acusacao de malware.
        private void CheckWinlogon(ScanContext ctx, SourceSet src, Inventory inv)
        {
            const string path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

            string shell = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", path, "Shell"));
            if (shell != null && !string.Equals(shell.Trim(), "explorer.exe", StringComparison.OrdinalIgnoreCase))
            {
                StartupItem item = new StartupItem();
                item.Name = "Winlogon\\Shell";
                item.Command = shell;
                item.Location = "Winlogon";
                item.Scope = "Machine";
                item.IsInUnusualLocation = true;
                inv.Startup.Add(item);
            }

            string userinit = AsString(RegistryWalk.ValueSafe(src.Registry, "HKLM", path, "Userinit"));
            if (userinit != null)
            {
                string normalized = userinit.Trim().TrimEnd(',').ToLowerInvariant();
                bool expected = normalized.EndsWith("\\userinit.exe", StringComparison.Ordinal) ||
                                normalized == "userinit.exe";
                if (!expected)
                {
                    StartupItem item = new StartupItem();
                    item.Name = "Winlogon\\Userinit";
                    item.Command = userinit;
                    item.Location = "Winlogon";
                    item.Scope = "Machine";
                    item.IsInUnusualLocation = true;
                    inv.Startup.Add(item);
                }
            }
        }

        private static string AsString(object v)
        {
            if (v == null) return null;
            string s = Convert.ToString(v, CultureInfo.InvariantCulture);
            if (s == null) return null;
            s = s.Trim();
            return s.Length == 0 ? null : s;
        }

        private static int ToInt(object v)
        {
            try { return Convert.ToInt32(v, CultureInfo.InvariantCulture); }
            catch { return 0; }
        }
    }
}
