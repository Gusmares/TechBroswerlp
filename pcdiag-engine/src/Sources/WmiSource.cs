using System;
using System.Collections.Generic;
using System.Management;

namespace PcDiag.Sources
{
    public sealed class WmiSource : IWmiSource
    {
        private readonly int _timeoutSeconds;

        public WmiSource(int timeoutSeconds)
        {
            _timeoutSeconds = timeoutSeconds < 1 ? 1 : timeoutSeconds;
        }

        public const string CimV2 = @"root\cimv2";
        public const string Wmi = @"root\wmi";
        public const string Storage = @"root\Microsoft\Windows\Storage";
        public const string Defender = @"root\Microsoft\Windows\Defender";
        public const string SecurityCenter = @"root\SecurityCenter2";

        public IList<DataRow> Query(string scope, string wql)
        {
            List<DataRow> rows = new List<DataRow>();

            ConnectionOptions conn = new ConnectionOptions();
            conn.Timeout = TimeSpan.FromSeconds(_timeoutSeconds);

            ManagementScope ms = new ManagementScope(scope, conn);
            ms.Connect();

            EnumerationOptions eo = new EnumerationOptions();
            eo.Timeout = TimeSpan.FromSeconds(_timeoutSeconds);
            eo.ReturnImmediately = true;
            eo.Rewindable = false;
            // Classes de storage/PnP podem ter instancias problematicas; nao
            // deixar uma instancia ruim derrubar a enumeracao inteira.
            eo.EnsureLocatable = false;

            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(ms, new ObjectQuery(wql), eo))
            using (ManagementObjectCollection results = searcher.Get())
            {
                foreach (ManagementBaseObject mo in results)
                {
                    using (mo)
                    {
                        DataRow row = new DataRow();
                        foreach (PropertyData p in mo.Properties)
                        {
                            object v;
                            try { v = p.Value; }
                            catch { continue; }
                            row.Set(p.Name, v);
                        }
                        rows.Add(row);
                    }
                }
            }

            return rows;
        }
    }
}
