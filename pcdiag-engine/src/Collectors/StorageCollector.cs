using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;
using PcDiag.Core;
using PcDiag.Model;
using PcDiag.Sources;

namespace PcDiag.Collectors
{
    public sealed class StorageCollector : ICollector
    {
        public string Name { get { return "Storage"; } }

        public void Collect(ScanContext ctx, SourceSet src, Inventory inv)
        {
            CollectPhysicalDisks(ctx, src, inv);
            CollectVolumes(ctx, src, inv);
            MapVolumesToDisks(ctx, src, inv);
            CollectBitLocker(ctx, src, inv);
        }

        // ---------- discos fisicos ----------

        private void CollectPhysicalDisks(ScanContext ctx, SourceSet src, Inventory inv)
        {
            IList<DataRow> msft = Try.Get(ctx, Name, "MSFT_PhysicalDisk", delegate
            {
                return src.Wmi.Query(WmiSource.Storage,
                    "SELECT DeviceId, ObjectId, FriendlyName, SerialNumber, FirmwareVersion, Size, " +
                    "MediaType, BusType, HealthStatus, OperationalStatus FROM MSFT_PhysicalDisk");
            });

            IList<DataRow> legacy = Try.Get(ctx, Name, "Win32_DiskDrive", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT Index, Model, SerialNumber, FirmwareRevision, Size, InterfaceType, Status, MediaType, PNPDeviceID FROM Win32_DiskDrive");
            });

            if (msft != null && msft.Count > 0)
            {
                foreach (DataRow r in msft)
                {
                    DiskInfo d = new DiskInfo();
                    d.Index = Helpers.ParseIntSafe(r.Str("DeviceId"));
                    d.Model = r.Str("FriendlyName");
                    d.SerialNumber = SystemCollector.IsPlaceholder(r.Str("SerialNumber")) ? null : r.Str("SerialNumber");
                    d.FirmwareVersion = r.Str("FirmwareVersion");
                    d.SizeBytes = r.ULong("Size");
                    d.MediaType = MediaTypeName(r.Int("MediaType"));
                    d.MediaTypeSource = "MSFT_PhysicalDisk.MediaType";
                    d.BusType = BusTypeName(r.Int("BusType"));
                    d.HealthStatus = HealthStatusName(r.Int("HealthStatus"));
                    d.OperationalStatus = OperationalStatusName(r.Raw("OperationalStatus"));

                    CollectReliability(ctx, src, r.Str("ObjectId"), d);
                    inv.Disks.Add(d);
                }

                CrossCheckLegacy(ctx, inv, legacy);
            }
            else if (legacy != null && legacy.Count > 0)
            {
                // Fallback para maquina onde o namespace Storage nao responde.
                // O laudo registra que a fonte foi a antiga, que nao expoe
                // saude nem tipo de midia.
                foreach (DataRow r in legacy)
                {
                    DiskInfo d = new DiskInfo();
                    d.Index = r.Int("Index");
                    d.Model = r.Str("Model");
                    d.SerialNumber = SystemCollector.IsPlaceholder(r.Str("SerialNumber")) ? null : r.Str("SerialNumber");
                    d.FirmwareVersion = r.Str("FirmwareRevision");
                    d.SizeBytes = r.ULong("Size");
                    d.BusType = r.Str("InterfaceType");
                    d.OperationalStatus = r.Str("Status");
                    d.PnpDeviceId = r.Str("PNPDeviceID");
                    d.MediaTypeSource = "Win32_DiskDrive (namespace Storage indisponivel - tipo SSD/HDD nao determinavel)";
                    inv.Disks.Add(d);
                }
            }

            CollectLegacySmart(ctx, src, inv);
        }

        // Contadores de confiabilidade (wear, horas ligado, erros nao
        // corrigidos, temperatura). Exigem elevacao: sem admin a consulta e
        // negada, e isso precisa aparecer como REQUIRES_ADMIN no laudo - nunca
        // como "disco saudavel".
        private void CollectReliability(ScanContext ctx, SourceSet src, string objectId, DiskInfo d)
        {
            if (string.IsNullOrEmpty(objectId)) return;

            IList<DataRow> rel = Try.Get(ctx, Name, "MSFT_StorageReliabilityCounter", delegate
            {
                string wql = "ASSOCIATORS OF {MSFT_PhysicalDisk.ObjectId=\"" + EscapeWqlLiteral(objectId) + "\"} " +
                             "WHERE ResultClass = MSFT_StorageReliabilityCounter";
                return src.Wmi.Query(WmiSource.Storage, wql);
            });

            if (rel == null || rel.Count == 0) return;

            DataRow r = rel[0];

            // Alguns controladores devolvem 0 quando NAO suportam o
            // contador de desgaste - o mesmo padrao ja tratado abaixo para
            // Temperature. Sem a guarda, "0% de desgaste" (nao suportado)
            // seria indistinguivel de um SSD genuinamente zerado.
            int? wear = r.Int("Wear");
            if (wear.HasValue && wear.Value > 0 && wear.Value <= 100) d.WearPercent = wear;

            d.PowerOnHours = r.ULong("PowerOnHours");
            d.ReadErrorsUncorrected = r.ULong("ReadErrorsUncorrected");
            d.WriteErrorsUncorrected = r.ULong("WriteErrorsUncorrected");

            int? temp = r.Int("Temperature");
            // Muitos controladores devolvem 0 quando nao suportam o sensor.
            // Zero grau nao e uma temperatura plausivel para disco em uso.
            if (temp.HasValue && temp.Value > 0 && temp.Value < 120)
            {
                d.TemperatureC = temp.Value;
                d.TemperatureSource = "MSFT_StorageReliabilityCounter";
            }
            else if (temp.HasValue && temp.Value >= 120)
            {
                // Um valor >= 120C (NVMe em falha termica severa, ou
                // controlador com a escala em Kelvin) nao pode ser
                // simplesmente descartado - deixar TemperatureC null e
                // TemperatureSource vazio faria o laudo concluir "o contador
                // nao expos a temperatura", quando na verdade o controlador
                // respondeu um numero. Guarda o valor bruto rejeitado no
                // proprio TemperatureSource (sem campo novo no modelo) para
                // o laudo poder citar "o controlador informou X C" em vez de
                // alegar ausencia da fonte.
                d.TemperatureSource = "MSFT_StorageReliabilityCounter reportou " +
                    temp.Value.ToString(CultureInfo.InvariantCulture) +
                    "C - fora da faixa plausivel (>=120C), valor descartado e nao publicado como temperatura";
            }

            // MSFT_StorageReliabilityCounter precisa ser comparado com
            // HealthStatus - um disco com HealthStatus=Healthy e erros de
            // leitura/escrita NAO CORRIGIDOS (a evidencia mais dura que
            // existe de midia falhando) e uma contradicao que vale a pena
            // registrar, ja que as duas fontes vem do MESMO namespace de
            // storage.
            ulong readErrors = d.ReadErrorsUncorrected.HasValue ? d.ReadErrorsUncorrected.Value : 0;
            ulong writeErrors = d.WriteErrorsUncorrected.HasValue ? d.WriteErrorsUncorrected.Value : 0;
            if (d.HealthStatus == "Healthy" && (readErrors > 0 || writeErrors > 0))
            {
                ctx.AddInconsistency("Saude do disco " + (d.Model == null ? "?" : d.Model) + " x erros nao corrigidos",
                    "MSFT_PhysicalDisk.HealthStatus reporta Healthy, mas MSFT_StorageReliabilityCounter registra erros de leitura/escrita que o controlador nao conseguiu corrigir.",
                    Severity.High,
                    Evidence.Of("WMI", "MSFT_PhysicalDisk.HealthStatus", "Healthy"),
                    Evidence.Of("WMI", "MSFT_StorageReliabilityCounter.ReadErrorsUncorrected/WriteErrorsUncorrected",
                        readErrors + "/" + writeErrors));
            }
        }

        // WQL: aspas e barras invertidas dentro de literal precisam ser
        // escapadas. ObjectId de storage contem os dois.
        public static string EscapeWqlLiteral(string value)
        {
            if (value == null) return "";
            return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        private void CollectLegacySmart(ScanContext ctx, SourceSet src, Inventory inv)
        {
            IList<DataRow> pred = Try.Get(ctx, Name, "MSStorageDriver_FailurePredictStatus", delegate
            {
                return src.Wmi.Query(WmiSource.Wmi,
                    "SELECT InstanceName, PredictFailure, Reason FROM MSStorageDriver_FailurePredictStatus");
            });

            if (pred == null || pred.Count == 0)
            {
                // Ausencia aqui NAO significa disco bom. Registra a fonte como
                // indisponivel para que o teste correspondente reporte o motivo.
                foreach (DiskInfo d in inv.Disks)
                {
                    if (d.SmartSource == null)
                        d.SmartSource = ctx.IsElevated
                            ? "Nao exposto pelo driver do controlador (comum em NVMe e SATA antigos)"
                            : "Requer privilegio de Administrador";
                }
                return;
            }

            foreach (DataRow r in pred)
            {
                string instance = r.Str("InstanceName");
                bool? fail = r.Bool("PredictFailure");
                DiskInfo target = MatchDiskByInstanceName(inv.Disks, instance);
                if (target == null) continue;
                target.SmartPredictFailure = fail;
                target.SmartSource = "MSStorageDriver_FailurePredictStatus";
            }

            foreach (DiskInfo d in inv.Disks)
            {
                if (d.SmartSource == null)
                    d.SmartSource = "Disco nao reportado pelo provedor SMART legado (tipico de NVMe)";
            }
        }

        // InstanceName tem a forma "SCSI\Disk&Ven_...&Prod_...\4&xxxx&0&000000_0".
        //
        // O ultimo numero (o LUN) e por CONTROLADOR, nao global - um NVMe
        // (DeviceId 0, seu proprio controlador) e um SATA (DeviceId 1,
        // outro controlador) podem os dois ter InstanceName terminado em
        // "_0", porque cada um e o LUN 0 do SEU controlador. Casar so pelo
        // sufixo numerico atribuiria o SMART de um disco ao outro sempre
        // que essa colisao acontecesse. O casamento preferencial e por
        // PnpDeviceId (de Win32_DiskDrive), que e um PREFIXO real e estavel
        // do InstanceName - o sufixo numerico so entra como ultimo
        // recurso, quando nao ha PnpDeviceId disponivel para nenhum disco.
        public static DiskInfo MatchDiskByInstanceName(List<DiskInfo> disks, string instanceName)
        {
            if (disks == null || disks.Count == 0 || string.IsNullOrEmpty(instanceName)) return null;

            DiskInfo byPnp = MatchByPnpDeviceIdPrefix(disks, instanceName);
            if (byPnp != null) return byPnp;

            // Fallback pelo sufixo numerico so quando NENHUM disco tem
            // PnpDeviceId (WMI antiga, ou campo nao exposto) - com
            // PnpDeviceId disponivel, o casamento por sufixo fica desativado
            // porque e exatamente o que causa a colisao entre controladores.
            bool anyHasPnp = false;
            foreach (DiskInfo d in disks) if (!string.IsNullOrEmpty(d.PnpDeviceId)) { anyHasPnp = true; break; }
            if (anyHasPnp) return disks.Count == 1 ? disks[0] : null;

            Match m = Regex.Match(instanceName, @"_(\d+)\s*$");
            if (m.Success)
            {
                int idx;
                if (int.TryParse(m.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out idx))
                {
                    foreach (DiskInfo d in disks)
                    {
                        if (d.Index.HasValue && d.Index.Value == idx) return d;
                    }
                }
            }

            if (disks.Count == 1) return disks[0];
            return null;
        }

        // PnpDeviceId de Win32_DiskDrive ("SCSI\Disk&Ven_...&Prod_...\4&xxxx&0&000000")
        // e um prefixo do InstanceName de MSStorageDriver_FailurePredictStatus
        // ("SCSI\Disk&Ven_...&Prod_...\4&xxxx&0&000000_0") - so o LUN final
        // muda. Normaliza para maiusculas (WMI nao garante consistencia de
        // caixa entre provedores) antes de comparar.
        private static DiskInfo MatchByPnpDeviceIdPrefix(List<DiskInfo> disks, string instanceName)
        {
            string normalizedInstance = instanceName.ToUpperInvariant();
            DiskInfo match = null;
            int matches = 0;

            foreach (DiskInfo d in disks)
            {
                if (string.IsNullOrEmpty(d.PnpDeviceId)) continue;
                if (normalizedInstance.StartsWith(d.PnpDeviceId.ToUpperInvariant(), StringComparison.Ordinal))
                {
                    match = d;
                    matches++;
                }
            }

            // Se mais de um disco "casa" (nao deveria acontecer com prefixo
            // real, mas WQL/driver podem devolver algo inesperado), nao
            // arriscar atribuicao errada - melhor nao atribuir a nenhum.
            return matches == 1 ? match : null;
        }

        private void CrossCheckLegacy(ScanContext ctx, Inventory inv, IList<DataRow> legacy)
        {
            if (legacy == null || legacy.Count == 0) return;

            if (legacy.Count != inv.Disks.Count)
            {
                ctx.AddInconsistency("Quantidade de discos fisicos",
                    "MSFT_PhysicalDisk e Win32_DiskDrive reportam quantidades diferentes de discos.",
                    Severity.Medium,
                    Evidence.Of("WMI", "MSFT_PhysicalDisk (contagem)", inv.Disks.Count),
                    Evidence.Of("WMI", "Win32_DiskDrive (contagem)", legacy.Count));
            }

            foreach (DataRow r in legacy)
            {
                int? idx = r.Int("Index");
                if (!idx.HasValue) continue;

                foreach (DiskInfo d in inv.Disks)
                {
                    if (!d.Index.HasValue || d.Index.Value != idx.Value) continue;

                    string legacyStatus = r.Str("Status");
                    bool legacyOk = legacyStatus != null && string.Equals(legacyStatus, "OK", StringComparison.OrdinalIgnoreCase);

                    if (legacyStatus != null && !legacyOk && d.HealthStatus == "Healthy")
                    {
                        ctx.AddInconsistency("Saude do disco " + (d.Model == null ? idx.Value.ToString(CultureInfo.InvariantCulture) : d.Model),
                            "A camada de storage reporta o disco como saudavel, mas a classe legada reporta status diferente de OK.",
                            Severity.High,
                            Evidence.Of("WMI", "MSFT_PhysicalDisk.HealthStatus", "Healthy"),
                            Evidence.Of("WMI", "Win32_DiskDrive.Status", legacyStatus));
                    }
                    else if (legacyOk && d.HealthStatus == "Healthy")
                    {
                        // Prova real de que a segunda fonte
                        // (Win32_DiskDrive.Status) concordou com
                        // MSFT_PhysicalDisk.HealthStatus.
                        d.HealthConfirmedByLegacyStatus = true;
                    }

                    if (d.Model == null) d.Model = r.Str("Model");
                    if (d.SerialNumber == null && !SystemCollector.IsPlaceholder(r.Str("SerialNumber")))
                        d.SerialNumber = r.Str("SerialNumber");
                    d.PnpDeviceId = r.Str("PNPDeviceID");
                }
            }
        }

        // ---------- volumes ----------

        // A enumeracao primaria e Win32_Volume, que cobre letras, pontos de
        // montagem e volumes sem letra - Win32_LogicalDisk WHERE
        // DriveType=3 sozinho so lista volumes com letra atribuida, e um
        // volume montado em pasta (ex.: C:\Dados sem letra propria),
        // removivel, ou BitLocker ainda bloqueado (a letra so aparece apos
        // o desbloqueio) ficaria de fora do inventario. Win32_LogicalDisk
        // vira so enriquecimento/cross-check para os que tem letra.
        private void CollectVolumes(ScanContext ctx, SourceSet src, Inventory inv)
        {
            IList<DataRow> volumes = Try.Get(ctx, Name, "Win32_Volume", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT DriveLetter, Name, Label, FileSystem, Capacity, FreeSpace, DriveType, " +
                    "DirtyBitSet, BootVolume, SystemVolume, Compressed FROM Win32_Volume");
            });

            if (volumes == null || volumes.Count == 0)
            {
                // Fallback: maquina onde a classe Win32_Volume nao responde.
                // Cobre so volumes com letra, mas e melhor que nada.
                CollectVolumesFromLogicalDiskOnly(ctx, src, inv);
                MarkPageFileVolumes(inv);
                return;
            }

            foreach (DataRow r in volumes)
            {
                // DriveType 3 = disco fixo local. Filtra CD-ROM(5), removivel
                // sem ser disco fixo(2), rede(4) etc., mas mantem volumes
                // montados sem letra, que tambem sao DriveType 3.
                int? driveType = r.Int("DriveType");
                if (driveType.HasValue && driveType.Value != 3) continue;

                VolumeInfo v = new VolumeInfo();
                v.DriveLetter = Helpers.NormalizeDriveLetter(r.Str("DriveLetter"));

                string label = r.Str("Label");
                // Sem letra, usa o caminho de montagem (Name, ex.
                // "C:\Dados\") como rotulo, para o volume nao aparecer sem
                // identificacao nenhuma no laudo.
                v.Label = !string.IsNullOrEmpty(label) ? label : (v.DriveLetter == null ? r.Str("Name") : null);

                v.FileSystem = r.Str("FileSystem");
                v.SizeBytes = r.ULong("Capacity");
                v.FreeBytes = r.ULong("FreeSpace");
                if (v.SizeBytes.HasValue && v.SizeBytes.Value > 0 && v.FreeBytes.HasValue)
                    v.FreePercent = Math.Round((double)v.FreeBytes.Value / v.SizeBytes.Value * 100.0, 1);

                v.DirtyBit = r.Bool("DirtyBitSet");
                v.IsBootVolume = r.Bool("BootVolume");
                v.IsSystemVolume = r.Bool("SystemVolume");
                v.Compressed = r.Bool("Compressed");

                inv.Volumes.Add(v);
            }

            EnrichWithLogicalDisk(ctx, src, inv);
            MarkPageFileVolumes(inv);
        }

        private void CollectVolumesFromLogicalDiskOnly(ScanContext ctx, SourceSet src, Inventory inv)
        {
            IList<DataRow> logical = Try.Get(ctx, Name, "Win32_LogicalDisk", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT DeviceID, VolumeName, FileSystem, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3");
            });

            if (logical == null) return;

            foreach (DataRow r in logical)
            {
                VolumeInfo v = new VolumeInfo();
                v.DriveLetter = Helpers.NormalizeDriveLetter(r.Str("DeviceID"));
                v.Label = r.Str("VolumeName");
                v.FileSystem = r.Str("FileSystem");
                v.SizeBytes = r.ULong("Size");
                v.FreeBytes = r.ULong("FreeSpace");

                if (v.SizeBytes.HasValue && v.SizeBytes.Value > 0 && v.FreeBytes.HasValue)
                    v.FreePercent = Math.Round((double)v.FreeBytes.Value / v.SizeBytes.Value * 100.0, 1);

                inv.Volumes.Add(v);
            }
        }

        // Enriquecimento/cross-check pos-Win32_Volume: preenche so o que
        // ainda estiver faltando para volumes com letra (Win32_Volume as
        // vezes nao expoe FileSystem/Label num provedor mais antigo).
        private void EnrichWithLogicalDisk(ScanContext ctx, SourceSet src, Inventory inv)
        {
            IList<DataRow> logical = Try.Get(ctx, Name, "Win32_LogicalDisk", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2,
                    "SELECT DeviceID, VolumeName, FileSystem, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3");
            });

            if (logical == null) return;

            foreach (DataRow r in logical)
            {
                string letter = Helpers.NormalizeDriveLetter(r.Str("DeviceID"));
                if (letter == null) continue;

                foreach (VolumeInfo v in inv.Volumes)
                {
                    if (v.DriveLetter != letter) continue;
                    if (string.IsNullOrEmpty(v.FileSystem)) v.FileSystem = r.Str("FileSystem");
                    if (string.IsNullOrEmpty(v.Label)) v.Label = r.Str("VolumeName");
                    if (!v.SizeBytes.HasValue) v.SizeBytes = r.ULong("Size");
                    if (!v.FreeBytes.HasValue) v.FreeBytes = r.ULong("FreeSpace");
                }
            }
        }

        private void MarkPageFileVolumes(Inventory inv)
        {
            if (inv.Memory == null || inv.Memory.PageFileLocation == null) return;
            string loc = inv.Memory.PageFileLocation.ToUpperInvariant();

            foreach (VolumeInfo v in inv.Volumes)
            {
                if (v.DriveLetter == null) continue;
                v.HasPageFile = loc.IndexOf(v.DriveLetter, StringComparison.Ordinal) >= 0;
            }
        }

        // Mapeamento volume -> disco fisico. O coletor antigo nao tinha isso, e
        // por causa disso julgava a velocidade de um HD usando o limiar de SSD
        // sempre que existisse algum SSD na maquina.
        private void MapVolumesToDisks(ScanContext ctx, SourceSet src, Inventory inv)
        {
            IList<DataRow> partitions = Try.Get(ctx, Name, "Win32_DiskPartition", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2, "SELECT DeviceID, DiskIndex, BootPartition FROM Win32_DiskPartition");
            });

            IList<DataRow> links = Try.Get(ctx, Name, "Win32_LogicalDiskToPartition", delegate
            {
                return src.Wmi.Query(WmiSource.CimV2, "SELECT Antecedent, Dependent FROM Win32_LogicalDiskToPartition");
            });

            if (partitions == null || links == null) return;

            Dictionary<string, int> partitionToDisk = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (DataRow p in partitions)
            {
                string id = p.Str("DeviceID");
                int? diskIndex = p.Int("DiskIndex");
                if (id != null && diskIndex.HasValue) partitionToDisk[id] = diskIndex.Value;
            }

            foreach (DataRow link in links)
            {
                string partitionId = ExtractDeviceIdFromReference(link.Str("Antecedent"));
                string letter = Helpers.NormalizeDriveLetter(ExtractDeviceIdFromReference(link.Str("Dependent")));
                if (partitionId == null || letter == null) continue;

                int diskIndex;
                if (!partitionToDisk.TryGetValue(partitionId, out diskIndex)) continue;

                foreach (VolumeInfo v in inv.Volumes)
                {
                    if (v.DriveLetter == letter) v.PhysicalDiskIndex = diskIndex;
                }

                foreach (DiskInfo d in inv.Disks)
                {
                    if (d.Index.HasValue && d.Index.Value == diskIndex && !d.VolumeLetters.Contains(letter))
                        d.VolumeLetters.Add(letter);
                }
            }

            foreach (VolumeInfo v in inv.Volumes)
            {
                if (v.IsBootVolume != true || !v.PhysicalDiskIndex.HasValue) continue;
                foreach (DiskInfo d in inv.Disks)
                {
                    if (d.Index.HasValue && d.Index.Value == v.PhysicalDiskIndex.Value) d.IsBootDisk = true;
                }
            }
        }

        // A referencia vem como
        //   \\PC\root\cimv2:Win32_LogicalDisk.DeviceID="C:"
        // ou, dependendo do provedor, no formato abreviado
        //   Win32_LogicalDisk (DeviceID = "C:")
        private static readonly Regex DeviceIdRefRegex =
            new Regex("DeviceID\\s*=\\s*\"(?<id>[^\"]*)\"", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static string ExtractDeviceIdFromReference(string reference)
        {
            if (string.IsNullOrEmpty(reference)) return null;
            Match m = DeviceIdRefRegex.Match(reference);
            return m.Success ? m.Groups["id"].Value : null;
        }

        private void CollectBitLocker(ScanContext ctx, SourceSet src, Inventory inv)
        {
            // root\CIMV2\Security\MicrosoftVolumeEncryption tambem exige
            // elevacao - sem admin a consulta sempre falha, mas so depois
            // do custo total do handshake WMI/DCOM com o namespace de
            // seguranca. Medido em execucao real sem elevacao: modulo
            // Storage sozinho consumiu 5,15s dos 15,0s do orcamento padrao
            // do scan por causa desta e da consulta de confiabilidade,
            // ambas fadadas a falhar sem privilegio. Evita tocar na WMI
            // quando nao elevado.
            if (!ctx.IsElevated)
            {
                foreach (VolumeInfo v in inv.Volumes)
                {
                    v.BitLockerStatus = "NaoDeterminado";
                    v.BitLockerSource = "Requer privilegio de Administrador";
                }
                return;
            }

            IList<DataRow> bde = Try.Get(ctx, Name, "Win32_EncryptableVolume", delegate
            {
                return src.Wmi.Query(@"root\CIMV2\Security\MicrosoftVolumeEncryption",
                    "SELECT DriveLetter, ProtectionStatus, ConversionStatus FROM Win32_EncryptableVolume");
            });

            if (bde == null)
            {
                string reason = "Provedor de criptografia indisponivel (edicao do Windows pode nao suportar BitLocker)";
                foreach (VolumeInfo v in inv.Volumes)
                {
                    v.BitLockerStatus = "NaoDeterminado";
                    v.BitLockerSource = reason;
                }
                return;
            }

            // O provedor pode responder (bde != null) sem enumerar TODOS os
            // volumes - servico BDESVC parado para um volume especifico,
            // edicao que nao suporta BitLocker naquele volume, etc. O
            // padrao para cada volume e "NaoDeterminado"; so vira
            // "NaoCriptografado" quando o volume de fato aparece em bde com
            // ProtectionStatus=0 - tratar a ausencia no retorno do provedor
            // como "NaoCriptografado" afirmado seria um dado fabricado a
            // partir de silencio.
            foreach (VolumeInfo v in inv.Volumes)
            {
                v.BitLockerStatus = "NaoDeterminado";
                v.BitLockerSource = "Win32_EncryptableVolume nao reportou este volume";
            }

            foreach (DataRow r in bde)
            {
                string letter = Helpers.NormalizeDriveLetter(r.Str("DriveLetter"));
                if (letter == null) continue;
                int? prot = r.Int("ProtectionStatus");

                foreach (VolumeInfo v in inv.Volumes)
                {
                    if (v.DriveLetter != letter) continue;
                    v.BitLockerStatus = ProtectionStatusName(prot);
                    v.BitLockerSource = "Win32_EncryptableVolume";
                }
            }

            foreach (VolumeInfo v in inv.Volumes)
            {
                if (v.IsBootVolume == true) inv.Security.BitLockerSystemDrive = v.BitLockerStatus;
            }
        }

        // ---------- tabelas de traducao ----------

        public static string MediaTypeName(int? code)
        {
            if (!code.HasValue) return null;
            switch (code.Value)
            {
                case 0: return null;          // Unspecified: nao afirmar nada
                case 3: return "HDD";
                case 4: return "SSD";
                case 5: return "SCM";
                default: return null;
            }
        }

        public static string BusTypeName(int? code)
        {
            if (!code.HasValue) return null;
            switch (code.Value)
            {
                case 1: return "SCSI";
                case 2: return "ATAPI";
                case 3: return "ATA";
                case 4: return "IEEE 1394";
                case 5: return "SSA";
                case 6: return "Fibre Channel";
                case 7: return "USB";
                case 8: return "RAID";
                case 9: return "iSCSI";
                case 10: return "SAS";
                case 11: return "SATA";
                case 12: return "SD";
                case 13: return "MMC";
                case 15: return "Virtual";
                case 16: return "Storage Spaces";
                case 17: return "NVMe";
                case 18: return "SCM";
                case 19: return "UFS";
                default: return "Tipo " + code.Value;
            }
        }

        public static string HealthStatusName(int? code)
        {
            if (!code.HasValue) return null;
            switch (code.Value)
            {
                case 0: return "Healthy";
                case 1: return "Warning";
                case 2: return "Unhealthy";
                case 5: return "Unknown";
                default: return "Codigo " + code.Value;
            }
        }

        public static string OperationalStatusName(object raw)
        {
            if (raw == null) return null;

            List<int> codes = new List<int>();
            ushort[] us = raw as ushort[];
            if (us != null) foreach (ushort u in us) codes.Add(u);
            else
            {
                int[] ints = raw as int[];
                if (ints != null) codes.AddRange(ints);
                else
                {
                    try { codes.Add(Convert.ToInt32(raw, CultureInfo.InvariantCulture)); }
                    catch { return Convert.ToString(raw, CultureInfo.InvariantCulture); }
                }
            }

            List<string> names = new List<string>();
            foreach (int c in codes) names.Add(OperationalStatusCodeName(c));
            return string.Join(", ", names.ToArray());
        }

        private static string OperationalStatusCodeName(int code)
        {
            switch (code)
            {
                case 0: return "Unknown";
                case 1: return "Other";
                case 2: return "OK";
                case 3: return "Degraded";
                case 4: return "Stressed";
                case 5: return "Predictive Failure";
                case 6: return "Error";
                case 7: return "Non-Recoverable Error";
                case 8: return "Starting";
                case 9: return "Stopping";
                case 10: return "Stopped";
                case 11: return "In Service";
                case 12: return "No Contact";
                case 13: return "Lost Communication";
                case 15: return "Dormant";
                case 0xD010: return "Unrecognized Metadata";
                default: return "Codigo " + code;
            }
        }

        public static string ProtectionStatusName(int? code)
        {
            if (!code.HasValue) return "NaoDeterminado";
            switch (code.Value)
            {
                case 0: return "NaoCriptografado";
                case 1: return "Criptografado";
                case 2: return "CriptografadoSemProtecao";
                default: return "Codigo " + code.Value;
            }
        }
    }
}
