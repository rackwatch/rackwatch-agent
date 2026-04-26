// ============================================================
// RackWatch.Agent — Windows Collectors
// Uses WMI · PerfCounters · Windows Update COM API
// Only compiled when targeting win-x64
// ============================================================

using System.Diagnostics;
using System.Management;
using RackWatch.Agent.Abstractions;
using RackWatch.Agent.Models;

namespace RackWatch.Agent.Collectors.Windows;

// ─────────────────────────────────────────────
// 1. METRICS — CPU · Memory · Temperature · Uptime
// ─────────────────────────────────────────────
public class WindowsMetricsCollector : IMetricsCollector
{
    private readonly PerformanceCounter _cpu =
        new("Processor", "% Processor Time", "_Total");

    public MetricsResult Collect()
    {
        _ = _cpu.NextValue();
        Thread.Sleep(500);
        float cpu = _cpu.NextValue();

        var mem = new MEMORYSTATUSEX();
        NativeMethods.GlobalMemoryStatusEx(mem);
        long totalMb = (long)(mem.ullTotalPhys / 1024 / 1024);
        long usedMb  = totalMb - (long)(mem.ullAvailPhys / 1024 / 1024);
        float memPct = totalMb > 0 ? (float)usedMb / totalMb * 100 : 0;

        float temp    = QueryCpuTemp();
        long  uptime  = Environment.TickCount64 / 1000;

        var issues = new List<IssueReport>();
        if (cpu > 85)
            issues.Add(new IssueReport("CPU", IssueSeverity.Warning,
                $"CPU utilization critical: {cpu:F1}%"));
        if (memPct > 90)
            issues.Add(new IssueReport("Memory", IssueSeverity.Critical,
                $"Memory utilization critical: {memPct:F1}%"));
        if (temp > 80)
            issues.Add(new IssueReport("Temperature", IssueSeverity.Warning,
                $"CPU temperature high: {temp:F0}°C"));

        return new MetricsResult
        {
            CpuPercent         = Math.Round(cpu, 1),
            MemoryPercent      = Math.Round(memPct, 1),
            MemoryTotalMb      = totalMb,
            MemoryUsedMb       = usedMb,
            TemperatureCelsius = temp,
            UptimeSeconds      = uptime,
            Issues             = issues
        };
    }

    private static float QueryCpuTemp()
    {
        try
        {
            using var s = new ManagementObjectSearcher(
                @"root\wmi", "SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature");
            foreach (var o in s.Get())
                return ((uint)o["CurrentTemperature"] - 2732) / 10f;
        }
        catch { }
        return 0;
    }
}

// ─────────────────────────────────────────────
// 2. PATCH SCANNER — Windows Update COM API
// ─────────────────────────────────────────────
public class WindowsPatchScanner : IPatchScanner
{
    private readonly ILogger<WindowsPatchScanner> _logger;
    public WindowsPatchScanner(ILogger<WindowsPatchScanner> logger) => _logger = logger;

    public Task<PatchResult> ScanAsync(CancellationToken ct = default)
        => Task.Run(() => Scan(), ct);

    private PatchResult Scan()
    {
        var missing   = new List<string>();
        DateTime? lastPatch = null;

        try
        {
            Type? t = Type.GetTypeFromProgID("Microsoft.Update.Session");
            if (t is null) return Empty();
            dynamic session = Activator.CreateInstance(t)!;

            // Last installed patch date
            dynamic hist = session.CreateUpdateSearcher();
            int total    = hist.GetTotalHistoryCount();
            if (total > 0)
            {
                dynamic history = hist.QueryHistory(0, Math.Min(total, 500));
                for (int i = 0; i < history.Count; i++)
                {
                    dynamic e = history.Item(i);
                    if (e.ResultCode == 2)
                    {
                        DateTime d = (DateTime)e.Date;
                        if (lastPatch == null || d > lastPatch) lastPatch = d;
                    }
                }
            }

            // Missing patches
            dynamic searcher = session.CreateUpdateSearcher();
            dynamic result   = searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0");
            for (int i = 0; i < result.Updates.Count; i++)
                missing.Add((string)result.Updates.Item(i).Title);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Windows Update API query failed");
        }

        int count   = missing.Count;
        float score = count == 0 ? 100 : Math.Max(0, 100 - count * 3.5f);

        var issues = new List<IssueReport>();
        if (count > 0)
            issues.Add(new IssueReport("Patches",
                count > 10 ? IssueSeverity.Critical : IssueSeverity.Warning,
                $"{count} security/update patches missing"));

        return new PatchResult
        {
            MissingCount    = count,
            MissingPatchIds = missing,
            LastPatchDate   = lastPatch,
            ComplianceScore = score,
            Issues          = issues
        };
    }

    private static PatchResult Empty() => new()
    {
        MissingCount = 0, MissingPatchIds = [], ComplianceScore = 100, Issues = []
    };
}

// ─────────────────────────────────────────────
// 3. STORAGE — DriveInfo + S.M.A.R.T. via WMI
// ─────────────────────────────────────────────
public class WindowsStorageAnalyzer : IStorageAnalyzer
{
    public StorageResult Analyze()
    {
        var volumes = new List<VolumeInfo>();
        var issues  = new List<IssueReport>();

        foreach (var d in DriveInfo.GetDrives().Where(d => d.IsReady))
        {
            float pct = d.TotalSize > 0
                ? (float)(d.TotalSize - d.AvailableFreeSpace) / d.TotalSize * 100 : 0;

            volumes.Add(new VolumeInfo
            {
                Label       = d.VolumeLabel,
                RootPath    = d.RootDirectory.FullName,
                TotalGb     = Math.Round(d.TotalSize / 1e9, 1),
                FreeGb      = Math.Round(d.AvailableFreeSpace / 1e9, 1),
                UsedPercent = Math.Round(pct, 1),
                DriveType   = d.DriveType.ToString()
            });

            if (pct > 95)
                issues.Add(new IssueReport("Storage", IssueSeverity.Critical,
                    $"Drive {d.Name} is {pct:F1}% full — IMMEDIATE ACTION"));
            else if (pct > 85)
                issues.Add(new IssueReport("Storage", IssueSeverity.Warning,
                    $"Drive {d.Name} is {pct:F1}% full — add capacity within 30 days"));
        }

        try
        {
            using var s = new ManagementObjectSearcher(
                @"root\wmi", "SELECT PredictFailure FROM MSStorageDriver_FailurePredictStatus");
            foreach (var o in s.Get())
                if ((bool)o["PredictFailure"])
                    issues.Add(new IssueReport("Storage", IssueSeverity.Critical,
                        "S.M.A.R.T. failure predicted — replace disk immediately"));
        }
        catch { }

        double overall = volumes.Any() ? volumes.Average(v => v.UsedPercent) : 0;
        return new StorageResult
        {
            Volumes        = volumes,
            OverallPercent = Math.Round(overall, 1),
            Issues         = issues
        };
    }
}

// ─────────────────────────────────────────────
// 4. MEMORY HEAP — Private bytes + .NET GC
// ─────────────────────────────────────────────
public class WindowsMemoryHeapAnalyzer : IMemoryHeapAnalyzer
{
    private const long ThresholdBytes = 500L * 1024 * 1024;

    public MemoryHeapResult Analyze()
    {
        var candidates = new List<string>();
        long largestMb = 0;

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                long priv = proc.PrivateMemorySize64;
                if (priv > ThresholdBytes)
                {
                    long mb = priv / 1024 / 1024;
                    candidates.Add($"{proc.ProcessName} ({mb} MB private)");
                    if (mb > largestMb) largestMb = mb;
                }
            }
            catch { }
        }

        var issues = new List<IssueReport>();
        if (candidates.Any())
            issues.Add(new IssueReport("Memory", IssueSeverity.Warning,
                $"High memory in {candidates.Count} process(es): " +
                string.Join(", ", candidates.Take(3))));

        return new MemoryHeapResult
        {
            LeakDetected    = candidates.Any(),
            LargestHeapMb   = largestMb,
            LeakyCandidates = candidates,
            Issues          = issues
        };
    }
}

// ─────────────────────────────────────────────
// 5. EVENT LOG — Unexpected shutdowns (IDs 41, 6008)
// ─────────────────────────────────────────────
public class WindowsEventLogMonitor : IEventLogMonitor
{
    public EventLogResult Scan()
    {
        var shutdowns = new List<ShutdownEvent>();
        var issues    = new List<IssueReport>();
        int critCount = 0;

        try
        {
            using var log = new EventLog("System");
            var recent = log.Entries.Cast<EventLogEntry>()
                .Where(e => e.TimeWritten > DateTime.UtcNow.AddDays(-30))
                .OrderByDescending(e => e.TimeWritten);

            foreach (var e in recent)
            {
                if (e.Source == "Microsoft-Windows-Kernel-Power" && e.InstanceId == 41)
                    shutdowns.Add(new ShutdownEvent
                    {
                        OccurredAtUtc = e.TimeWritten.ToUniversalTime(),
                        Reason        = "Kernel-Power: unexpected shutdown (ID 41)",
                        IsClean       = false
                    });
                else if (e.InstanceId == 6008)
                    shutdowns.Add(new ShutdownEvent
                    {
                        OccurredAtUtc = e.TimeWritten.ToUniversalTime(),
                        Reason        = "System: previous shutdown was unexpected (ID 6008)",
                        IsClean       = false
                    });

                if (e.EntryType is EventLogEntryType.Error or EventLogEntryType.FailureAudit)
                    critCount++;
            }

            if (shutdowns.Any())
                issues.Add(new IssueReport("EventLog", IssueSeverity.Critical,
                    $"{shutdowns.Count} unexpected shutdown(s) in last 30 days"));
            if (critCount > 100)
                issues.Add(new IssueReport("EventLog", IssueSeverity.Warning,
                    $"{critCount} error/failure events in last 30 days"));
        }
        catch (Exception ex)
        {
            issues.Add(new IssueReport("EventLog", IssueSeverity.Warning,
                $"Could not read System event log: {ex.Message}"));
        }

        return new EventLogResult
        {
            UnexpectedShutdowns = shutdowns,
            CriticalCount       = critCount,
            LastShutdownReason  = shutdowns.FirstOrDefault()?.Reason,
            Issues              = issues
        };
    }
}

// ─────────────────────────────────────────────
// 6. HARDWARE INFO — WMI Win32_ComputerSystem + BIOS
// ─────────────────────────────────────────────
public class WindowsHardwareInfoProvider : IHardwareInfoProvider
{
    public ServerProfile GetServerProfile()
    {
        string? manufacturer = null, model = null, serial = null, os = null, osVer = null;
        DateTime? biosDate = null;

        try
        {
            using var cs = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
            foreach (var o in cs.Get())
            {
                manufacturer = o["Manufacturer"]?.ToString();
                model        = o["Model"]?.ToString();
            }
            using var bios = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS");
            foreach (var o in bios.Get())
            {
                serial = o["SerialNumber"]?.ToString();
                if (o["ReleaseDate"] is string rd)
                    biosDate = ManagementDateTimeConverter.ToDateTime(rd);
            }
            using var osQ = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
            foreach (var o in osQ.Get())
            {
                os    = o["Caption"]?.ToString();
                osVer = o["Version"]?.ToString();
            }
        }
        catch { }

        return new ServerProfile
        {
            Hostname      = Environment.MachineName,
            Manufacturer  = manufacturer ?? "Unknown",
            Model         = model        ?? "Unknown",
            SerialNumber  = serial       ?? "Unknown",
            OsName        = os           ?? Environment.OSVersion.ToString(),
            OsVersion     = osVer        ?? "",
            BiosDate      = biosDate,
            ReportedAtUtc = DateTime.UtcNow
        };
    }
}

// ─────────────────────────────────────────────
// P/Invoke for GlobalMemoryStatusEx
// ─────────────────────────────────────────────
[System.Runtime.InteropServices.StructLayout(
    System.Runtime.InteropServices.LayoutKind.Sequential,
    CharSet = System.Runtime.InteropServices.CharSet.Auto)]
public class MEMORYSTATUSEX
{
    public uint  dwLength = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(MEMORYSTATUSEX));
    public uint  dwMemoryLoad;
    public ulong ullTotalPhys;
    public ulong ullAvailPhys;
    public ulong ullTotalPageFile;
    public ulong ullAvailPageFile;
    public ulong ullTotalVirtual;
    public ulong ullAvailVirtual;
    public ulong ullAvailExtendedVirtual;
}

public static class NativeMethods
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll",
        CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(
        System.Runtime.InteropServices.UnmanagedType.Bool)]
    public static extern bool GlobalMemoryStatusEx(
        [System.Runtime.InteropServices.In,
         System.Runtime.InteropServices.Out] MEMORYSTATUSEX lpBuffer);
}
