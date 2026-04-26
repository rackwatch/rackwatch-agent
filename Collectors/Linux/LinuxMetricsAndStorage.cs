// ============================================================
// RackWatch.Agent — Linux Collectors Part 1
// MetricsCollector · StorageAnalyzer
// Uses /proc, /sys, and standard Linux tooling — no WMI.
// ============================================================

using System.Diagnostics;
using RackWatch.Agent.Abstractions;
using RackWatch.Agent.Models;

namespace RackWatch.Agent.Collectors.Linux;

// ─────────────────────────────────────────────
// 1. LINUX METRICS COLLECTOR
//    CPU  → /proc/stat  (two reads, 200ms apart for delta)
//    Mem  → /proc/meminfo
//    Temp → /sys/class/thermal/thermal_zone*/temp
//    Up   → /proc/uptime
// ─────────────────────────────────────────────
public class LinuxMetricsCollector : IMetricsCollector
{
    private readonly ILogger<LinuxMetricsCollector> _logger;
    public LinuxMetricsCollector(ILogger<LinuxMetricsCollector> logger) => _logger = logger;

    public MetricsResult Collect()
    {
        var issues = new List<IssueReport>();

        double cpu   = ReadCpuPercent();
        var   mem    = ReadMemInfo();
        float temp   = ReadCpuTemperature();
        long  uptime = ReadUptimeSeconds();

        if (cpu > 85)
            issues.Add(new IssueReport("CPU", IssueSeverity.Warning,
                $"CPU utilization critical: {cpu:F1}%"));
        if (mem.usedPercent > 90)
            issues.Add(new IssueReport("Memory", IssueSeverity.Critical,
                $"Memory utilization critical: {mem.usedPercent:F1}%"));
        if (temp > 80)
            issues.Add(new IssueReport("Temperature", IssueSeverity.Warning,
                $"CPU temperature high: {temp:F0}°C"));

        return new MetricsResult
        {
            CpuPercent         = Math.Round(cpu, 1),
            MemoryPercent      = Math.Round(mem.usedPercent, 1),
            MemoryTotalMb      = mem.totalMb,
            MemoryUsedMb       = mem.usedMb,
            TemperatureCelsius = temp,
            UptimeSeconds      = uptime,
            Issues             = issues
        };
    }

    // /proc/stat — read two snapshots 200ms apart and compute delta
    private double ReadCpuPercent()
    {
        try
        {
            static long[] ParseStat()
            {
                var line = File.ReadLines("/proc/stat").First(l => l.StartsWith("cpu "));
                return line.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                           .Skip(1).Take(7).Select(long.Parse).ToArray();
            }

            var s1 = ParseStat();
            Thread.Sleep(200);
            var s2 = ParseStat();

            // fields: user nice system idle iowait irq softirq
            long idle1 = s1[3] + s1[4];
            long idle2 = s2[3] + s2[4];
            long total1 = s1.Sum();
            long total2 = s2.Sum();

            long deltaIdle  = idle2 - idle1;
            long deltaTotal = total2 - total1;

            return deltaTotal == 0 ? 0 : (1.0 - (double)deltaIdle / deltaTotal) * 100.0;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read /proc/stat");
            return 0;
        }
    }

    // /proc/meminfo — MemTotal, MemFree, Buffers, Cached
    private (long totalMb, long usedMb, double usedPercent) ReadMemInfo()
    {
        try
        {
            var info = File.ReadAllLines("/proc/meminfo")
                .Select(l => l.Split(':'))
                .Where(p => p.Length == 2)
                .ToDictionary(
                    p => p[0].Trim(),
                    p => long.Parse(p[1].Trim().Split(' ')[0])); // values in kB

            long totalKb    = info.GetValueOrDefault("MemTotal");
            long freeKb     = info.GetValueOrDefault("MemFree");
            long buffersKb  = info.GetValueOrDefault("Buffers");
            long cachedKb   = info.GetValueOrDefault("Cached") +
                              info.GetValueOrDefault("SReclaimable");

            long usedKb     = totalKb - freeKb - buffersKb - cachedKb;
            long totalMb    = totalKb / 1024;
            long usedMb     = usedKb  / 1024;
            double usedPct  = totalKb > 0 ? (double)usedKb / totalKb * 100 : 0;

            return (totalMb, usedMb, usedPct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read /proc/meminfo");
            return (0, 0, 0);
        }
    }

    // /sys/class/thermal — average across all zones (millidegrees → °C)
    private float ReadCpuTemperature()
    {
        try
        {
            var temps = Directory
                .GetFiles("/sys/class/thermal", "temp", SearchOption.AllDirectories)
                .Select(f =>
                {
                    if (long.TryParse(File.ReadAllText(f).Trim(), out var v))
                        return v / 1000f;  // millidegrees → °C
                    return 0f;
                })
                .Where(t => t > 0)
                .ToList();

            return temps.Any() ? temps.Max() : 0;
        }
        catch { return 0; }
    }

    // /proc/uptime — first field is uptime in seconds
    private long ReadUptimeSeconds()
    {
        try
        {
            var parts = File.ReadAllText("/proc/uptime").Trim().Split(' ');
            return double.TryParse(parts[0], out var v) ? (long)v : 0;
        }
        catch { return 0; }
    }
}

// ─────────────────────────────────────────────
// 2. LINUX STORAGE ANALYZER
//    Volumes  → DriveInfo (cross-platform in .NET)
//    SMART    → smartctl via subprocess (smartmontools)
// ─────────────────────────────────────────────
public class LinuxStorageAnalyzer : IStorageAnalyzer
{
    private readonly ILogger<LinuxStorageAnalyzer> _logger;
    public LinuxStorageAnalyzer(ILogger<LinuxStorageAnalyzer> logger) => _logger = logger;

    public StorageResult Analyze()
    {
        var volumes = new List<VolumeInfo>();
        var issues  = new List<IssueReport>();

        // DriveInfo works on Linux for mounted filesystems
        foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed))
        {
            // Skip pseudo-filesystems like tmpfs, proc, sysfs, devtmpfs
            if (IsPseudoFs(drive.DriveFormat)) continue;

            double usedPct = drive.TotalSize > 0
                ? (double)(drive.TotalSize - drive.AvailableFreeSpace) / drive.TotalSize * 100
                : 0;

            volumes.Add(new VolumeInfo
            {
                Label       = drive.VolumeLabel,
                RootPath    = drive.RootDirectory.FullName,
                TotalGb     = Math.Round(drive.TotalSize / 1e9, 1),
                FreeGb      = Math.Round(drive.AvailableFreeSpace / 1e9, 1),
                UsedPercent = Math.Round(usedPct, 1),
                DriveType   = drive.DriveFormat
            });

            if (usedPct > 95)
                issues.Add(new IssueReport("Storage", IssueSeverity.Critical,
                    $"Mount {drive.RootDirectory.FullName} is {usedPct:F1}% full — IMMEDIATE ACTION"));
            else if (usedPct > 85)
                issues.Add(new IssueReport("Storage", IssueSeverity.Warning,
                    $"Mount {drive.RootDirectory.FullName} is {usedPct:F1}% full — add capacity"));
        }

        // S.M.A.R.T. via smartctl (requires smartmontools package)
        RunSmartCheck(issues);

        double overall = volumes.Any() ? volumes.Average(v => v.UsedPercent) : 0;
        return new StorageResult { Volumes = volumes, OverallPercent = Math.Round(overall, 1), Issues = issues };
    }

    private void RunSmartCheck(List<IssueReport> issues)
    {
        try
        {
            // Find block devices
            var devices = Directory.GetFiles("/dev", "sd?")
                .Concat(Directory.GetFiles("/dev", "nvme?n?"))
                .ToList();

            foreach (var dev in devices)
            {
                var result = RunProcess("smartctl", $"-H {dev}");
                if (result.Contains("FAILED") || result.Contains("Prefailure"))
                    issues.Add(new IssueReport("Storage", IssueSeverity.Critical,
                        $"S.M.A.R.T. FAILURE on {dev} — replace disk immediately"));
                else if (result.Contains("OLD_AGE"))
                    issues.Add(new IssueReport("Storage", IssueSeverity.Warning,
                        $"S.M.A.R.T. OLD_AGE attribute on {dev} — disk aging, plan replacement"));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "smartctl not available or no drives found — skipping SMART check");
        }
    }

    private static string RunProcess(string cmd, string args)
    {
        using var proc = Process.Start(new ProcessStartInfo(cmd, args)
        {
            RedirectStandardOutput = true,
            UseShellExecute        = false,
            CreateNoWindow         = true
        });
        return proc?.StandardOutput.ReadToEnd() ?? "";
    }

    private static bool IsPseudoFs(string format) =>
        format is "tmpfs" or "proc" or "sysfs" or "devtmpfs" or "cgroup"
               or "cgroup2" or "pstore" or "securityfs" or "debugfs"
               or "hugetlbfs" or "mqueue" or "fusectl" or "overlay";
}
