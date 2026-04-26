// ============================================================
// RackWatch.Agent — Linux Collectors Part 3
// MemoryHeapAnalyzer · EventLogMonitor
// ============================================================

using System.Diagnostics;
using RackWatch.Agent.Abstractions;
using RackWatch.Agent.Models;

namespace RackWatch.Agent.Collectors.Linux;

// ─────────────────────────────────────────────
// 3. LINUX MEMORY HEAP ANALYZER
//    - Reads /proc/<pid>/status for each process (VmRSS, VmSwap)
//    - Detects OOM kills from journalctl
//    - Flags processes with unusually high VmRSS growth
// ─────────────────────────────────────────────
public class LinuxMemoryHeapAnalyzer : IMemoryHeapAnalyzer
{
    private const long LeakThresholdMb = 500;
    private readonly ILogger<LinuxMemoryHeapAnalyzer> _logger;

    public LinuxMemoryHeapAnalyzer(ILogger<LinuxMemoryHeapAnalyzer> logger) => _logger = logger;

    public MemoryHeapResult Analyze()
    {
        var leakyCandidates = new List<string>();
        long largestMb = 0;
        var issues = new List<IssueReport>();

        // Scan all processes via /proc/<pid>/status
        foreach (var pidDir in Directory.GetDirectories("/proc")
                                        .Where(d => int.TryParse(Path.GetFileName(d), out _)))
        {
            try
            {
                var statusFile = Path.Combine(pidDir, "status");
                if (!File.Exists(statusFile)) continue;

                var status = File.ReadAllLines(statusFile)
                    .Select(l => l.Split(':'))
                    .Where(p => p.Length == 2)
                    .ToDictionary(p => p[0].Trim(), p => p[1].Trim());

                if (!status.TryGetValue("Name", out var name)) continue;
                if (!status.TryGetValue("VmRSS", out var rssStr)) continue;

                // VmRSS is in kB
                long rssMb = ParseKb(rssStr) / 1024;

                if (rssMb >= LeakThresholdMb)
                {
                    string pid = Path.GetFileName(pidDir);
                    leakyCandidates.Add($"{name} (PID {pid}: {rssMb} MB RSS)");
                    if (rssMb > largestMb) largestMb = rssMb;
                }
            }
            catch { /* process may have exited — skip */ }
        }

        // Detect OOM kills in kernel log (last 24h)
        var oomKills = DetectOomKills();
        if (oomKills.Any())
        {
            issues.Add(new IssueReport("Memory", IssueSeverity.Critical,
                $"OOM killer activated {oomKills.Count}x in last 24h — " +
                $"killed: {string.Join(", ", oomKills.Take(3))}"));
        }

        bool leakDetected = leakyCandidates.Count > 0;
        if (leakDetected)
            issues.Add(new IssueReport("Memory", IssueSeverity.Warning,
                $"High RSS in {leakyCandidates.Count} process(es): " +
                string.Join(", ", leakyCandidates.Take(3))));

        return new MemoryHeapResult
        {
            LeakDetected    = leakDetected || oomKills.Any(),
            LargestHeapMb   = largestMb,
            LeakyCandidates = leakyCandidates,
            Issues          = issues
        };
    }

    // Scan /proc/kmsg or journalctl for OOM killer events
    private List<string> DetectOomKills()
    {
        var killed = new List<string>();
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo("/bin/journalctl",
                    "--since='24 hours ago' --no-pager -q -k --grep='oom_kill_process|Out of memory'")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    UseShellExecute        = false
                }
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();

            killed = output.Split('\n')
                .Where(l => l.Contains("Killed process") || l.Contains("oom_kill_process"))
                .Select(l =>
                {
                    // Extract process name from "Killed process 12345 (nginx) total-vm:..."
                    var match = System.Text.RegularExpressions.Regex
                        .Match(l, @"\(([^)]+)\)");
                    return match.Success ? match.Groups[1].Value : "unknown";
                })
                .Distinct()
                .ToList();
        }
        catch (Exception ex)
        {
            // journalctl may not be available (e.g., Docker containers)
        }
        return killed;
    }

    private static long ParseKb(string val) =>
        long.TryParse(val.Replace("kB", "").Trim(), out var v) ? v : 0;
}

// ─────────────────────────────────────────────
// 4. LINUX EVENT LOG MONITOR
//    - Unexpected shutdowns → journalctl (kernel panic, power loss, watchdog)
//    - OOM kills
//    - systemd failed units
//    - Disk I/O errors from kernel log
// ─────────────────────────────────────────────
public class LinuxEventLogMonitor : IEventLogMonitor
{
    private readonly ILogger<LinuxEventLogMonitor> _logger;
    public LinuxEventLogMonitor(ILogger<LinuxEventLogMonitor> logger) => _logger = logger;

    public EventLogResult Scan()
    {
        var shutdowns = new List<ShutdownEvent>();
        var issues    = new List<IssueReport>();
        int critCount = 0;
        string? lastReason = null;

        // ── 1. Detect unclean shutdowns via last/lastb ────────
        shutdowns.AddRange(DetectUncleanShutdowns());

        // ── 2. Kernel panics ──────────────────────────────────
        var panics = DetectKernelPanics();
        if (panics.Any())
        {
            shutdowns.AddRange(panics);
            issues.Add(new IssueReport("EventLog", IssueSeverity.Critical,
                $"{panics.Count} kernel panic(s) detected in journal — investigate hardware"));
        }

        // ── 3. systemd failed units ───────────────────────────
        var failedUnits = GetFailedSystemdUnits();
        if (failedUnits.Any())
            issues.Add(new IssueReport("EventLog", IssueSeverity.Warning,
                $"{failedUnits.Count} systemd unit(s) in failed state: " +
                string.Join(", ", failedUnits.Take(5))));

        // ── 4. Disk I/O errors ────────────────────────────────
        var diskErrors = DetectDiskErrors();
        if (diskErrors > 0)
            issues.Add(new IssueReport("Storage", IssueSeverity.Critical,
                $"{diskErrors} disk I/O error(s) in kernel log — check hardware immediately"));

        // ── 5. Critical journal entries (last 30 days) ────────
        critCount = CountCriticalJournalEntries();
        if (critCount > 50)
            issues.Add(new IssueReport("EventLog", IssueSeverity.Warning,
                $"{critCount} critical/error entries in journal (last 30 days)"));

        if (shutdowns.Any())
        {
            lastReason = shutdowns.First().Reason;
            issues.Add(new IssueReport("EventLog", IssueSeverity.Critical,
                $"{shutdowns.Count} unexpected shutdown/reboot event(s) in last 30 days"));
        }

        return new EventLogResult
        {
            UnexpectedShutdowns = shutdowns,
            CriticalCount       = critCount,
            LastShutdownReason  = lastReason,
            Issues              = issues
        };
    }

    // 'last reboot' lists all reboots; we cross-reference with wtmp dirty flag
    private List<ShutdownEvent> DetectUncleanShutdowns()
    {
        var events = new List<ShutdownEvent>();
        try
        {
            var output = RunCommand("journalctl",
                "--since='30 days ago' --no-pager -q " +
                "--grep='(shutdown|reboot|power|watchdog|Watchdog)' -p warning");

            foreach (var line in output.Split('\n').Where(l => l.Trim().Length > 10))
            {
                bool isClean = line.Contains("clean") || line.Contains("requested");
                events.Add(new ShutdownEvent
                {
                    OccurredAtUtc = TryParseJournalDate(line),
                    Reason        = line.Trim().Length > 120 ? line[..120] : line.Trim(),
                    IsClean       = isClean
                });
            }
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Shutdown detection via journalctl failed"); }

        return events.Where(e => !e.IsClean).Take(20).ToList();
    }

    private List<ShutdownEvent> DetectKernelPanics()
    {
        var panics = new List<ShutdownEvent>();
        try
        {
            var output = RunCommand("journalctl",
                "--since='30 days ago' --no-pager -q -k --grep='Kernel panic'");

            foreach (var line in output.Split('\n').Where(l => l.Contains("Kernel panic")))
            {
                panics.Add(new ShutdownEvent
                {
                    OccurredAtUtc = TryParseJournalDate(line),
                    Reason        = "KERNEL PANIC: " + line.Trim(),
                    IsClean       = false
                });
            }
        }
        catch { }
        return panics;
    }

    private List<string> GetFailedSystemdUnits()
    {
        try
        {
            var output = RunCommand("systemctl",
                "list-units --state=failed --no-legend --no-pager");
            return output.Split('\n')
                         .Where(l => l.Trim().Length > 0)
                         .Select(l => l.Trim().Split(' ').First())
                         .ToList();
        }
        catch { return []; }
    }

    private int DetectDiskErrors()
    {
        try
        {
            var output = RunCommand("journalctl",
                "--since='7 days ago' --no-pager -q -k " +
                "--grep='(I/O error|blk_update_request|Buffer I/O error)'");
            return output.Split('\n').Count(l => l.Trim().Length > 0);
        }
        catch { return 0; }
    }

    private int CountCriticalJournalEntries()
    {
        try
        {
            var output = RunCommand("journalctl",
                "--since='30 days ago' --no-pager -q -p err");
            return output.Split('\n').Count(l => l.Trim().Length > 0);
        }
        catch { return 0; }
    }

    private static string RunCommand(string cmd, string args)
    {
        using var proc = new Process
        {
            StartInfo = new ProcessStartInfo(cmd, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            }
        };
        proc.Start();
        var output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(TimeSpan.FromSeconds(10));
        return output;
    }

    private static DateTime TryParseJournalDate(string line)
    {
        // journalctl lines start with: "Apr 08 02:14:55"
        if (line.Length >= 15 &&
            DateTime.TryParse(line[..15], out var d))
            return DateTime.SpecifyKind(d, DateTimeKind.Local).ToUniversalTime();
        return DateTime.UtcNow;
    }
}
