// ============================================================
// RackWatch.Agent — Linux Patch Scanner
// Supports: apt (Debian/Ubuntu) · dnf/yum (RHEL/CentOS/Rocky)
//           zypper (SUSE/openSUSE)
// Detects the package manager at runtime — no config needed.
// ============================================================

using System.Diagnostics;
using RackWatch.Agent.Abstractions;
using RackWatch.Agent.Models;

namespace RackWatch.Agent.Collectors.Linux;

public class LinuxPatchScanner : IPatchScanner
{
    private readonly ILogger<LinuxPatchScanner> _logger;
    public LinuxPatchScanner(ILogger<LinuxPatchScanner> logger) => _logger = logger;

    public async Task<PatchResult> ScanAsync(CancellationToken ct = default)
    {
        var pkgManager = DetectPackageManager();
        _logger.LogInformation("Patch scan using: {PkgMgr}", pkgManager);

        return pkgManager switch
        {
            PackageManager.Apt    => await ScanAptAsync(ct),
            PackageManager.Dnf    => await ScanDnfAsync(ct),
            PackageManager.Yum    => await ScanYumAsync(ct),
            PackageManager.Zypper => await ScanZypperAsync(ct),
            _                     => UnknownResult()
        };
    }

    // ── APT (Debian / Ubuntu) ─────────────────────────────────
    private async Task<PatchResult> ScanAptAsync(CancellationToken ct)
    {
        // Refresh package lists first (requires root — run agent as root or with sudo)
        await RunAsync("apt-get", "update -qq", ct);

        // List upgradable packages
        var output     = await RunAsync("apt-get", "--simulate --assume-yes upgrade", ct);
        var missing    = ParseAptUpgradable(output);
        var lastPatch  = ReadDpkgLastInstall();

        // Security-only count (grep security sources)
        var secOut     = await RunAsync("apt-get",
            "--simulate --assume-yes -o Dir::Etc::sourcelist=/dev/null " +
            "-o Dir::Etc::sourceparts=/dev/null " +
            "-o APT::Get::List-Cleanup=false upgrade", ct);
        // Simpler approach — just count all upgradable packages
        int secCount   = missing.Count(p => p.Contains("security", StringComparison.OrdinalIgnoreCase));

        return BuildResult(missing, lastPatch, secCount);
    }

    private static List<string> ParseAptUpgradable(string output)
    {
        // apt output lines like:  Inst libssl3 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04 ...)
        return output.Split('\n')
                     .Where(l => l.StartsWith("Inst "))
                     .Select(l => l.Split(' ').Skip(1).FirstOrDefault() ?? l)
                     .ToList();
    }

    private static DateTime? ReadDpkgLastInstall()
    {
        // /var/log/dpkg.log tracks all installs
        try
        {
            var log = "/var/log/dpkg.log";
            if (!File.Exists(log)) return null;

            var lastInstall = File.ReadLines(log)
                .LastOrDefault(l => l.Contains(" install ") || l.Contains(" upgrade "));

            if (lastInstall is null) return null;
            // Line format: "2025-03-15 14:22:01 install ..."
            return DateTime.TryParse(lastInstall[..10], out var d) ? d : null;
        }
        catch { return null; }
    }

    // ── DNF (RHEL 8+, CentOS 8+, Fedora, Rocky, AlmaLinux) ──
    private async Task<PatchResult> ScanDnfAsync(CancellationToken ct)
    {
        var output    = await RunAsync("dnf", "check-update --quiet 2>/dev/null || true", ct);
        var missing   = ParseDnfYumOutput(output);
        var lastPatch = await ReadRpmLastInstallAsync(ct);

        int secCount  = (await RunAsync("dnf", "updateinfo list security --quiet 2>/dev/null", ct))
                        .Split('\n').Count(l => l.Trim().Length > 0 && !l.StartsWith("Last"));

        return BuildResult(missing, lastPatch, secCount);
    }

    // ── YUM (RHEL 7, CentOS 7) ───────────────────────────────
    private async Task<PatchResult> ScanYumAsync(CancellationToken ct)
    {
        var output    = await RunAsync("yum", "check-update --quiet 2>/dev/null || true", ct);
        var missing   = ParseDnfYumOutput(output);
        var lastPatch = await ReadRpmLastInstallAsync(ct);

        int secCount  = (await RunAsync("yum", "list-security 2>/dev/null", ct))
                        .Split('\n').Count(l => l.Contains("RHSA") || l.Contains("CESA"));

        return BuildResult(missing, lastPatch, secCount);
    }

    private static List<string> ParseDnfYumOutput(string output)
    {
        // dnf/yum check-update output:
        // bash.x86_64   5.1.8-6.el9   baseos
        // (exit code 100 = updates available, 0 = up to date)
        return output.Split('\n')
                     .Where(l => l.Length > 0 && !l.StartsWith("Last") && char.IsLetter(l[0]))
                     .Select(l => l.Split(Array.Empty<char>(), StringSplitOptions.RemoveEmptyEntries)
                                   .FirstOrDefault() ?? l)
                     .ToList();
    }

    private async Task<DateTime?> ReadRpmLastInstallAsync(CancellationToken ct)
    {
        try
        {
            var out2 = await RunAsync("rpm",
                "-q --last kernel 2>/dev/null | head -1", ct);
            // Example: "kernel-5.14.0-362.8.1.el9.x86_64  Wed 13 Dec 2023 06:00:00"
            if (out2.Length > 40)
            {
                var datePart = string.Join(" ", out2.Split(' ').TakeLast(4));
                return DateTime.TryParse(datePart, out var d) ? d : null;
            }
        }
        catch { }
        return null;
    }

    // ── ZYPPER (SUSE / openSUSE) ─────────────────────────────
    private async Task<PatchResult> ScanZypperAsync(CancellationToken ct)
    {
        var output  = await RunAsync("zypper", "--non-interactive list-updates 2>/dev/null", ct);
        var missing = output.Split('\n')
                            .Where(l => l.StartsWith("v |") || l.StartsWith("| "))
                            .Select(l => l.Split('|').Skip(2).FirstOrDefault()?.Trim() ?? l)
                            .Where(l => l.Length > 0)
                            .ToList();

        // Last update from zypper history
        var hist = await RunAsync("zypper", "--non-interactive history 2>/dev/null | head -30", ct);
        DateTime? lastPatch = null;
        var dateToken = hist.Split('\n')
                            .FirstOrDefault(l => l.Contains("update") || l.Contains("install"));
        if (dateToken is not null)
            DateTime.TryParse(dateToken.Split('|').FirstOrDefault()?.Trim(), out var d);

        return BuildResult(missing, lastPatch, 0);
    }

    // ── Shared result builder ─────────────────────────────────
    private static PatchResult BuildResult(List<string> missing, DateTime? lastPatch, int secCount)
    {
        int count   = missing.Count;
        float score = count == 0 ? 100 : Math.Max(0, 100 - (count * 3.5f));

        var issues = new List<IssueReport>();
        if (secCount > 0)
            issues.Add(new IssueReport("Patches", IssueSeverity.Critical,
                $"{secCount} SECURITY patches missing — apply immediately"));
        else if (count > 10)
            issues.Add(new IssueReport("Patches", IssueSeverity.Warning,
                $"{count} updates pending — schedule maintenance window"));
        else if (count > 0)
            issues.Add(new IssueReport("Patches", IssueSeverity.Warning,
                $"{count} updates pending"));

        return new PatchResult
        {
            MissingCount    = count,
            MissingPatchIds = missing,
            LastPatchDate   = lastPatch,
            ComplianceScore = score,
            Issues          = issues
        };
    }

    private static PatchResult UnknownResult() => new()
    {
        MissingCount = -1, MissingPatchIds = [],
        ComplianceScore = 0,
        Issues = [new IssueReport("Patches", IssueSeverity.Warning,
            "Could not determine package manager — patch scan skipped")]
    };

    // ── Package manager detection ─────────────────────────────
    private static PackageManager DetectPackageManager()
    {
        if (File.Exists("/usr/bin/dnf") || File.Exists("/bin/dnf"))   return PackageManager.Dnf;
        if (File.Exists("/usr/bin/apt-get"))                           return PackageManager.Apt;
        if (File.Exists("/usr/bin/yum") || File.Exists("/bin/yum"))    return PackageManager.Yum;
        if (File.Exists("/usr/bin/zypper"))                            return PackageManager.Zypper;
        return PackageManager.Unknown;
    }

    // ── Shell helper ──────────────────────────────────────────
    private static async Task<string> RunAsync(string cmd, string args, CancellationToken ct)
    {
        using var proc = new Process
        {
            StartInfo = new ProcessStartInfo("/bin/bash", $"-c \"{cmd} {args}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            }
        };
        proc.Start();
        var output = await proc.StandardOutput.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct);
        return output;
    }

    private enum PackageManager { Unknown, Apt, Dnf, Yum, Zypper }
}
