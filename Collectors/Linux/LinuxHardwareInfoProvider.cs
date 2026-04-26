// ============================================================
// RackWatch.Agent — Linux HardwareInfoProvider
// Uses dmidecode (requires root) + /etc/os-release + /proc/cpuinfo
// Falls back gracefully when dmidecode is unavailable (VMs/containers)
// ============================================================

using System.Diagnostics;
using RackWatch.Agent.Abstractions;
using RackWatch.Agent.Models;

namespace RackWatch.Agent.Collectors.Linux;

public class LinuxHardwareInfoProvider : IHardwareInfoProvider
{
    private readonly ILogger<LinuxHardwareInfoProvider> _logger;
    public LinuxHardwareInfoProvider(ILogger<LinuxHardwareInfoProvider> logger) => _logger = logger;

    public ServerProfile GetServerProfile()
    {
        var dmi = ReadDmiDecode();
        var os  = ReadOsRelease();

        return new ServerProfile
        {
            Hostname      = Environment.MachineName,
            Manufacturer  = dmi.GetValueOrDefault("System Manufacturer", "Unknown"),
            Model         = dmi.GetValueOrDefault("System Product Name", DetectVirtualPlatform()),
            SerialNumber  = dmi.GetValueOrDefault("System Serial Number", "Unknown"),
            OsName        = os.GetValueOrDefault("PRETTY_NAME", "Linux"),
            OsVersion     = os.GetValueOrDefault("VERSION_ID", ""),
            BiosDate      = ParseBiosDate(dmi.GetValueOrDefault("BIOS Release Date")),
            AgentVersion  = typeof(LinuxHardwareInfoProvider).Assembly
                                .GetName().Version?.ToString() ?? "unknown",
            ReportedAtUtc = DateTime.UtcNow
        };
    }

    // dmidecode parses the SMBIOS/DMI tables for hardware identity
    // Must run as root; gracefully returns empty dict if unavailable
    private Dictionary<string, string> ReadDmiDecode()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            // dmidecode type 0 = BIOS, type 1 = System info
            var output = RunCommand("dmidecode", "-t 0,1");

            string? currentKey = null;
            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.Contains(':'))
                {
                    var idx = trimmed.IndexOf(':');
                    currentKey = trimmed[..idx].Trim();
                    var val    = trimmed[(idx + 1)..].Trim();
                    if (val.Length > 0 && !val.Equals("Not Specified", StringComparison.OrdinalIgnoreCase))
                        result[currentKey] = val;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "dmidecode not available — using fallback hardware detection");
        }
        return result;
    }

    // /etc/os-release contains NAME, VERSION, PRETTY_NAME etc.
    private static Dictionary<string, string> ReadOsRelease()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var line in File.ReadAllLines("/etc/os-release"))
            {
                var parts = line.Split('=', 2);
                if (parts.Length == 2)
                    result[parts[0]] = parts[1].Trim('"', '\'');
            }
        }
        catch { }
        return result;
    }

    // Detect VM/cloud platforms when dmidecode is unavailable (containers, cloud VMs)
    private static string DetectVirtualPlatform()
    {
        // Check hypervisor from /proc/cpuinfo
        try
        {
            var cpuInfo = File.ReadAllText("/proc/cpuinfo");
            if (cpuInfo.Contains("hypervisor")) return "Virtual Machine";
        }
        catch { }

        // Cloud vendor detection via DMI product name files
        var checks = new[]
        {
            ("/sys/class/dmi/id/product_name",    (string?)null),
            ("/sys/class/dmi/id/sys_vendor",       null),
            ("/sys/class/dmi/id/board_vendor",     null),
        };

        foreach (var (path, _) in checks)
        {
            try
            {
                var content = File.ReadAllText(path).Trim().ToLower();
                if (content.Contains("vmware"))   return "VMware VM";
                if (content.Contains("virtualbox")) return "VirtualBox VM";
                if (content.Contains("kvm"))       return "KVM VM";
                if (content.Contains("amazon"))    return "AWS EC2";
                if (content.Contains("microsoft")) return "Azure VM / Hyper-V";
                if (content.Contains("google"))    return "GCP VM";
            }
            catch { }
        }

        // Bare metal fallback: read from /proc/cpuinfo model name
        try
        {
            var model = File.ReadLines("/proc/cpuinfo")
                .FirstOrDefault(l => l.StartsWith("model name"))
                ?.Split(':').Last().Trim();
            return model ?? "Physical Server";
        }
        catch { return "Physical Server"; }
    }

    private static DateTime? ParseBiosDate(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        return DateTime.TryParse(raw, out var d) ? d : null;
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
        proc.WaitForExit(TimeSpan.FromSeconds(5));
        return output;
    }
}
