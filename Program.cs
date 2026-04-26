// ============================================================
// RackWatch.Agent — Program.cs (Cross-Platform Entry Point)
// Detects OS at startup and registers the correct collectors.
// Runs as:
//   Windows → Windows Service  (sc create ...)
//   Linux   → systemd service  (see Deploy/rackwatch-agent.service)
// ============================================================

using System.Runtime.InteropServices;
using RackWatch.Agent;
using RackWatch.Agent.Abstractions;
#if WINDOWS_BUILD
using RackWatch.Agent.Collectors.Windows;
#else
using RackWatch.Agent.Collectors.Linux;
#endif
using RackWatch.Agent.Config;
using RackWatch.Agent.Services;

var builder = Host.CreateDefaultBuilder(args);

bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
bool isLinux   = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

// ── OS-specific service setup ────────────────────────────────
if (isWindows)
    builder.UseWindowsService(o => o.ServiceName = "RackWatch Agent");
else if (isLinux)
    builder.UseSystemd();   // Integrates with systemd watchdog + journal logging

builder.ConfigureServices((ctx, services) =>
{
    services.Configure<AgentOptions>(ctx.Configuration.GetSection("Agent"));

    // ── Register the correct collector implementations ────────
#if WINDOWS_BUILD
    if (isWindows)
    {
        services.AddSingleton<IMetricsCollector,    WindowsMetricsCollector>();
        services.AddSingleton<IPatchScanner,         WindowsPatchScanner>();
        services.AddSingleton<IStorageAnalyzer,      WindowsStorageAnalyzer>();
        services.AddSingleton<IMemoryHeapAnalyzer,   WindowsMemoryHeapAnalyzer>();
        services.AddSingleton<IEventLogMonitor,      WindowsEventLogMonitor>();
        services.AddSingleton<IHardwareInfoProvider, WindowsHardwareInfoProvider>();
    }
    else
    {
        throw new PlatformNotSupportedException(
            "This build targets Windows only. Rebuild with -r linux-x64 for Linux.");
    }
#else
    if (isLinux)
    {
        services.AddSingleton<IMetricsCollector,    LinuxMetricsCollector>();
        services.AddSingleton<IPatchScanner,         LinuxPatchScanner>();
        services.AddSingleton<IStorageAnalyzer,      LinuxStorageAnalyzer>();
        services.AddSingleton<IMemoryHeapAnalyzer,   LinuxMemoryHeapAnalyzer>();
        services.AddSingleton<IEventLogMonitor,      LinuxEventLogMonitor>();
        services.AddSingleton<IHardwareInfoProvider, LinuxHardwareInfoProvider>();
    }
    else
    {
        throw new PlatformNotSupportedException(
            "This build targets Linux only. Rebuild with -r win-x64 for Windows. " +
            "macOS agent support is on the roadmap.");
    }
#endif

    services.AddSingleton<CentralApiReporter>();
    services.AddHostedService<AgentWorker>();
})
.ConfigureLogging((ctx, logging) =>
{
    logging.ClearProviders();
    if (isWindows)
        logging.AddEventLog(s => { s.SourceName = "RackWatch Agent"; s.LogName = "Application"; });
    else
        logging.AddSystemdConsole();   // Structured journal output on Linux
    logging.AddConsole();
});

await builder.Build().RunAsync();
