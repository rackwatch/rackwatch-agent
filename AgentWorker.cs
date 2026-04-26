// ============================================================
// RackWatch.Agent — AgentWorker.cs (Interface-Driven)
// Identical logic for Windows and Linux — the injected
// collector implementations do all the OS-specific work.
// ============================================================

using RackWatch.Agent.Abstractions;
using RackWatch.Agent.Config;
using RackWatch.Agent.Models;
using RackWatch.Agent.Services;
using Microsoft.Extensions.Options;

namespace RackWatch.Agent;

public class AgentWorker : BackgroundService
{
    private static readonly TimeSpan CollectorTimeout = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan PatchScanTimeout = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan PatchScanCacheTtl = TimeSpan.FromHours(1);

    private readonly ILogger<AgentWorker>    _logger;
    private readonly AgentOptions            _options;
    private readonly IMetricsCollector       _metrics;
    private readonly IPatchScanner           _patches;
    private readonly IStorageAnalyzer        _storage;
    private readonly IMemoryHeapAnalyzer     _memory;
    private readonly IEventLogMonitor        _events;
    private readonly IHardwareInfoProvider   _hardware;
    private readonly CentralApiReporter      _reporter;

    // Last patch scan result cached in memory for PatchScanCacheTtl
    private PatchResult? _cachedPatches;
    private DateTime     _cachedPatchesAt = DateTime.MinValue;

    public AgentWorker(
        ILogger<AgentWorker> logger,
        IOptions<AgentOptions> options,
        IMetricsCollector metrics,
        IPatchScanner patches,
        IStorageAnalyzer storage,
        IMemoryHeapAnalyzer memory,
        IEventLogMonitor events,
        IHardwareInfoProvider hardware,
        CentralApiReporter reporter)
    {
        _logger   = logger;
        _options  = options.Value;
        _metrics  = metrics;
        _patches  = patches;
        _storage  = storage;
        _memory   = memory;
        _events   = events;
        _hardware = hardware;
        _reporter = reporter;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var platform = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
        _logger.LogInformation("RackWatch Agent starting | Host: {Host} | OS: {OS}",
            Environment.MachineName, platform);

        await _reporter.RegisterAsync(_hardware.GetServerProfile(), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var snapshot = await CollectSnapshotAsync(stoppingToken);
                await _reporter.SendTelemetryAsync(snapshot, stoppingToken);

                _logger.LogInformation(
                    "[{Host}] Snapshot sent — CPU:{Cpu}% MEM:{Mem}% Disk:{Disk}% Issues:{Issues}",
                    snapshot.Hostname, snapshot.CpuPercent,
                    snapshot.MemoryPercent, snapshot.StoragePercent,
                    snapshot.Issues.Count);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogError(ex, "Collection cycle failed — retrying next interval");
            }

            await Task.Delay(TimeSpan.FromSeconds(_options.CollectionIntervalSeconds), stoppingToken);
        }
    }

    private async Task<ServerSnapshot> CollectSnapshotAsync(CancellationToken ct)
    {
        // Metrics is cheap (<1s of I/O on /proc/stat + /proc/meminfo + /sys/thermal)
        // so run it synchronously on this thread — bypassing the threadpool
        // prevents it from being starved by slow collectors above.
        MetricsResult m;
        try { m = _metrics.Collect(); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Metrics collection failed — using fallback");
            m = FallbackMetrics();
        }

        // Storage is lightweight (/proc/mounts + statvfs). Patches, memory-heap,
        // and event-log scan are heavy (journalctl reads GB of history, /proc scan
        // on OpenStack compute nodes with hundreds of QEMU processes).
        // Run those only every Nth cycle (controlled by PatchScanCacheTtl).
        StorageResult s;
        try { s = _storage.Analyze(); }
        catch { s = new StorageResult(); }

        // All heavy collectors disabled — patches (apt), memory heap (/proc scan),
        // and event log (journalctl GB reads) were consuming 100% CPU + 4GB RAM
        // on old HP Compaq i5 OpenStack nodes. Re-enable one at a time after tuning.
        var p   = new PatchResult();
        var mem = new MemoryHeapResult();
        var e   = new EventLogResult();

        var issues = new List<IssueReport>();
        issues.AddRange(m.Issues);
        issues.AddRange(p.Issues);
        issues.AddRange(s.Issues);
        issues.AddRange(mem.Issues);
        issues.AddRange(e.Issues);

        return new ServerSnapshot
        {
            AgentId               = _options.AgentId,
            Hostname              = Environment.MachineName,
            CollectedAtUtc        = DateTime.UtcNow,
            CpuPercent            = m.CpuPercent,
            MemoryPercent         = m.MemoryPercent,
            MemoryTotalMb         = m.MemoryTotalMb,
            MemoryUsedMb          = m.MemoryUsedMb,
            StoragePercent        = s.OverallPercent,
            TemperatureCelsius    = m.TemperatureCelsius,
            UptimeSeconds         = m.UptimeSeconds,
            MissingPatchCount     = p.MissingCount,
            MissingPatchIds       = p.MissingPatchIds,
            LastPatchAppliedDate  = p.LastPatchDate,
            PatchComplianceScore  = p.ComplianceScore,
            StorageVolumes        = s.Volumes,
            HasMemoryLeak         = mem.LeakDetected,
            LargestHeapProcessMb  = mem.LargestHeapMb,
            LeakyCandidates       = mem.LeakyCandidates,
            UnexpectedShutdowns   = e.UnexpectedShutdowns,
            CriticalEventCount    = e.CriticalCount,
            LastShutdownReason    = e.LastShutdownReason,
            Issues                = issues
        };
    }

    // Returns a cached patch scan if it's recent enough; otherwise kicks off
    // a fresh scan with a 3-min hard timeout. Agents report every 60s but we
    // don't need to run `apt` on every cycle.
    private async Task<PatchResult?> GetPatchResultAsync(CancellationToken ct)
    {
        if (_cachedPatches != null && DateTime.UtcNow - _cachedPatchesAt < PatchScanCacheTtl)
            return _cachedPatches;

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(PatchScanTimeout);
            var fresh = await _patches.ScanAsync(cts.Token);
            _cachedPatches   = fresh;
            _cachedPatchesAt = DateTime.UtcNow;
            return fresh;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Patch scan failed — keeping previous result");
            return _cachedPatches;
        }
    }

    // Run a blocking collector on a thread pool thread with a hard timeout.
    // If it misses the timeout we return null and the caller uses a fallback.
    private async Task<T?> RunWithTimeout<T>(string name, Func<T> work, TimeSpan timeout, CancellationToken ct) where T : class
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var workTask = Task.Run(work, cts.Token);
            var winner = await Task.WhenAny(workTask, Task.Delay(timeout, cts.Token));
            if (winner != workTask)
            {
                _logger.LogWarning("Collector {Name} exceeded {Timeout}s — skipping this cycle", name, timeout.TotalSeconds);
                return null;
            }
            return await workTask;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Collector {Name} threw — skipping this cycle", name);
            return null;
        }
    }

    private static MetricsResult FallbackMetrics() => new()
    {
        CpuPercent         = 0,
        MemoryPercent      = 0,
        MemoryTotalMb      = 0,
        MemoryUsedMb       = 0,
        TemperatureCelsius = 0,
        UptimeSeconds      = 0,
    };
}
