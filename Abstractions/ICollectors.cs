using RackWatch.Agent.Models;

namespace RackWatch.Agent.Abstractions;

public interface IMetricsCollector      { MetricsResult Collect(); }
public interface IPatchScanner          { Task<PatchResult> ScanAsync(CancellationToken ct = default); }
public interface IStorageAnalyzer       { StorageResult Analyze(); }
public interface IMemoryHeapAnalyzer    { MemoryHeapResult Analyze(); }
public interface IEventLogMonitor       { EventLogResult Scan(); }
public interface IHardwareInfoProvider  { ServerProfile GetServerProfile(); }
