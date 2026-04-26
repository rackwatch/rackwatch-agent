namespace RackWatch.Agent.Models;

public class ServerSnapshot
{
    public string    AgentId               { get; set; } = "";
    public string    Hostname              { get; set; } = "";
    public DateTime  CollectedAtUtc        { get; set; }
    public double    CpuPercent            { get; set; }
    public double    MemoryPercent         { get; set; }
    public long      MemoryTotalMb         { get; set; }
    public long      MemoryUsedMb          { get; set; }
    public double    StoragePercent        { get; set; }
    public float     TemperatureCelsius    { get; set; }
    public long      UptimeSeconds         { get; set; }
    public int       MissingPatchCount     { get; set; }
    public List<string> MissingPatchIds    { get; set; } = [];
    public DateTime? LastPatchAppliedDate  { get; set; }
    public float     PatchComplianceScore  { get; set; }
    public List<VolumeInfo> StorageVolumes { get; set; } = [];
    public bool      HasMemoryLeak         { get; set; }
    public long      LargestHeapProcessMb  { get; set; }
    public List<string> LeakyCandidates    { get; set; } = [];
    public List<ShutdownEvent> UnexpectedShutdowns { get; set; } = [];
    public int       CriticalEventCount    { get; set; }
    public string?   LastShutdownReason    { get; set; }
    public List<IssueReport> Issues        { get; set; } = [];
}

public class ServerProfile
{
    public string    Hostname      { get; set; } = "";
    public string    Manufacturer  { get; set; } = "";
    public string    Model         { get; set; } = "";
    public string    SerialNumber  { get; set; } = "";
    public string    OsName        { get; set; } = "";
    public string    OsVersion     { get; set; } = "";
    public DateTime? BiosDate      { get; set; }
    public string?   AgentVersion  { get; set; }
    public DateTime  ReportedAtUtc { get; set; }
}

public class IssueReport
{
    public IssueReport(string category, IssueSeverity severity, string message)
    {
        Category   = category;
        Severity   = severity;
        Message    = message;
        DetectedAt = DateTime.UtcNow;
    }
    public string        Category   { get; set; }
    public IssueSeverity Severity   { get; set; }
    public string        Message    { get; set; }
    public DateTime      DetectedAt { get; set; }
}

public enum IssueSeverity { Info, Warning, Critical }

public class VolumeInfo
{
    public string Label       { get; set; } = "";
    public string RootPath    { get; set; } = "";
    public double TotalGb     { get; set; }
    public double FreeGb      { get; set; }
    public double UsedPercent { get; set; }
    public string DriveType   { get; set; } = "";
}

public class ShutdownEvent
{
    public DateTime OccurredAtUtc { get; set; }
    public string   Reason        { get; set; } = "";
    public bool     IsClean       { get; set; }
}

// ── Collector result types ──────────────────────────────────

public record MetricsResult
{
    public double CpuPercent         { get; init; }
    public double MemoryPercent      { get; init; }
    public long   MemoryTotalMb      { get; init; }
    public long   MemoryUsedMb       { get; init; }
    public float  TemperatureCelsius { get; init; }
    public long   UptimeSeconds      { get; init; }
    public List<IssueReport> Issues  { get; init; } = [];
}

public record PatchResult
{
    public int           MissingCount    { get; init; }
    public List<string>  MissingPatchIds { get; init; } = [];
    public DateTime?     LastPatchDate   { get; init; }
    public float         ComplianceScore { get; init; }
    public List<IssueReport> Issues      { get; init; } = [];
}

public record StorageResult
{
    public List<VolumeInfo>  Volumes        { get; init; } = [];
    public double            OverallPercent { get; init; }
    public List<IssueReport> Issues         { get; init; } = [];
}

public record MemoryHeapResult
{
    public bool         LeakDetected    { get; init; }
    public long         LargestHeapMb   { get; init; }
    public List<string> LeakyCandidates { get; init; } = [];
    public List<IssueReport> Issues     { get; init; } = [];
}

public record EventLogResult
{
    public List<ShutdownEvent> UnexpectedShutdowns { get; init; } = [];
    public int                 CriticalCount        { get; init; }
    public string?             LastShutdownReason   { get; init; }
    public List<IssueReport>   Issues               { get; init; } = [];
}
