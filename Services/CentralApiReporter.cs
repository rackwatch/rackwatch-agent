using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using RackWatch.Agent.Config;
using RackWatch.Agent.Models;
using Microsoft.Extensions.Options;

namespace RackWatch.Agent.Services;

public class CentralApiReporter
{
    // The Platform's DTOs use string-typed Severity (e.g. "Critical"),
    // but our enum IssueSeverity serializes as int (0/1/2) by default.
    // Force camelCase + string enums so the Platform accepts our payloads.
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient  _http;
    private readonly AgentOptions _options;
    private readonly ILogger<CentralApiReporter> _logger;

    public CentralApiReporter(IOptions<AgentOptions> opts, ILogger<CentralApiReporter> logger)
    {
        _options = opts.Value;
        _logger  = logger;
        _http    = new HttpClient
        {
            BaseAddress = new Uri(_options.PlatformUrl),
            Timeout     = TimeSpan.FromSeconds(30)
        };
        _http.DefaultRequestHeaders.Add("X-Agent-Key", _options.AgentApiKey);
    }

    public async Task RegisterAsync(ServerProfile profile, CancellationToken ct)
    {
        try
        {
            var resp = await _http.PostAsJsonAsync("/api/agents/register", profile, Json, ct);
            resp.EnsureSuccessStatusCode();
            _logger.LogInformation("Agent registered with platform at {Url}", _options.PlatformUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Agent registration failed — will retry on next start");
        }
    }

    public async Task SendTelemetryAsync(ServerSnapshot snapshot, CancellationToken ct)
    {
        var resp = await _http.PostAsJsonAsync("/api/telemetry", snapshot, Json, ct);
        resp.EnsureSuccessStatusCode();
    }
}
