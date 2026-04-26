namespace RackWatch.Agent.Config;

public class AgentOptions
{
    public string AgentId                   { get; set; } = Guid.NewGuid().ToString();
    public string PlatformUrl               { get; set; } = "https://rackwatch.internal";
    public string AgentApiKey               { get; set; } = "";
    public int    CollectionIntervalSeconds { get; set; } = 60;
}
