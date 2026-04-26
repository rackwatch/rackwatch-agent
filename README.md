# RackWatch Agent

Cross-platform server monitoring agent for [RackWatch](https://rackwatch.io). Open source so you can audit exactly what runs on your hosts before installing.

The agent collects host telemetry every 60 seconds — CPU, memory, disk, pending patches with CVE mapping, hardware identification — and pushes it to a RackWatch platform you control. The platform is the closed-source piece that scores risk, dispatches alerts, and serves the dashboard.

## Install

Each RackWatch platform serves its own one-line installer with the
right `AGENT_API_KEY` already baked in. Run the URL printed by *your*
platform — not a generic one.

**Trying out the public RackWatch instance** (free for ≤5 servers,
shared homelab tenant):

```bash
curl -fsSL https://rackwatch.io/install.sh | sudo bash
```

**Self-hosted platform** — substitute the hostname or IP of the box
running your RackWatch platform:

```bash
# Example only — replace platform.example.internal with your actual platform.
curl -fsSL https://platform.example.internal/install.sh | sudo bash
```

Either one drops the binary at `/opt/rackwatch-agent/`, registers a
`systemd` unit, and starts collecting. Works on Ubuntu 20.04+,
Debian 11+, RHEL 8+, CentOS Stream, Rocky, and Alma.

For Windows Server (2019, 2022) and Windows 11:

```powershell
# Trying it out:
iwr https://rackwatch.io/install.ps1 -UseB | iex

# Self-hosted (example — replace the hostname):
iwr https://platform.example.internal/install.ps1 -UseB | iex
```

If you'd rather build from this repo, see [Building](#building).

## What it collects

| Source | Frequency | What |
|---|---|---|
| `/proc`, `sysfs` | 60 s | CPU load, memory, swap, network counters |
| `df` | 60 s | Filesystem utilization for every mounted volume |
| `apt` / `yum` / `dnf` | 1 hr | Pending package updates |
| Windows Update API | 1 hr | Pending Windows patches |
| `dmidecode`, SMBIOS | startup, daily | Hardware ID, BIOS install date, vendor, warranty hint |
| `smartctl` | 1 hr | SMART attributes for monitored block devices |
| `last`, `wtmp` | 60 s | Recent reboots, login history |

Nothing is collected that isn't on the dashboard. No file contents, no process arguments beyond names, no environment variables.

## What it doesn't do

- Phone home to RackWatch. The agent only talks to the platform URL you configure.
- Run code from the platform. Telemetry is one-way (agent → platform).
- Install other software on your host.
- Modify any system file outside of `/opt/rackwatch-agent/` and `/etc/systemd/system/rackwatch-agent.service`.

## Permissions

The agent runs as root because it reads `/proc/1/status`, calls `dmidecode`, and queries the package manager. Hardware identification and patch enumeration both require it — there's no graceful degradation that produces useful output without root.

The Windows agent runs as `LocalSystem` for the same reasons (WMI hardware queries, Windows Update API).

If you're not comfortable running an agent as root, the binary is small enough that auditing the source first is realistic — see `Collectors/` for the privileged paths.

## Building

```bash
git clone https://github.com/rackwatch/rackwatch-agent
cd rackwatch-agent
dotnet publish -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true
```

The output is a self-contained ~30 MB binary at `bin/Release/net8.0/linux-x64/publish/rackwatch-agent`. No .NET runtime needed on the host.

For Windows: `-r win-x64`. For ARM: `-r linux-arm64`.

## Configuration

`/opt/rackwatch-agent/appsettings.json`:

```json
{
  "Agent": {
    "AgentId": "uuid-generated-at-install",
    "PlatformUrl": "https://your-platform.example.com",
    "AgentApiKey": "your-platform-api-key",
    "CollectionIntervalSeconds": 60
  },
  "Logging": { "LogLevel": { "Default": "Information" } }
}
```

The platform's installer fills in `PlatformUrl` and `AgentApiKey` for you.

## Verifying release artifacts

Each release is tagged in this repo and the SHA-256 of every binary is published in the GitHub release notes. To verify:

```bash
sha256sum rackwatch-agent
# Compare against the SHA-256 in the matching release on GitHub.
```

Reproducible builds are a goal, not yet a guarantee. See [SECURITY.md](SECURITY.md).

## Security

Reports go to <security@rackwatch.io> or via [private GitHub advisory](https://github.com/rackwatch/rackwatch-agent/security/advisories/new). See [SECURITY.md](SECURITY.md) for scope, disclosure timeline, and what to expect.

## License

Apache 2.0. See [LICENSE](LICENSE).

The platform that this agent reports to is a separate, commercial product. The agent being open source means you can verify what it does on your hosts; running it does not grant any rights to the platform.

## Links

- Platform & docs: <https://rackwatch.io>
- Pricing: <https://rackwatch.io/pricing.html>
- Risk score formula: <https://rackwatch.io/risk-score.html>
- Security policy: <https://rackwatch.io/security.html>
