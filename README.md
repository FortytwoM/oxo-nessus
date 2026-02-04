# Agent Nessus

<p align="center">
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"/>
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"/>
  </a>
  <a href="https://oxo.ostorlab.co/store">
    <img src="https://img.shields.io/badge/OXO-Agent-green.svg" alt="OXO Agent"/>
  </a>
</p>

[OXO Agent](https://pypi.org/project/ostorlab/) for vulnerability scanning with [Tenable Nessus](https://www.tenable.com/products/nessus) via the pyTenable API.

## Quick Start

```shell
oxo scan run --install --agent agent/FortyTwoM/nessus \
  --arg access_key:YOUR_ACCESS_KEY \
  --arg secret_key:YOUR_SECRET_KEY \
  --arg nessus_url:https://your-nessus:8834 \
  ip 192.168.1.1
```

See [OXO Documentation](https://oxo.ostorlab.co/docs) for more.

## Agent Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `nessus_url` | string | `https://localhost:8834` | Nessus server URL |
| `access_key` | string | *(required)* | Nessus API access key |
| `secret_key` | string | *(required)* | Nessus API secret key |
| `verify_ssl` | boolean | `false` | Verify SSL certificate |
| `scan_policy_id` | number | `0` | Nessus policy ID (0 = use template) |
| `scan_template` | string | `basic` | Template when no policy: `basic`, `discovery`, `advanced` |
| `wait_for_completion` | boolean | `true` | Wait for scan to finish |
| `timeout` | number | `3600` | Scan timeout (seconds) |
| `min_severity` | string | `info` | Report severity: `info`, `low`, `medium`, `high`, `critical` |

## Install & Run

**From OXO store:**

```shell
oxo agent install agent/FortyTwoM/nessus
oxo scan run --agent agent/FortyTwoM/nessus --arg access_key:KEY --arg secret_key:SECRET --arg nessus_url:https://nessus:8834 ip 8.8.8.8
```

**From repo (build locally):**

```shell
pip install ostorlab
git clone https://github.com/FortyTwoM/oxo-nessus.git && cd oxo-nessus
oxo agent build --file=oxo.yaml
oxo scan run --agent agent//nessus --arg access_key:KEY --arg secret_key:SECRET --arg nessus_url:https://nessus:8834 ip 192.168.1.1
```

## Examples

**IP:** `oxo scan run --agent agent/FortyTwoM/nessus ... ip 192.168.1.1`

**Hostname (use `domain-name`):** `oxo scan run ... domain-name scanme.nmap.org`

**With policy:** `oxo scan run ... --arg scan_policy_id:4 ip 10.0.0.1`

**Higher severity only:** `oxo scan run ... --arg min_severity:high --arg timeout:7200 ip 10.0.0.0/24`

**Agent group** — define `agent_group.yaml` with `key: agent/FortyTwoM/nessus` and `args` (e.g. `nessus_url`, `access_key`, `secret_key`, `scan_policy_id`, `scan_template`), then: `oxo scan run --install -g agent_group.yaml ip 192.168.1.1`

## OXO management

| Action | Command |
|--------|---------|
| List scans | `oxo scan list` |
| Stop one scan | `oxo scan stop <scan-id>` |
| Stop several scans | `oxo scan stop <id1> <id2> <id3>` |
| Stop all scans | `oxo scan stop -a` |
| List vulnerabilities for a scan | `oxo vulnz list --scan-id <scan-id>` (required) |
| Show vulnerability details | `oxo vulnz describe --vuln-id <vuln-id>` |


## Selectors

| Direction | Selector | Description |
|-----------|----------|-------------|
| In | `v3.asset.ip.v4` | IPv4 |
| In | `v3.asset.ip.v6` | IPv6 |
| In | `v3.asset.domain_name` | Domain/hostname |
| In | `v3.asset.link` | URL (host extracted) |
| Out | `v3.report.vulnerability` | Vulnerability report |

## Prerequisites

- Nessus with API enabled; API keys from **Settings → My Account → API Keys**
- Agent must reach Nessus (URL, firewall; use `verify_ssl: false` for self-signed certs)

## License

[MIT](LICENSE)

## References

- [OXO Docs](https://oxo.ostorlab.co/docs) · [Agent Tutorial](https://oxo.ostorlab.co/tutorials/write_an_agent)
- [pyTenable](https://pytenable.readthedocs.io/) · [Nessus API](https://docs.tenable.com/nessus/api) · [Tenable Nessus](https://www.tenable.com/products/nessus)
