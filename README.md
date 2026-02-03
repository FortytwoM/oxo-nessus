<p align="center">
  <img src="https://raw.githubusercontent.com/Ostorlab/oxo/main/images/oxo_logo.png" alt="OXO Logo" width="100"/>
</p>

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

Agent Nessus is an [OXO Agent](https://pypi.org/project/ostorlab/) that performs vulnerability scanning using [Tenable Nessus](https://www.tenable.com/products/nessus) scanner via the pyTenable API.

## Getting Started

To perform your first scan, simply run the following command:

```shell
oxo scan run --install --agent agent/FortyTwoM/nessus \
  --arg access_key:YOUR_ACCESS_KEY \
  --arg secret_key:YOUR_SECRET_KEY \
  --arg nessus_url:https://your-nessus-server:8834 \
  ip 192.168.1.1
```

This command will download and install `agent/FortyTwoM/nessus` and target the IP `192.168.1.1`.

For more information, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs).

## Usage

Agent Nessus can be installed directly from the OXO agent store or built from this repository.

### Supported Agent Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `nessus_url` | string | `https://localhost:8834` | Nessus server URL |
| `access_key` | string | *(required)* | Nessus API access key |
| `secret_key` | string | *(required)* | Nessus API secret key |
| `verify_ssl` | boolean | `false` | Verify SSL certificate |
| `scan_policy_id` | number | `0` | Custom scan policy ID (0 = use template) |
| `scan_template` | string | `basic` | Scan template: `basic`, `discovery`, `advanced` |
| `wait_for_completion` | boolean | `true` | Wait for scan to complete |
| `timeout` | number | `3600` | Scan timeout in seconds |
| `min_severity` | string | `info` | Minimum severity: `info`, `low`, `medium`, `high`, `critical` |

### Install from OXO Agent Store

After publishing to the OXO store:

```shell
oxo agent install agent/FortyTwoM/nessus
```

Then run scans with:

```shell
oxo scan run --agent agent/FortyTwoM/nessus \
  --arg access_key:YOUR_KEY \
  --arg secret_key:YOUR_SECRET \
  --arg nessus_url:https://nessus.example.com:8834 \
  ip 8.8.8.8
```

### Build from Repository

1. Install [OXO](https://pypi.org/project/ostorlab/) if not already installed:

```shell
pip3 install ostorlab
```

2. Clone this repository:

```shell
git clone https://github.com/FortyTwoM/oxo-nessus.git && cd oxo-nessus
```

3. Build the agent image:

```shell
oxo agent build --file=oxo.yaml
```

You can pass the optional flag `--organization` to specify your organization.

4. Run a scan:

```shell
oxo scan run --agent agent//nessus \
  --arg access_key:YOUR_KEY \
  --arg secret_key:YOUR_SECRET \
  --arg nessus_url:https://nessus.example.com:8834 \
  ip 192.168.1.1
```

## Example Scans

### Basic IP Scan

```shell
oxo scan run --install --agent agent/FortyTwoM/nessus \
  --arg access_key:YOUR_KEY \
  --arg secret_key:YOUR_SECRET \
  --arg nessus_url:https://nessus.example.com:8834 \
  ip 192.168.1.1
```

### Domain Scan with Custom Policy

```shell
oxo scan run --install --agent agent/FortyTwoM/nessus \
  --arg access_key:YOUR_KEY \
  --arg secret_key:YOUR_SECRET \
  --arg nessus_url:https://nessus.example.com:8834 \
  --arg scan_policy_id:4 \
  domain example.com
```

### Network Range Scan (High Severity Only)

```shell
oxo scan run --install --agent agent/FortyTwoM/nessus \
  --arg access_key:YOUR_KEY \
  --arg secret_key:YOUR_SECRET \
  --arg nessus_url:https://nessus.example.com:8834 \
  --arg min_severity:high \
  --arg timeout:7200 \
  ip 10.0.0.0/24
```

### Using Agent Group Definition

Create `agent_group.yaml`:

```yaml
kind: AgentGroup
description: Nessus vulnerability scanning

agents:
  - key: agent/FortyTwoM/nessus
    args:
      - name: nessus_url
        type: string
        value: "https://nessus.example.com:8834"
      - name: access_key
        type: string
        value: "YOUR_ACCESS_KEY"
      - name: secret_key
        type: string
        value: "YOUR_SECRET_KEY"
      - name: scan_template
        type: string
        value: "basic"
      - name: min_severity
        type: string
        value: "medium"
```

Run with:

```shell
oxo scan run --install -g agent_group.yaml ip 192.168.1.1
```

## Selectors

### Input Selectors

| Selector | Description |
|----------|-------------|
| `v3.asset.ip.v4` | IPv4 address |
| `v3.asset.ip.v6` | IPv6 address |
| `v3.asset.domain_name` | Domain name / hostname |
| `v3.asset.link` | URL (hostname extracted automatically) |

### Output Selectors

| Selector | Description |
|----------|-------------|
| `v3.report.vulnerability` | Vulnerability finding with details |

## Prerequisites

- **Tenable Nessus** scanner with API access enabled
- **API Keys**: Generate in Nessus UI → Settings → My Account → API Keys
- **Network Access**: Agent must be able to reach Nessus server

## Getting Nessus API Keys

1. Log in to your Nessus web interface
2. Navigate to **Settings** → **My Account** → **API Keys**
3. Click **Generate** to create new API keys
4. Copy the **Access Key** and **Secret Key**

## Troubleshooting

### Connection Issues

- Verify Nessus server is running and accessible
- Check URL format (include `https://` and port)
- For self-signed certificates, ensure `verify_ssl` is `false`

### Authentication Errors

- Verify API keys are correct (no extra spaces)
- Ensure API access is enabled in Nessus settings
- Check if keys have necessary permissions

### Scan Timeout

- Increase `timeout` argument for large network scans
- Check Nessus server load and resources
- Verify targets are reachable from Nessus server

### No Vulnerabilities Reported

- Check `min_severity` setting — try `info` to see all findings
- Verify scan completed successfully in Nessus UI
- Review scan results directly in Nessus web interface

## Publishing to OXO Store

1. Push code to a public GitHub repository
2. Go to [OXO Platform](https://oxo.ostorlab.co/)
3. Navigate to **Library** → **Agent publish**
4. Fill in:
   - **Name**: `nessus`
   - **Git URL**: `https://github.com/FortyTwoM/oxo-nessus`
   - **YAML path**: `oxo.yaml`
5. Click **Publish**

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

## License

[MIT](LICENSE)

## References

- [OXO Documentation](https://oxo.ostorlab.co/docs)
- [OXO Agent Tutorial](https://oxo.ostorlab.co/tutorials/write_an_agent)
- [pyTenable Documentation](https://pytenable.readthedocs.io/)
- [Nessus API Documentation](https://docs.tenable.com/nessus/api)
- [Tenable Nessus](https://www.tenable.com/products/nessus)
