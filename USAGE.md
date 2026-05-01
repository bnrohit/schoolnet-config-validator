# Usage Guide

## Quick Start

```bash
git clone https://github.com/bnrohit/edunetguard-repo.git
cd edunetguard-repo
cp .env.example .env
docker compose up --build -d
```

Open the dashboard at `http://localhost:3000`.

## Web workflow

1. Click **Load demo config**.
2. Click **Validate**.
3. Review risk score and findings.
4. Export Markdown report for a change-review packet.
5. Paste your own sanitized config and repeat.

## API workflow

```bash
curl -F "file=@configs/example-broken-switch.txt" \
  -F "vendor=cisco_ios" \
  http://localhost:8000/api/v1/validate/upload
```

## CLI workflow

```bash
python -m cli.main validate --file configs/example-broken-switch.txt --vendor cisco_ios --json
python -m cli.main fix --file configs/example-broken-switch.txt --output remediation.txt
```

## Common checks

| Check | What it finds |
|---|---|
| VLAN mismatch | Access ports assigned to non-existent VLANs |
| Native VLAN risk | Native VLAN 1 or native VLAN not in allowed list |
| STP issue | Missing PortFast, BPDU Guard, Root Guard |
| Trunk risk | All VLANs allowed, DTP/dynamic trunking |
| Duplex mismatch | Half-duplex or speed/duplex mismatch |
| Security gap | Telnet, weak SNMP, missing DHCP snooping |
| Uplink resilience | Single uplink, no port-channel, no UDLD |

## Troubleshooting

**Frontend cannot reach backend**

- Confirm backend health: `http://localhost:8000/api/v1/health`
- Confirm Docker containers are running: `docker compose ps`

**Docker build fails**

- Update Docker Desktop.
- Run `docker compose build --no-cache`.

**Live SSH says disabled**

This is expected. Set `ENABLE_LIVE_SSH=true` in `.env` only on trusted internal networks.
