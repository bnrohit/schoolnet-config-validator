# 🏫 SchoolNet Config Validator

[![CI](https://github.com/bnrohit/schoolnet-config-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/bnrohit/schoolnet-config-validator/actions)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.12-blue)
![Node](https://img.shields.io/badge/node-22-brightgreen)
![Docker](https://img.shields.io/badge/docker-ready-blue)
![K-12](https://img.shields.io/badge/focus-K--12%20networks-purple)

**SchoolNet Config Validator** is an open-source, safety-first network engineering toolkit for configuration risk analysis, proposed-change pre-flight review, rollback-aware planning, and read-only troubleshooting.

It is designed for real operational problems: VLAN mistakes, native VLAN mismatches, STP instability, unrestricted trunks, routing changes, management lockout, DHCP relay errors, weak management security, firewall/ACL drift, and configuration changes that look small but can create a large outage blast radius.

> Review-first design: SchoolNet analyzes evidence and produces engineering guidance. It does not automatically push production configuration changes.

---

## ✨ What it does

- Auto-detect or manually select 20+ common network platform families
- Deep structured validation for Cisco IOS/IOS-XE and Aruba platforms, plus conservative universal parsing for other network OS families
- Detect evidence-backed Layer 2, routing, management-plane, security, and resilience risks
- Produce risk score, confidence, impact, pre-checks, rollback, and post-change validation guidance
- Compare **current vs proposed configuration** in the **Change Impact Lab**
- Estimate affected operational domains / blast radius before a change
- Detect management-lockout, trunk/native-VLAN, STP, routing, ACL/firewall, DHCP relay, interface, and default-route change signatures
- Generate a **Change Gate**: `BLOCK`, `HOLD`, `CAUTION`, or `REVIEW`
- Generate a semantic **Configuration DNA** fingerprint for drift/change evidence
- Export a Change Passport JSON for change records
- Generate review-first safe change plans
- Run optional read-only live diagnostics with defensive command blocking
- Export JSON and Markdown configuration-analysis reports
- Run in Docker Compose with web UI + FastAPI API

---

## 🧠 Change Impact Lab

SchoolNet v1.4 adds a pre-production change-analysis workflow.

Paste:

1. the current sanitized configuration, and
2. the proposed sanitized configuration.

SchoolNet calculates:

- line-level operational diff
- change density
- high-impact change signatures
- affected domains: management, routing, Layer 2, security policy, services, interfaces
- VLAN additions/removals
- routing-protocol additions/removals
- semantic configuration fingerprint before/after
- pre-change evidence to capture
- controlled implementation sequence
- rollback contract
- post-change proof / validation steps

The feature intentionally does **not** claim a perfect digital twin. A configuration file cannot reveal every physical topology, runtime dependency, software defect, or live protocol state. High-risk changes still require human approval, live pre-checks, and a verified console/OOB recovery path.

---

## 🌐 Platform coverage

The platform catalog includes:

- Auto-detect
- Cisco IOS / IOS-XE / NX-OS / ASA
- Arista EOS
- Juniper Junos
- Aruba AOS-CX / AOS-Switch
- HPE Comware
- ExtremeXOS / VOSS
- Brocade / Ruckus FastIron / ICX
- Dell OS10 / OS9
- MikroTik RouterOS
- VyOS
- Fortinet FortiOS
- Palo Alto PAN-OS
- SONiC
- FRRouting / Linux routing
- Ubiquiti EdgeOS
- Generic / unknown network-device configuration

Support depth differs by platform. Unknown or partially understood syntax is handled conservatively instead of being silently interpreted as Cisco syntax.

---

## 🚀 Quick install

### Requirements

- Ubuntu Server 22.04/24.04, Debian 12, Windows with Docker Desktop, or macOS with Docker Desktop
- Docker + Docker Compose
- 2 vCPU / 4 GB RAM minimum
- 4 vCPU / 8 GB RAM recommended

### Run full stack

```bash
git clone https://github.com/bnrohit/schoolnet-config-validator.git
cd schoolnet-config-validator
cp .env.example .env
docker compose up --build -d
```

Default endpoints:

- Web UI: http://localhost:3002
- API docs through the UI proxy: http://localhost:3002/docs
- Direct API docs: http://localhost:8000/docs
- Health check: http://localhost:8000/api/v1/health

The production frontend uses a same-origin Nginx proxy for `/api/*` so browser API requests stay on the SchoolNet host instead of trying to contact the operator workstation's localhost.

---

## 🔐 Security model

SchoolNet is designed to process **sanitized configuration text**.

Do not upload:

- passwords or enable secrets
- private keys
- API tokens
- unsanitized production backups
- student data
- sensitive diagrams containing information you do not intend to expose

The API sanitizes several common credential patterns before analysis, but operators must still review data before submission.

Live SSH troubleshooting is disabled by default:

```bash
ENABLE_LIVE_SSH=false
```

Only enable live diagnostics on a trusted internal network. Use HTTPS before entering credentials in the web UI, and use a least-privilege/read-only network account where the platform supports it.

---

## ✅ Engineering checks

| Area | Example analysis |
|---|---|
| VLAN / trunking | Missing/removed VLANs, native/PVID risk, broad trunks, dynamic trunking |
| STP / loops | STP disablement, edge protection, topology-change risk |
| Routing | OSPF/BGP/IS-IS change awareness, default-route changes, route-policy review |
| Management | Telnet/HTTP exposure, AAA/TACACS/RADIUS changes, management lockout risk |
| Security policy | ACL/firewall/NAT policy changes and blast-radius awareness |
| Services | DHCP relay, DNS/NTP/logging/SNMP dependency changes |
| Interfaces | Shutdown/address/MTU/speed/duplex changes |
| Resilience | Uplink/LAG/UDLD/rollback/recovery considerations |
| Observability | Pre/post evidence, logs, counters, monitoring continuity |

---

## 📡 API examples

Validate a configuration:

```bash
curl -X POST http://localhost:8000/api/v1/validate \
  -H "Content-Type: application/json" \
  -d '{"vendor":"auto","config_text":"hostname access01\n..."}'
```

Run Change Impact Lab:

```bash
curl -X POST http://localhost:8000/api/v1/change-impact \
  -H "Content-Type: application/json" \
  -d '{
    "vendor":"auto",
    "before_config":"hostname access01\ninterface Gi1/0/48\n switchport mode trunk\n switchport trunk allowed vlan 10,20",
    "after_config":"hostname access01\ninterface Gi1/0/48\n switchport mode trunk\n switchport trunk allowed vlan 10,20,30"
  }'
```

Upload config:

```bash
curl -F "file=@configs/example-broken-switch.txt" \
  -F "vendor=auto" \
  http://localhost:8000/api/v1/validate/upload
```

---

## 🗺️ Architecture

```text
Browser UI
   │
   ▼
Nginx frontend ── /api/* ──► FastAPI backend
                                  │
                 ┌────────────────┼─────────────────┐
                 │                │                 │
                 ▼                ▼                 ▼
           Config Parser    Validation Engine   Change Impact Lab
                 │                │                 │
                 │                │                 ├─ operational diff
                 │                │                 ├─ blast radius
                 │                │                 ├─ change gate
                 │                │                 ├─ Config DNA
                 │                │                 └─ rollback/validation plan
                 │                │
                 └────────► review-first reports
```

---

## 🔄 Upgrade an existing deployment

If `git pull` reports local changes, inspect/stash them first instead of forcing an overwrite.

```bash
cd ~/schoolnet-config-validator
git status --short
git stash push -m "pre-schoolnet-upgrade" -- docker-compose.yml  # only if that file is locally modified
git checkout main
git pull --ff-only origin main
```

Keep ports in `.env`, not by editing `docker-compose.yml`:

```env
WEB_PORT=3002
API_PORT=8000
VITE_API_URL=.
```

Rebuild:

```bash
docker compose build --pull frontend backend
docker compose up -d --force-recreate frontend backend
docker compose ps
```

Verify:

```bash
curl -fsS http://localhost:8000/api/v1/health
curl -fsS http://localhost:3002/api/v1/vendors >/dev/null && echo "frontend API proxy OK"
```

---

## 🧪 Development

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Tests:

```bash
pytest backend/tests -q
```

---

## 🛣️ Roadmap

- **v1.3**: Universal multi-vendor analysis, evidence/confidence, review-first change plans, vendor-aware read-only diagnostics
- **v1.4**: Change Impact Lab, blast-radius analysis, change gate, Configuration DNA, Change Passport
- **v1.5**: Multi-device topology bundle analysis and peer-consistency checks
- **v1.6**: Historical configuration drift timeline and approved-baseline policy
- **v1.7**: NetBox/Nautobot inventory context and change dependency enrichment
- **v1.8**: Role-based login, audit log, and change approvals
- **v2.0**: Cross-device Network Safety Graph for pre-change dependency reasoning

---

## 🤝 Contributing

Pull requests are welcome. Useful contributions include:

- vendor parsers
- vendor-specific read-only command profiles
- validation rules with tests
- safe change-impact signatures
- sanitized sample configurations
- documentation and screenshots

See `docs/CONTRIBUTING.md`.

---

## ⚠️ Disclaimer

SchoolNet provides configuration-analysis and change-review recommendations. It is not a substitute for validated network design, vendor documentation, live operational state, maintenance procedures, or qualified engineering review. Always preserve a tested rollback and recovery path before production changes.

---

## License

MIT License.
