# 🏫 SchoolNet Config Validator

[![CI](https://github.com/bnrohit/edunetguard-repo/actions/workflows/ci.yml/badge.svg)](https://github.com/bnrohit/edunetguard-repo/actions)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.12-blue)
![Node](https://img.shields.io/badge/node-22-brightgreen)
![Docker](https://img.shields.io/badge/docker-ready-blue)
![K-12](https://img.shields.io/badge/focus-K--12%20networks-purple)

**SchoolNet Config Validator** is an open-source K-12 network configuration validation and outage-prevention toolkit. It helps school IT teams, consultants, and network engineers safely review switch/router configs before small mistakes become campus outages.

It is built for real school network problems: VLAN mistakes, native VLAN risk, STP instability, unrestricted trunks, half-duplex ports, weak SNMP, Telnet exposure, missing DHCP snooping, and lack of uplink resilience.

> Safe-first design: offline config review works without live network access. Live SSH troubleshooting is disabled by default.

---

## ✨ What it does

- Validate Cisco IOS / IOS-XE switch configs
- Partially parse Aruba AOS-CX / AOS-Switch configs
- Detect high-risk access-layer misconfigurations
- Generate executive risk score and plain-English leadership summary
- Export JSON and Markdown reports
- Generate review-first remediation snippets
- Validate one config, uploaded file, CSV, or API batch
- Provide FastAPI OpenAPI docs for automation
- Provide CLI mode for pipelines and engineers
- Run in Docker Compose with web UI + API

---

## 🧩 Why this matters for schools

School networks support instruction, testing, phones, cameras, Wi-Fi, access control, and administrative systems. A small switch misconfiguration can cause AP drops, phone outages, DHCP failures, VLAN leaks, or broadcast storms across a campus.

SchoolNet gives small/rural school IT teams a simple repeatable way to review configs before changes are pushed.

---

## 🚀 Quick install

### Requirements

- Ubuntu Server 22.04/24.04, Debian 12, Windows with Docker Desktop, or macOS with Docker Desktop
- Docker + Docker Compose
- 2 vCPU / 4 GB RAM minimum
- 4 vCPU / 8 GB RAM recommended

### Run full stack

```bash
git clone https://github.com/bnrohit/edunetguard-repo.git
cd edunetguard-repo
cp .env.example .env
docker compose up --build -d
```

Open:

- Web UI: http://localhost:3000
- API docs: http://localhost:8000/docs
- Health check: http://localhost:8000/api/v1/health

### First-time demo

1. Open the Web UI.
2. Click **Load demo config**.
3. Click **Validate**.
4. Review findings and export the Markdown report.
5. Replace the demo with your own sanitized config.

---

## 🖥️ Recommended install location

Best place to run this:

- Internal NOC VM
- Monitoring VLAN server
- Admin workstation with Docker Desktop
- Lab VM used for change reviews

Do **not** install directly on:

- Domain controllers
- DHCP production servers
- Core routers/switches
- Internet-exposed servers without VPN/HTTPS

---

## 🔐 Security model

SchoolNet is designed to store and process **sanitized configuration text** only.

Do not upload:

- Passwords or enable secrets
- Private keys
- Full production backups containing secrets
- Student data
- Sensitive diagrams

The app includes a **Sanitize** helper that redacts common config secrets, but you should still review before uploading.

Live SSH troubleshooting is disabled by default:

```bash
ENABLE_LIVE_SSH=false
```

Only enable it on a trusted internal network.

---

## ✅ Validation checks

| Area | Example findings |
|---|---|
| VLAN correctness | Access port assigned to non-existent VLAN, VLAN 1 data use |
| Native VLAN risk | Native VLAN 1, native VLAN not in allowed trunk list |
| STP safety | Missing PortFast, BPDU Guard, Root Guard, STP mode |
| Trunk hygiene | All VLANs allowed, DTP/dynamic trunk risk |
| Duplex/speed | Half-duplex, hard-coded speed without duplex |
| Security | Telnet enabled, weak SNMP communities, missing DHCP snooping |
| Uplink resilience | Single uplink, no port-channel, fiber uplink without UDLD |

---

## 📡 API examples

Validate pasted config:

```bash
curl -X POST http://localhost:8000/api/v1/validate \
  -H "Content-Type: application/json" \
  -d @examples/validate-request.sample.json
```

Upload config:

```bash
curl -F "file=@configs/example-broken-switch.txt" \
  -F "vendor=cisco_ios" \
  http://localhost:8000/api/v1/validate/upload
```

Generate Markdown report:

```bash
curl -X POST http://localhost:8000/api/v1/report/markdown \
  -H "Content-Type: application/json" \
  -d '{"result": {}}'
```

---

## 🧰 CLI examples

```bash
python -m cli.main validate --file configs/example-broken-switch.txt --vendor cisco_ios --json
python -m cli.main fix --file configs/example-broken-switch.txt --output remediation.txt
```

Exit codes:

- `0` = no high/critical findings
- `1` = high findings detected
- `2` = critical findings detected

---

## 🗺️ Architecture

```text
Browser UI
   │
   ▼
React/Vite frontend ──► FastAPI backend ──► Parsers ──► Validation engine
                              │                 │              │
                              │                 │              └─ Risk score + findings
                              │                 └─ Cisco/Aruba config parsing
                              └─ Markdown/JSON reports + remediation snippets
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

- v1.2: Better reports, demo mode, sanitization, API docs
- v1.3: PDF reports and branded change-review packets
- v1.4: Meraki Dashboard API import
- v1.5: SNMP read-only collection
- v1.6: NetBox/Nautobot import
- v1.7: Role-based login and audit log
- v1.8: Teams/email notifications
- v2.0: Rule marketplace for school IT teams

---

## 🤝 Contributing

Pull requests are welcome. Good first contributions:

- Add a new vendor parser
- Add a new validation rule
- Improve remediation text
- Add test configs
- Improve docs and screenshots

See `docs/CONTRIBUTING.md`.

---

## ⚠️ Disclaimer

SchoolNet provides configuration review recommendations. Always validate changes in a lab or maintenance window and review generated commands with a qualified network engineer before applying them to production.

---

## License

MIT License.
