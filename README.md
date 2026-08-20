# 🏫 SchoolNet Config Validator

[![CI](https://github.com/bnrohit/schoolnet-config-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/bnrohit/schoolnet-config-validator/actions)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.12-blue)
![Node](https://img.shields.io/badge/node-22-brightgreen)
![Docker](https://img.shields.io/badge/docker-ready-blue)
![K-12](https://img.shields.io/badge/focus-K--12%20networks-purple)

**SchoolNet Config Validator v1.9** is an open-source, safety-first, multi-vendor network engineering and troubleshooting platform for configuration analysis, live read-only diagnostics, path intelligence, change-impact review, drift comparison, and rollback-aware operations.

It is designed around four practical questions:

1. **What is wrong?**
2. **Where is the fault?**
3. **What changed or what is risky?**
4. **What should an engineer verify before and after a change?**

> Review-first design: SchoolNet analyzes evidence and produces engineering guidance. It does **not** automatically push production configuration changes, brute-force credentials, exploit vulnerabilities, or run arbitrary shell commands.

For a detailed feature-by-feature explanation, see [`docs/PRODUCT_OVERVIEW.md`](docs/PRODUCT_OVERVIEW.md).

---

## ✨ Current capabilities

### Analyze Config

- Auto-detect or manually select 20+ common network platform families
- Deep Cisco IOS/IOS-XE and Aruba parsing plus conservative universal parsing for other platforms
- Detect evidence-backed Layer 2, routing, management-plane, security, service, interface, and resilience risks
- Risk score, confidence, impact, evidence, pre-checks, rollback, and post-change validation

### Change Impact Lab

- Compare current vs proposed configuration
- Operational diff and blast-radius domains
- Change Gate: `BLOCK`, `HOLD`, `CAUTION`, or `REVIEW`
- Configuration DNA / semantic drift fingerprint
- VLAN, routing, ACL/firewall, management, service, and interface change signatures
- Change Passport JSON

### Network Safety Graph

- Multi-device topology/dependency inference
- CDP/LLDP/equivalent peer evidence
- Shared transit, trunk, VLAN, gateway, and routing relationships
- Peer-aware proposed-change checks
- First-hop/second-hop impact propagation
- Network-wide change gate

### Incident Investigator

- DNS and reverse lookup
- ICMP reachability and packet loss
- route lookup and traceroute
- bounded TCP service tests
- HTTP status and TLS evidence
- management/service exposure review
- optional read-only device/Linux evidence
- ranked probable-cause hypotheses and Incident Passport

### Deep Network Engineer

- DNS A/AAAA/CNAME/MX/NS/SOA/TXT/PTR
- enterprise/default resolver context and comparison
- IPv4/IPv6 routes, policy rules, neighbor cache, per-target route lookup
- UDP, ICMP, and TCP traceroute
- path-MTU hints
- HTTP/HTTPS application assurance
- response/security headers
- TLS protocol, cipher, trust, SANs, validity, and expiry
- bounded security-surface review
- optional OSPF/BGP/PIM/VRRP/HSRP/VLAN/STP/ARP/MAC/interface/logging evidence where supported

### Path Intelligence & Drift Lab

- Hop-by-hop PTR naming
- Visual UDP/ICMP/TCP path comparison
- First trace-mode divergence evidence
- Bounded MTR-style per-hop loss/latency/jitter sampling
- Optional VRF/routing-instance context for supported route lookups
- Optional forward/return route evidence from a read-only device
- Opt-in SQLite diagnostic history
- Before/after drift comparison
- JSON export and browser Print / Save PDF

### Safe Change Plan

- Evidence
- Impact
- Pre-change checks
- Controlled implementation sequence
- Rollback contract
- Post-change validation

### Read-Only Live

- Optional predefined read-only diagnostics for supported network devices and Linux
- Disabled by default
- HTTPS required for live credentials by default
- Defensive blocking of obvious write/config/reload operations

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

- Web UI: `http://localhost:3002`
- API docs through UI proxy: `http://localhost:3002/docs`
- Direct API docs: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/api/v1/health`

The production frontend uses a same-origin Nginx proxy for `/api/*`.

---

## ⚙️ Important environment settings

```env
APP_ENV=production
API_PORT=8000
WEB_PORT=3002
VITE_API_URL=.

# Optional enterprise resolver. Empty = container/system resolver.
DEFAULT_DNS_SERVER=
AUTO_APPLICATION_PROBE=true

# Live device/Linux SSH
ENABLE_LIVE_SSH=false
REQUIRE_HTTPS_FOR_LIVE_CREDENTIALS=true
ALLOW_INSECURE_LIVE_CREDENTIALS=false

# Public targets blocked by default
ALLOW_PUBLIC_DIAGNOSTICS=false

# Diagnostic history is opt-in because it stores internal network evidence
ENABLE_DIAGNOSTIC_HISTORY=false
DIAGNOSTIC_HISTORY_RETENTION=100
```

---

## 🔐 Security model

SchoolNet is designed for **authorized administration and sanitized configuration evidence**.

Do not upload or retain unnecessary:

- passwords or enable secrets
- private keys
- API tokens
- unsanitized production backups
- student/staff personal data
- sensitive diagrams or logs you do not intend to store

Key guardrails:

- active diagnostics are bounded to one authorized target
- public targets are blocked by default
- no subnet/range scanning in the troubleshooting workflows
- no brute force or credential guessing
- no exploitation
- no arbitrary shell
- no automatic production configuration changes
- live SSH is disabled by default
- live credentials are blocked over insecure HTTP by default
- live investigation responses are returned with no-store cache controls
- diagnostic history is opt-in

Use HTTPS before entering live device credentials, and use least-privilege/read-only accounts.

---

## 🧠 Example troubleshooting workflow

```text
User reports service problem
        ↓
DNS resolution / PTR
        ↓
Route lookup / policy route context
        ↓
UDP + ICMP + TCP traceroute
        ↓
Per-hop loss / latency / jitter
        ↓
TCP service reachability
        ↓
HTTP / TLS assurance
        ↓
Optional device evidence:
OSPF / BGP / STP / interfaces / logs / route lookup
        ↓
Rank likely fault domains
        ↓
Review security exposure
        ↓
Compare proposed change
        ↓
Safe plan + rollback + post-change proof
        ↓
Save before/after evidence
```

---

## 🗺️ Architecture

```text
Browser UI
   │
   ▼
Nginx frontend ── /api/* ──► FastAPI backend
                                  │
          ┌───────────────────────┼────────────────────────┐
          │                       │                        │
          ▼                       ▼                        ▼
   Config Analysis       Incident / Deep Engine     Path Intelligence
          │                       │                        │
          ▼                       ▼                        ▼
   Change Impact         DNS/routes/services        Trace correlation
   Safety Graph          HTTP/TLS/device state      History/drift
          │                       │                        │
          └───────────────────────┼────────────────────────┘
                                  ▼
                         Review-first evidence
                         rollback / validation
```

---

## 🔄 Upgrade an existing deployment

If `git pull` reports local changes, inspect/stash them first instead of forcing an overwrite.

```bash
cd ~/schoolnet-config-validator
git status --short
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
curl -fsS http://localhost:8000/api/v1/runtime-policy
curl -fsS http://localhost:3002/api/v1/vendors >/dev/null && echo "frontend API proxy OK"
```

Do **not** remove persistent volumes if you enabled diagnostic history.

---

## 📚 Documentation

- [`docs/PRODUCT_OVERVIEW.md`](docs/PRODUCT_OVERVIEW.md) — what SchoolNet does and who it helps
- [`CHANGELOG.md`](CHANGELOG.md) — release-by-release feature history
- API/OpenAPI docs — `/docs`
- Existing operator/development docs under `docs/`

---

## 🛣️ Product direction

Current stable line: **v1.9**.

High-value future work should be added only with appropriate privilege/secret controls:

- SNMPv3 / streaming telemetry overlay
- authenticated users, RBAC, and audit logging
- secure LLDP/CDP topology ingestion
- historical interface/error/OSPF/BGP state correlation
- hardened temporary PCAP worker with interface/filter/duration/size controls
- allowlisted ServiceNow/Jira/Slack integrations
- stronger cross-product incident correlation with EduNetGuard

The long-term goal is an evidence-driven network operations assistant that helps answer:

> **What is broken, what changed before it broke, what is the likely fault domain, and what is the safest next action?**

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

SchoolNet provides configuration-analysis, diagnostic, and change-review recommendations. It is not a substitute for validated network design, vendor documentation, live operational state, maintenance procedures, or qualified engineering review. Always preserve a tested rollback and recovery path before production changes.

---

## License

MIT License.
