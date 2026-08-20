# SchoolNet Config Validator — Product Overview

SchoolNet Config Validator is a safety-first, multi-vendor network engineering and troubleshooting platform. It is designed to help network and systems administrators answer four practical questions:

1. **What is wrong?**
2. **Where is the fault?**
3. **What changed or what is risky?**
4. **What should an engineer verify before and after a change?**

SchoolNet is intentionally review-first. It collects and correlates evidence, but it does not automatically push production configuration changes, brute-force credentials, exploit vulnerabilities, or run arbitrary shell commands.

## Core workflows

### 1. Analyze Config

Offline/sanitized configuration analysis across 20+ common platform families.

- vendor/platform auto-detection
- Cisco/Aruba structured parsing plus conservative universal parsing
- VLAN/trunk/native-VLAN review
- STP and loop-risk checks
- routing awareness
- management-plane security checks
- ACL/firewall/NAT change awareness
- DHCP relay and infrastructure-service dependency checks
- interface, MTU, speed/duplex, and shutdown risk
- risk score, confidence, evidence, impact, pre-checks, rollback, and post-change validation

### 2. Change Impact Lab

Compares current and proposed configuration before production changes.

- operational diff
- blast-radius domains
- Change Gate: `BLOCK`, `HOLD`, `CAUTION`, or `REVIEW`
- Configuration DNA / semantic drift fingerprint
- VLAN/routing/security/interface change signatures
- pre-change evidence checklist
- controlled implementation sequence
- rollback contract
- post-change proof
- Change Passport JSON

### 3. Network Safety Graph

Correlates multiple device configurations and neighbor evidence.

- CDP/LLDP/equivalent peer inference
- shared transit/routed-link inference
- trunk, VLAN, gateway, and routing relationships
- inferred device roles and topology components
- potential single-point-of-failure indicators
- peer-aware proposed-change checks
- first-hop/second-hop impact propagation
- network-wide change gate

### 4. Incident Investigator

Runs bounded read-only troubleshooting against one authorized target.

- DNS resolution and reverse lookup
- ICMP reachability and packet-loss evidence
- route lookup from the SchoolNet probe
- traceroute
- bounded TCP service checks
- HTTP status and TLS evidence
- common management/service exposure review
- optional read-only device/Linux evidence
- ranked probable-cause hypotheses and recommended next checks
- Incident Passport export

### 5. Deep Network Engineer

Extends troubleshooting into deeper network/system-admin evidence.

- probe hostname/FQDN and resolver context
- DNS A, AAAA, CNAME, MX, NS, SOA, TXT, and PTR
- optional enterprise/default resolver comparison
- IPv4/IPv6 route tables and policy rules
- neighbor/ARP cache
- per-destination route lookup
- UDP, ICMP, and TCP traceroute modes
- path-MTU hints
- bounded management/service exposure review
- server-initiated banner evidence for selected services
- automatic HTTP/HTTPS application assurance
- response/security headers
- TLS protocol, cipher, trust, SAN, validity, and expiry
- optional read-only OSPF, BGP, PIM, VRRP/HSRP, VLAN/trunk/STP, ARP/MAC, interface, error, and logging evidence where the platform supports it
- optional target-side route lookup

### 6. Path Intelligence & Drift Lab

Adds path correlation and before/after operational evidence.

- hop-by-hop PTR/reverse-DNS enrichment
- visual UDP/ICMP/TCP path comparison
- first divergence evidence across trace modes
- bounded MTR-style sampling of discovered hops
- packet loss, min/avg/max latency, and jitter
- explicit control-plane rate-limit warning so router ICMP loss is not automatically treated as forwarding loss
- optional VRF/routing-instance context for supported read-only route lookups
- optional forward/return route evidence from a read-only device
- opt-in SQLite diagnostic history
- retention control
- before/after drift comparison for open ports, fault domains, application/TLS status, security findings, resolver context, and trace sequences
- JSON export and browser Print / Save PDF workflow

### 7. Safe Change Plan

Converts findings into a non-executable engineering plan.

- evidence
- impact
- pre-change checks
- controlled change steps
- rollback
- post-change validation

It is deliberately not an auto-remediation engine.

### 8. Read-Only Live

Optional live network-device/Linux diagnostics using predefined read-only command profiles.

- disabled by default
- HTTPS required for live credentials by default
- least-privilege/read-only accounts recommended
- unsupported commands fail individually instead of triggering configuration changes
- defensive blocking prevents obvious write/reload/configuration operations

## Operational and security controls

SchoolNet includes explicit guardrails:

- one authorized target for active diagnostics
- public targets blocked by default
- no subnet/range scanning in diagnostic workflows
- no brute force or credential guessing
- no exploitation
- no arbitrary shell
- no automatic production configuration changes
- live SSH disabled by default
- live credentials blocked over insecure HTTP by default
- live investigation responses use `Cache-Control: no-store`
- diagnostic history is opt-in because stored evidence can contain internal network metadata

## What SchoolNet can help teams do

SchoolNet is intended to reduce random troubleshooting and unnecessary production changes. A typical workflow is:

```text
Detect problem
   ↓
Resolve DNS / route / path / service state
   ↓
Correlate device and protocol evidence
   ↓
Rank likely fault domains
   ↓
Review security exposure
   ↓
Compare current vs proposed change
   ↓
Generate safe plan + rollback
   ↓
Engineer performs approved change
   ↓
Run post-change proof
   ↓
Save incident/change evidence
```

This can help senior engineers, junior administrators, help desk teams, MSPs, schools, municipalities, and smaller enterprises by making network troubleshooting more consistent and evidence-driven.

## What SchoolNet does not claim

SchoolNet is not a perfect digital twin and does not replace an experienced engineer. Configuration files and one probe location cannot prove every physical cable, application dependency, control-plane state, firewall path, wireless condition, or asymmetric route.

The system therefore uses evidence, confidence, bounded probing, and human approval rather than pretending to know facts it cannot observe.

## Planned hardened extensions

Future work should be added only with appropriate privilege and secret controls. High-value candidates include:

- SNMPv3 / streaming telemetry overlay
- secure LLDP/CDP topology ingestion from managed devices
- historical interface/error/OSPF/BGP state
- hardened temporary PCAP worker with interface/filter/duration/size controls
- allowlisted ticketing and collaboration integrations
- authenticated users, RBAC, and audit trail
- stronger observability correlation with EduNetGuard

The long-term direction is an evidence-driven network operations assistant that can help answer not only **“what is broken?”** but also **“what changed before it broke, what is the likely fault domain, and what is the safest next action?”**
