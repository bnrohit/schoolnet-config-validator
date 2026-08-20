# SchoolNet Universal Network Analysis

SchoolNet v1.3 adds a universal, safety-first analysis layer for switches, routers, and network appliances.

## What “universal” means

SchoolNet does **not** pretend every network operating system has identical syntax or behavior. It uses two analysis levels:

1. **Specialized parsing** — deeper structured checks for platforms with mature parsers.
2. **Universal parsing** — conservative platform detection plus evidence-based rules that only report conditions visible in the supplied configuration.

If a platform cannot be identified confidently, SchoolNet reports the confidence level and avoids vendor-specific assumptions.

## Platform families

The UI/API includes profiles for:

- Cisco IOS / IOS-XE
- Cisco NX-OS / Nexus
- Cisco ASA
- Arista EOS
- Juniper Junos
- Aruba AOS-CX
- Aruba AOS-Switch / ProCurve
- HPE Comware
- ExtremeXOS
- Extreme VOSS
- Brocade / Ruckus FastIron / ICX
- Dell OS10
- Dell OS9 / FTOS
- MikroTik RouterOS
- VyOS
- Fortinet FortiOS
- Palo Alto PAN-OS
- SONiC
- FRRouting / Linux routing
- Ubiquiti EdgeOS
- Generic / unknown network-device configuration

New vendor profiles can be added without changing the safety model.

## Engineering safety model

Every universal finding can include:

- severity
- confidence
- evidence
- operational/security impact
- pre-change checks
- controlled change plan
- rollback path
- post-change validation

SchoolNet does not automatically push these changes.

A finding is guidance for an engineer to review against the real topology, software version, maintenance window, redundancy design, and vendor documentation.

## Why the tool avoids “missing feature” guesses

A configuration excerpt may not contain the full device configuration. For that reason, universal mode focuses on explicit evidence such as:

- Telnet enabled
- cleartext HTTP management enabled
- SNMP community/write access
- weak/plaintext credential syntax
- dynamic trunk negotiation
- all-VLAN trunks
- native/PVID VLAN 1
- STP explicitly disabled
- half-duplex explicitly configured
- legacy directed-broadcast/source-route features
- dynamic routing protocols present
- system logging explicitly disabled

It does not assume a feature is missing simply because a vendor-specific command was not recognized.

## Read-only live diagnostics

Live SSH is disabled by default:

```env
ENABLE_LIVE_SSH=false
```

When enabled on a trusted internal network, live diagnostics use predefined read-only command profiles. The backend never enters configuration mode and rejects obvious configuration, save, reload, delete, and commit operations.

Use a dedicated least-privilege account whenever possible.

Use HTTPS before entering credentials in the browser.

## Production change workflow

For a high-impact finding:

1. Confirm device/platform/version and topology.
2. Capture current operational state.
3. Verify out-of-band or alternate management access.
4. Identify dependent services and peer-device settings.
5. Define rollback criteria before changing anything.
6. Make one controlled change at a time.
7. Validate interfaces, neighbors, routes, STP, monitoring, and representative application paths.
8. Save/commit only after validation according to the platform's normal change procedure.

## Important limitation

SchoolNet is an engineering-assistance tool, not a replacement for vendor documentation, lab testing, topology knowledge, or peer review. A configuration can be syntactically valid while still being wrong for the intended design.
