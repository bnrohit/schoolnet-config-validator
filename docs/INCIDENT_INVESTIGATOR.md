# Network Incident Investigator (v1.6)

The Network Incident Investigator is a bounded, read-only troubleshooting workflow that correlates network-path, DNS, service, TLS, security-surface, and optional device evidence into ranked root-cause hypotheses.

## What it can check

From the SchoolNet backend container:

- system DNS resolution
- `dig` A/AAAA queries, optionally against a selected resolver
- reverse DNS lookup
- ICMP reachability and packet-loss/RTT evidence
- Linux route lookup (`ip route get`) from the SchoolNet server
- traceroute from the SchoolNet server
- bounded TCP connection tests (maximum 16 ports)
- HTTP response status on common web/service ports
- TLS protocol/cipher/trust evidence and certificate expiry when verification succeeds
- optional bounded management-exposure checks

With `ENABLE_LIVE_SSH=true`, SchoolNet can also collect its existing predefined, read-only multi-vendor troubleshooting categories from one affected network device and correlate selected fault signatures.

## Important perspective limitation

Every network probe originates from the SchoolNet backend container. If that server is in a NOC, management VLAN, container network, VRF, VPN, or firewall zone that differs from the affected user/device path, its result can differ from the actual client experience.

Use the investigator to answer questions such as:

- Does the name resolve correctly?
- Does this resolver return the expected address?
- Does the SchoolNet host have a usable route?
- Does ICMP fail while the real application port still works?
- Is the server reachable but the expected listener closed/filtered?
- Is HTTP returning an application error even though the network path works?
- Is TLS trust/hostname/certificate state the failure?
- Does the affected switch/router show interface errors, routing-neighbor problems, native-VLAN mismatch, duplicate address/MAC movement, AAA warnings, DHCP warnings, or link flaps?

## Security guardrails

SchoolNet does not accept arbitrary shell commands. Diagnostic executables are called with fixed argument arrays; shell interpolation is not used.

Defaults:

```env
ENABLE_LIVE_SSH=false
ALLOW_PUBLIC_DIAGNOSTICS=false
```

With `ALLOW_PUBLIC_DIAGNOSTICS=false`, resolved targets must be private, loopback, or link-local. Only enable public diagnostics for systems you are authorized to test.

Live SSH uses the existing predefined read-only command catalog. It does not enter configuration mode or save/reload/delete configuration. Credentials are not returned in the investigation result.

Use HTTPS before entering credentials in the browser and use a least-privilege/read-only account whenever possible.

## API

### Capabilities

```http
GET /api/v1/investigate/capabilities
```

### Run an investigation

```http
POST /api/v1/investigate
Content-Type: application/json
```

Example:

```json
{
  "target": "10.10.10.1",
  "ports": [22, 80, 443],
  "dns_server": "10.10.0.53",
  "run_trace": true,
  "security_surface": false,
  "device": {
    "enabled": false,
    "host": "",
    "username": "",
    "password": "",
    "secret": "",
    "device_type": "cisco_ios",
    "port": 22,
    "categories": ["basic", "interfaces", "errors", "neighbors", "routing", "vlan", "stp", "security"]
  }
}
```

## Reading the result

The result includes:

- `overall_state`
- confidence
- DNS evidence
- route, ping, and traceroute evidence
- TCP/HTTP/TLS evidence
- security findings
- optional device evidence
- ranked root-cause hypotheses
- recommended next actions
- an `incident_passport` summary suitable for change/ticket records

A high-confidence hypothesis is still an engineering hypothesis, not an automatic authorization to change production. Correlate timestamps, adjacent-device evidence, monitoring alerts, physical-path information, and the affected user's actual path before remediation.
