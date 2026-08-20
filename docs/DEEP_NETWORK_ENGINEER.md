# Deep Network Engineer — SchoolNet v1.7

Deep Network Engineer is a bounded, read-only troubleshooting workflow for one authorized hostname or IP at a time. It extends Incident Investigator with the kinds of evidence a network/system administrator commonly checks before changing production.

## Evidence collected

- Probe hostname and FQDN
- Resolver inventory and `/etc/resolv.conf`
- DNS A, AAAA, CNAME, MX, NS, SOA, TXT and PTR/reverse evidence
- Optional comparison between the server's normal resolver and a selected resolver
- IPv4/IPv6 route tables, policy routing rules, neighbor cache and per-address `ip route get`
- UDP, ICMP and TCP traceroute variants
- Conservative IPv4 no-fragment path-MTU hints
- Requested TCP service reachability
- Existing HTTP and TLS evidence from Incident Investigator
- Optional bounded exposure review for a fixed set of common management/service ports
- Optional server-initiated banners for selected protocols
- Optional read-only device/server SSH correlation

## Deep routing evidence with live SSH

When `ENABLE_LIVE_SSH=true`, the shared read-only routing category is extended with platform-appropriate evidence such as route summaries, OSPF process/neighbor/interface/database state, BGP summary/neighbors, PIM, VRRP/HSRP and Linux route/socket state where supported. Unsupported commands are returned as errors; SchoolNet does not enter configuration mode.

Deep Network Engineer can also run one target-specific read-only route lookup from a supported device to the investigated destination. The destination is validated before the command template is generated.

## Security boundary

The exposure review is not a vulnerability exploit or broad scanner. It checks only one target and a fixed maximum of 16 common ports. Findings mean a service is reachable from the SchoolNet probe network and should be reviewed for necessity, segmentation, authentication and encryption. They do not prove compromise.

SchoolNet does not:

- run arbitrary user-supplied shell commands
- brute force or guess credentials
- exploit vulnerabilities
- make configuration changes
- save/reload/reboot devices
- scan address ranges

Public targets remain disabled by default with `ALLOW_PUBLIC_DIAGNOSTICS=false`. Live SSH remains disabled by default with `ENABLE_LIVE_SSH=false`.

## Operational interpretation

All path evidence originates from the SchoolNet backend container. A different client VLAN, VRF, firewall zone, WAN path or source address can produce different results. Validate key findings from the affected client or equivalent source context before remediation.
