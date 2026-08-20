# Changelog

## v1.6.0

- Added **Network Incident Investigator**, an evidence-driven read-only troubleshooting workflow.
- Added DNS A/AAAA and reverse lookup evidence, optional resolver selection, ICMP, backend route lookup, traceroute, bounded TCP checks, HTTP status, and TLS trust/protocol/certificate checks.
- Added correlation that distinguishes DNS, path, service/application, TLS, ICMP-filtering, and device-side failure signatures instead of treating every failed ping as an outage.
- Added optional read-only SSH evidence correlation using the existing multi-vendor command catalog.
- Added detection of native-VLAN mismatch, error-disabled interfaces, routing adjacency problems, link flaps, duplicate IP/MAC movement, AAA/DHCP warnings, and non-zero interface error counters from collected device evidence.
- Added optional bounded management-exposure checks and security findings for plaintext/inappropriately reachable administrative services.
- Added ranked root-cause hypotheses, confidence, recommended engineer next steps, and exportable Incident Passport JSON.
- Added guardrails: no arbitrary shell commands, no automatic changes, maximum 16 TCP checks, public diagnostics disabled by default, and live SSH disabled by default.
- Added dedicated Incident Investigator UI and diagnostic utilities to the production backend image.

## v1.5.0

- Added Network Safety Graph for multi-device topology and dependency inference.
- Added confidence-scored peer relationships from CDP/LLDP evidence, interface descriptions, shared transit networks, and BGP peer ownership.
- Added inferred device roles, VLAN/gateway context, routing protocols, graph components, bridge links, and potential single points of failure.
- Added peer-aware proposed-change validation for native VLANs, trunk VLANs, routed transit links, and routing relationships.
- Added network-wide change gate: BLOCK / HOLD / CAUTION / REVIEW.
- Added first-hop/second-hop impact propagation and network pre/post change contracts.
- Added Network Passport JSON export and dedicated Network Safety Graph UI.
- Added production v1.5 application assembly and API endpoint `/api/v1/network-graph`.

## v1.4.0

- Added Change Impact Lab for current-vs-proposed configuration analysis.
- Added change-risk scoring, blast-radius domains, Configuration DNA, Change Passport, rollback-aware runbooks, and change gates.

## v1.3.0

- Added universal multi-vendor parsing and platform auto-detection.
- Added evidence, confidence, impact, pre-check, rollback, and post-change validation fields.
- Added vendor-aware read-only live diagnostics with defensive command blocking.

## v1.2.0

- Added demo config loading support through API.
- Added config sanitization endpoint.
- Added Markdown report export endpoint.
- Added rule catalog endpoint.
- Improved Docker backend build context.
- Improved README, install guide, usage guide, issue templates, and PR template.
- Improved web UI first-time user flow.

## v1.1.0

- Added production Docker setup.
- Added CI workflow.
- Added batch/CSV validation endpoints.
- Added executive risk score and rule-based explanation endpoint.

## v1.0.0

- Initial MVP with Cisco/Aruba parsing, validation checks, remediation snippets, CLI, and web UI.
