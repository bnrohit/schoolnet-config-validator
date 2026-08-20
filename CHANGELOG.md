# Changelog

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
