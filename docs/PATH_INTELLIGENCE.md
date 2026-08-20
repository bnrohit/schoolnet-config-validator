# SchoolNet v1.9 — Path Intelligence & Drift Lab

SchoolNet v1.9 adds a bounded, read-only path-analysis workflow intended for authorized enterprise/K-12 troubleshooting.

## What it collects

For one authorized target, Path Intelligence can combine:

- enterprise/default DNS context and hop-by-hop PTR lookups
- UDP, ICMP, and TCP traceroute paths
- bounded per-hop ICMP samples (3–10) for loss, min/avg/max latency, and jitter
- automatic HTTP/TLS application assurance inherited from Deep Network Engineer
- optional read-only device route lookup toward the target
- optional read-only route lookup from the device back toward the SchoolNet probe source
- optional VRF/routing-instance context for supported vendors

Per-hop ICMP loss is not automatically treated as forwarding loss. Routers may rate-limit control-plane replies while forwarding traffic normally. SchoolNet therefore keeps the application path and downstream-hop evidence visible next to loss/jitter samples.

## Diagnostic history

History is opt-in because troubleshooting evidence can contain internal addressing, hostnames, route information, and service exposure.

Enable it in `.env`:

```env
ENABLE_DIAGNOSTIC_HISTORY=true
DIAGNOSTIC_HISTORY_DB=/data/diagnostic_history.sqlite3
DIAGNOSTIC_HISTORY_RETENTION=100
```

The Docker Compose file mounts a named volume at `/data`. Never use `docker compose down -v` if you want to preserve history.

Saved snapshots never receive the request username/password/enable secret. They store the diagnostic result payload only.

History comparison currently highlights:

- open TCP ports added/removed
- fault-domain state changes
- Application/TLS state changes
- security-finding count drift
- resolver changes
- top-hypothesis changes
- traceroute-sequence changes

## Export

The Path Intelligence UI supports:

- JSON export for incident/change records
- browser **Print / Save PDF** for a human-readable evidence packet

## VRF-aware route evidence

With HTTPS in front of SchoolNet, `ENABLE_LIVE_SSH=true`, and a least-privilege read-only account, the optional device section can perform predefined route lookups in a routing instance/VRF on supported platforms. Unsupported driver/VRF combinations are reported rather than guessed.

This route evidence helps identify obvious forward/return route discrepancies but does **not** prove end-to-end path symmetry. A true return-path measurement requires a probe or telemetry source on the remote side.

## Guardrails

Path Intelligence intentionally does not provide:

- indefinite/continuous monitoring loops
- subnet/range scanning
- credential guessing
- vulnerability exploitation
- arbitrary shell execution
- automatic device configuration changes

Packet capture is not enabled by default. A future capture feature should use a separately authorized capture worker with explicit interface/filter/time/size limits because PCAP data can contain sensitive payloads and requires elevated host/container permissions.
