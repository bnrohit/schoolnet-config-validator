"""Bounded path-intelligence helpers for SchoolNet v1.9.

Adds hop PTR enrichment, MTR-style bounded per-hop sampling, trace-mode comparison,
and optional target-side return-route evidence. This is diagnostic evidence, not a
continuous scanner and not proof of asymmetric routing by itself.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional

from incident_investigator import _allow_ip, _run
from deep_diagnostics import _device_target_route


MAX_HOPS = 24
MAX_SAMPLES = 10


def _ptr(address: str, dns_server: str = "") -> Dict[str, Any]:
    args = ["dig", "+time=2", "+tries=1", "+short"]
    if dns_server:
        args.append(f"@{dns_server}")
    args.extend(["-x", address])
    result = _run(args, timeout=5)
    names = [line.strip().rstrip(".") for line in result.get("stdout", "").splitlines() if line.strip()]
    return {"address": address, "names": names[:4], "server": dns_server or "system/default", "ok": bool(names), **result}


def _ping_sample(address: str, count: int) -> Dict[str, Any]:
    count = max(3, min(MAX_SAMPLES, int(count or 5)))
    result = _run(["ping", "-n", "-c", str(count), "-W", "1", "-i", "0.25", address], timeout=count * 2 + 3)
    text = result.get("stdout", "")
    loss = None
    match = re.search(r"([\d.]+)% packet loss", text)
    if match:
        loss = float(match.group(1))
    stats = {"min_ms": None, "avg_ms": None, "max_ms": None, "jitter_ms": None}
    rtt = re.search(r"(?:rtt|round-trip).*?=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", text)
    if rtt:
        stats = {
            "min_ms": float(rtt.group(1)),
            "avg_ms": float(rtt.group(2)),
            "max_ms": float(rtt.group(3)),
            "jitter_ms": float(rtt.group(4)),
        }
    return {
        "address": address,
        "samples": count,
        "packet_loss_percent": loss,
        "icmp_replied": bool(result.get("ok")),
        **stats,
        "note": "Per-hop ICMP loss can reflect control-plane rate limiting; do not treat it as forwarding loss unless downstream hops show the same loss.",
        **result,
    }


def _unique_trace_addresses(trace_variants: Dict[str, Any]) -> List[str]:
    addresses: List[str] = []
    for mode in ("udp", "icmp", "tcp"):
        for hop in (trace_variants.get(mode) or {}).get("hops", []):
            address = hop.get("address")
            if not address or address in addresses:
                continue
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue
            if not _allow_ip(address):
                continue
            addresses.append(address)
            if len(addresses) >= MAX_HOPS:
                return addresses
    return addresses


def enrich_hops(trace_variants: Dict[str, Any], dns_server: str = "") -> Dict[str, Any]:
    cache: Dict[str, Dict[str, Any]] = {}
    enriched: Dict[str, List[Dict[str, Any]]] = {}
    for mode in ("udp", "icmp", "tcp"):
        rows: List[Dict[str, Any]] = []
        for hop in (trace_variants.get(mode) or {}).get("hops", []):
            row = dict(hop)
            address = row.get("address")
            if address:
                if address not in cache:
                    cache[address] = _ptr(address, dns_server)
                row["ptr_names"] = cache[address].get("names", [])
                row["display_name"] = (row["ptr_names"][0] if row["ptr_names"] else address)
            else:
                row["ptr_names"] = []
                row["display_name"] = "no reply"
            rows.append(row)
        enriched[mode] = rows
    return {"by_mode": enriched, "ptr_cache": cache}


def sample_path(trace_variants: Dict[str, Any], count: int = 5) -> List[Dict[str, Any]]:
    return [_ping_sample(address, count) for address in _unique_trace_addresses(trace_variants)]


def compare_trace_modes(trace_variants: Dict[str, Any]) -> Dict[str, Any]:
    sequences: Dict[str, List[Optional[str]]] = {}
    for mode in ("udp", "icmp", "tcp"):
        sequences[mode] = [hop.get("address") for hop in (trace_variants.get(mode) or {}).get("hops", [])]

    max_len = max([len(value) for value in sequences.values()] or [0])
    divergence = None
    rows: List[Dict[str, Any]] = []
    for idx in range(max_len):
        values = {mode: (seq[idx] if idx < len(seq) else None) for mode, seq in sequences.items()}
        non_null = {value for value in values.values() if value}
        if divergence is None and len(non_null) > 1:
            divergence = idx + 1
        rows.append({"hop": idx + 1, **values, "same_address": len(non_null) <= 1})

    completed = {}
    for mode, seq in sequences.items():
        completed[mode] = bool(seq and seq[-1])
    return {
        "sequences": sequences,
        "hop_comparison": rows,
        "first_address_divergence_hop": divergence,
        "note": "Different traceroute modes may receive different control-plane replies even when application forwarding is healthy. Treat divergence as evidence to investigate, not proof of a fault.",
    }


def build_path_intelligence(
    payload: Dict[str, Any],
    dns_server: str = "",
    sample_count: int = 5,
    device: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    deep = payload.get("deep_diagnostics", {})
    traces = deep.get("trace_variants", {})
    route_matrix = deep.get("route_matrix", [])
    source_ip = None
    for row in route_matrix:
        if row.get("source_ip"):
            source_ip = row["source_ip"]
            break

    enriched = enrich_hops(traces, dns_server) if traces else {"by_mode": {}, "ptr_cache": {}}
    samples = sample_path(traces, sample_count) if traces else []
    comparison = compare_trace_modes(traces) if traces else {"sequences": {}, "hop_comparison": [], "first_address_divergence_hop": None}

    return_route = {"enabled": False, "collected": False, "reason": "no optional live device context"}
    if device and device.get("enabled") and source_ip:
        return_route = _device_target_route(device, source_ip)
        return_route["lookup_purpose"] = "route from optional target/next-hop device back toward the SchoolNet probe source"
        return_route["probe_source_ip"] = source_ip

    high_loss = [
        item for item in samples
        if isinstance(item.get("packet_loss_percent"), (int, float)) and item["packet_loss_percent"] >= 50
    ]
    path_findings: List[Dict[str, Any]] = []
    if comparison.get("first_address_divergence_hop"):
        path_findings.append({
            "severity": "info",
            "title": "Traceroute modes diverge",
            "detail": f"The first address-level divergence appears at hop {comparison['first_address_divergence_hop']}. Compare firewall/control-plane policy before treating this as a forwarding fault.",
        })
    if high_loss:
        path_findings.append({
            "severity": "medium",
            "title": "One or more hops did not consistently answer ICMP sampling",
            "detail": "High per-hop ICMP loss was observed. If downstream hops remain healthy, this is likely control-plane rate limiting rather than packet forwarding loss.",
        })

    return {
        "hop_dns": enriched,
        "bounded_path_samples": samples,
        "trace_mode_comparison": comparison,
        "return_path_route_evidence": return_route,
        "findings": path_findings,
        "sample_count": max(3, min(MAX_SAMPLES, int(sample_count or 5))),
        "guardrails": {
            "continuous_indefinite_monitoring": False,
            "max_samples_per_hop": MAX_SAMPLES,
            "max_hops_sampled": MAX_HOPS,
            "single_authorized_target": True,
        },
    }
