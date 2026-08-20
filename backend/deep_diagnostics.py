"""SchoolNet Deep Network Engineer diagnostics.

This module extends the bounded Incident Investigator with deeper read-only
network/system evidence. It intentionally avoids arbitrary shell execution,
credential guessing, exploitation, configuration changes, and broad scanning.
Every active probe is limited to one authorized target and fixed diagnostic
commands/arguments.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import os
import re
import socket
from typing import Any, Dict, List, Optional

from incident_investigator import (
    _allow_ip,
    _dig,
    _is_ip,
    _run,
    _tcp_probe,
    _validate_hostname_or_ip,
    investigate_incident,
)
from troubleshoot.ssh_client import SwitchSSHClient


VERSION = "1.7.0"
MAX_EXPOSURE_PORTS = 16
EXPOSURE_PORTS = [21, 22, 23, 80, 443, 445, 830, 3389, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 27017]
SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS/TCP",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    830: "NETCONF/SSH",
    3389: "RDP",
    5900: "VNC",
    5985: "WinRM/HTTP",
    5986: "WinRM/HTTPS",
    6379: "Redis",
    8080: "Alternate HTTP",
    8443: "Alternate HTTPS",
    9200: "Elasticsearch HTTP",
    27017: "MongoDB",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_read(path: str, limit: int = 12000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except Exception as exc:
        return f"unavailable: {exc}"


def _nameservers() -> List[str]:
    servers: List[str] = []
    for line in _safe_read("/etc/resolv.conf", 8000).splitlines():
        match = re.match(r"^\s*nameserver\s+(\S+)", line)
        if match:
            servers.append(match.group(1))
    return servers[:8]


def _system_context() -> Dict[str, Any]:
    return {
        "probe_hostname": socket.gethostname(),
        "probe_fqdn": socket.getfqdn(),
        "resolver_nameservers": _nameservers(),
        "resolv_conf": _safe_read("/etc/resolv.conf", 8000),
        "addresses": _run(["ip", "-brief", "address"], timeout=5),
        "routes_ipv4": _run(["ip", "-4", "route", "show", "table", "main"], timeout=5),
        "routes_ipv6": _run(["ip", "-6", "route", "show", "table", "main"], timeout=5),
        "policy_rules": _run(["ip", "rule", "show"], timeout=5),
        "neighbors": _run(["ip", "neigh", "show"], timeout=5),
    }


def _reverse_dig(address: str, dns_server: str = "") -> Dict[str, Any]:
    args = ["dig", "+time=2", "+tries=1", "+short"]
    if dns_server:
        args.append(f"@{dns_server}")
    args.extend(["-x", address])
    result = _run(args, timeout=5)
    answers = [line.strip().rstrip(".") for line in result.get("stdout", "").splitlines() if line.strip()]
    return {"address": address, "server": dns_server or "system/default", "answers": answers, **result}


def _deep_dns(target: str, addresses: List[str], dns_server: str = "") -> Dict[str, Any]:
    records: Dict[str, Any] = {}
    if not _is_ip(target):
        for qtype in ("A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"):
            records[qtype] = _dig(target, qtype, dns_server)
    reverse = [_reverse_dig(address, dns_server) for address in addresses[:4]]

    resolver_comparison: Dict[str, Any] = {"compared": False}
    if dns_server and not _is_ip(target):
        system_a = _dig(target, "A", "")
        selected_a = records.get("A") or _dig(target, "A", dns_server)
        system_ips = sorted({item.rstrip(".") for item in system_a.get("answers", []) if _is_ip(item.rstrip("."))})
        selected_ips = sorted({item.rstrip(".") for item in selected_a.get("answers", []) if _is_ip(item.rstrip("."))})
        resolver_comparison = {
            "compared": True,
            "system_addresses": system_ips,
            "selected_resolver_addresses": selected_ips,
            "match": system_ips == selected_ips,
        }
    return {"records": records, "reverse_dig": reverse, "resolver_comparison": resolver_comparison}


def _parse_trace(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    hops: List[Dict[str, Any]] = []
    for line in result.get("stdout", "").splitlines():
        match = re.match(r"\s*(\d+)\s+(.+)", line)
        if not match:
            continue
        rest = match.group(2).strip()
        address = None
        ip_match = re.search(r"(?<![A-Za-z0-9])([0-9a-fA-F:.]{3,})(?![A-Za-z0-9])", rest)
        if ip_match:
            candidate = ip_match.group(1).rstrip(".")
            try:
                ipaddress.ip_address(candidate)
                address = candidate
            except ValueError:
                pass
        hops.append({"hop": int(match.group(1)), "address": address, "raw": rest[:300]})
    return hops


def _trace_variant(address: str, mode: str, tcp_port: int = 443, max_hops: int = 20) -> Dict[str, Any]:
    if mode == "icmp":
        args = ["traceroute", "-I", "-n", "-m", str(max_hops), "-w", "1", "-q", "1", address]
    elif mode == "tcp":
        args = ["traceroute", "-T", "-p", str(tcp_port), "-n", "-m", str(max_hops), "-w", "1", "-q", "1", address]
    else:
        args = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", "-q", "1", address]
    result = _run(args, timeout=max_hops + 8)
    return {"mode": mode, "tcp_port": tcp_port if mode == "tcp" else None, "hops": _parse_trace(result), **result}


def _route_matrix(addresses: List[str]) -> List[Dict[str, Any]]:
    matrix: List[Dict[str, Any]] = []
    for address in addresses[:6]:
        result = _run(["ip", "route", "get", address], timeout=5)
        text = result.get("stdout", "")
        dev = re.search(r"\bdev\s+(\S+)", text)
        via = re.search(r"\bvia\s+(\S+)", text)
        src = re.search(r"\bsrc\s+(\S+)", text)
        matrix.append({
            "address": address,
            "interface": dev.group(1) if dev else None,
            "next_hop": via.group(1) if via else None,
            "source_ip": src.group(1) if src else None,
            **result,
        })
    return matrix


def _path_mtu(address: str) -> Dict[str, Any]:
    """Conservative IPv4 PMTU hints using a few no-fragment ICMP probes.

    Failure is not treated as proof of an MTU problem because ICMP may be filtered.
    """
    try:
        if ipaddress.ip_address(address).version != 4:
            return {"supported": False, "reason": "IPv4 PMTU hint only"}
    except ValueError:
        return {"supported": False, "reason": "invalid address"}

    attempts = []
    largest_success = None
    for payload in (1472, 1400, 1300, 1200):
        result = _run(["ping", "-c", "1", "-W", "2", "-M", "do", "-s", str(payload), address], timeout=4)
        success = bool(result.get("ok"))
        attempts.append({"payload_bytes": payload, "estimated_ip_mtu": payload + 28, "success": success, "stderr": result.get("stderr", "")[:300]})
        if success and largest_success is None:
            largest_success = payload + 28
    return {
        "supported": True,
        "largest_confirmed_ip_mtu": largest_success,
        "attempts": attempts,
        "note": "Inconclusive when ICMP is filtered; this is a hint, not proof of PMTU.",
    }


def _banner_probe(address: str, port: int) -> Dict[str, Any]:
    """Read a server-initiated banner only; no protocol commands or credentials."""
    if port not in {21, 22, 23, 25, 110, 143}:
        return {"port": port, "attempted": False}
    try:
        with socket.create_connection((address, port), timeout=2) as sock:
            sock.settimeout(1.25)
            data = sock.recv(512)
        text = "".join(chr(byte) if 32 <= byte < 127 or byte in (9, 10, 13) else "." for byte in data)
        return {"port": port, "attempted": True, "banner": text.strip()[:500], "error": None}
    except Exception as exc:
        return {"port": port, "attempted": True, "banner": "", "error": str(exc)[:300]}


def _exposure_findings(probes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    open_ports = {item["port"] for item in probes if item.get("open")}
    findings: List[Dict[str, Any]] = []

    catalog = {
        21: ("high", "FTP service reachable", "Plain FTP can expose credentials and data. Prefer SFTP/SCP/HTTPS and restrict access to approved management networks."),
        23: ("critical", "Telnet service reachable", "Telnet provides plaintext interactive administration. Disable it where possible and use SSH from restricted management networks."),
        445: ("medium", "SMB reachable from this network segment", "Confirm SMB exposure is required and constrained by host/network firewall policy; avoid unnecessary cross-segment administrative reachability."),
        3389: ("medium", "RDP reachable from this network segment", "Confirm RDP is intentionally reachable only from approved administration networks and protected by strong authentication/policy."),
        5900: ("high", "VNC reachable", "VNC is a high-value remote-management surface. Confirm encryption/authentication and restrict it to approved management paths."),
        5985: ("medium", "WinRM over HTTP reachable", "Confirm WinRM HTTP is required, authenticated, and management-network restricted; prefer HTTPS where practical."),
        5986: ("low", "WinRM over HTTPS reachable", "Validate certificate trust and confirm management-network restriction."),
        6379: ("high", "Redis service reachable", "Redis should normally be tightly segmented and authenticated. Verify it is not broadly reachable from user or untrusted networks."),
        9200: ("high", "Elasticsearch HTTP API reachable", "Verify authentication/TLS and restrict the API to trusted application or administration networks."),
        27017: ("high", "MongoDB service reachable", "Verify authentication/TLS and restrict database reachability to only required application/administration networks."),
        8080: ("medium", "Alternate HTTP service reachable", "Review whether this is a management/application listener and whether plaintext access is necessary."),
        8443: ("low", "Alternate HTTPS service reachable", "Confirm this listener is expected and access-restricted; validate TLS policy/certificate."),
    }
    for port, (severity, title, impact) in catalog.items():
        if port in open_ports:
            findings.append({"severity": severity, "port": port, "service": SERVICE_NAMES.get(port), "title": title, "impact": impact})
    if 80 in open_ports and 443 not in open_ports:
        findings.append({"severity": "medium", "port": 80, "service": "HTTP", "title": "HTTP reachable without HTTPS detected", "impact": "If this is a management or authenticated application, verify transport encryption or a controlled redirect path."})
    return findings


def _exposure_review(address: str) -> Dict[str, Any]:
    probes = [{**_tcp_probe(address, port), "service": SERVICE_NAMES.get(port, "unknown")} for port in EXPOSURE_PORTS[:MAX_EXPOSURE_PORTS]]
    banners = [_banner_probe(address, item["port"]) for item in probes if item.get("open")]
    return {
        "ports_checked": EXPOSURE_PORTS[:MAX_EXPOSURE_PORTS],
        "tcp": probes,
        "banners": [item for item in banners if item.get("attempted")],
        "findings": _exposure_findings(probes),
        "note": "Exposure review is a bounded reachability check from the SchoolNet server, not a vulnerability exploit or full scanner.",
    }


def _device_route_command(device_type: str, address: str) -> Optional[str]:
    dt = (device_type or "").lower()
    if "linux" in dt:
        return f"ip route get {address}"
    if "juniper" in dt or "junos" in dt:
        return f"show route {address} detail"
    if "comware" in dt:
        return f"display ip routing-table {address}"
    if "extreme" in dt:
        return f"show iproute {address}"
    if "fortinet" in dt:
        return f"get router info routing-table details {address}"
    if "paloalto" in dt:
        return f"show routing route destination {address}"
    if "mikrotik" in dt:
        return None
    if any(token in dt for token in ("cisco", "nxos", "arista", "aoscx", "procurve", "fastiron", "ruckus", "brocade", "dell", "vyos")):
        return f"show ip route {address}"
    return None


def _device_target_route(device: Dict[str, Any], address: str) -> Dict[str, Any]:
    if not device or not device.get("enabled"):
        return {"enabled": False, "collected": False}
    if os.getenv("ENABLE_LIVE_SSH", "false").lower() not in ("1", "true", "yes"):
        return {"enabled": True, "collected": False, "error": "ENABLE_LIVE_SSH=false"}
    command = _device_route_command(device.get("device_type") or "", address)
    if not command:
        return {"enabled": True, "collected": False, "error": "No safe target-specific route lookup template is defined for this driver."}

    host = _validate_hostname_or_ip(device.get("host") or "")
    client = SwitchSSHClient(
        host=host,
        username=device.get("username") or "",
        password=device.get("password") or "",
        device_type=device.get("device_type") or "cisco_ios",
        port=int(device.get("port") or 22),
        secret=device.get("secret") or "",
    )
    try:
        with client:
            result = client.run_command(command, use_textfsm=False)
        return {"enabled": True, "collected": True, "host": host, "command": command, "result": result, "credentials_stored": False}
    except Exception as exc:
        return {"enabled": True, "collected": False, "host": host, "command": command, "error": str(exc)[:800]}


def _fault_domains(base: Dict[str, Any], deep: Dict[str, Any]) -> List[Dict[str, Any]]:
    dns = base.get("dns", {})
    ping = base.get("path", {}).get("ping", {})
    route = base.get("path", {}).get("route", {})
    tcp = base.get("services", {}).get("tcp", [])
    http = base.get("services", {}).get("http", [])
    tls = base.get("services", {}).get("tls", [])
    exposure = deep.get("security_exposure", {})

    open_count = sum(1 for item in tcp if item.get("open"))
    return [
        {"domain": "DNS", "status": "healthy" if dns.get("addresses") else "fault", "evidence": f"Resolved addresses: {', '.join(dns.get('addresses', [])) or 'none'}"},
        {"domain": "Routing", "status": "healthy" if route.get("ok") else "fault", "evidence": route.get("stdout") or route.get("stderr") or route.get("error") or "No route evidence"},
        {"domain": "ICMP", "status": "healthy" if ping.get("reachable") else "unknown_or_filtered", "evidence": f"packet loss={ping.get('packet_loss_percent')}%, avg={ping.get('avg_rtt_ms')} ms"},
        {"domain": "TCP services", "status": "healthy" if open_count else "fault_or_filtered", "evidence": f"{open_count}/{len(tcp)} requested TCP ports accepted connections"},
        {"domain": "Application", "status": "healthy" if any(item.get('ok') and isinstance(item.get('status'), int) and item.get('status') < 500 for item in http) else ("fault" if http else "not_tested"), "evidence": "; ".join(f"{item.get('status')} {item.get('url', item.get('port'))}" for item in http)[:800]},
        {"domain": "TLS", "status": "healthy" if tls and all(item.get('verified') for item in tls) else ("review" if tls else "not_tested"), "evidence": "; ".join(f"port {item.get('port')} {item.get('protocol')} verified={item.get('verified')}" for item in tls)[:800]},
        {"domain": "Security surface", "status": "review" if exposure.get("findings") else "no_high_signal_exposure_found", "evidence": f"{len(exposure.get('findings', []))} bounded exposure finding(s)"},
    ]


def deep_investigate(
    target: str,
    ports: Optional[List[int]] = None,
    dns_server: str = "",
    run_trace: bool = True,
    security_surface: bool = True,
    device: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run Incident Investigator plus deeper engineer-style diagnostics."""
    base = investigate_incident(
        target=target,
        ports=ports,
        dns_server=dns_server,
        run_trace=run_trace,
        security_surface=False,  # deep exposure is handled separately and remains bounded to 16 ports
        device=device or {},
    )
    base["version"] = VERSION
    base["mode"] = "deep_read_only_network_engineer"

    primary = base.get("primary_address")
    addresses = base.get("dns", {}).get("addresses", [])
    if not primary:
        base["deep_diagnostics"] = {
            "system_context": _system_context(),
            "dns_deep": _deep_dns(_validate_hostname_or_ip(target), [], dns_server),
            "route_matrix": [],
            "trace_variants": {},
            "path_mtu": {"supported": False, "reason": "target unresolved"},
            "security_exposure": {"skipped": True, "reason": "target unresolved"},
            "device_target_route": {"collected": False, "reason": "target unresolved"},
        }
        return base

    if not _allow_ip(primary):
        raise ValueError("Public diagnostics are disabled by default; enable only for systems you are authorized to test.")

    requested_ports = [int(port) for port in (ports or [22, 53, 80, 443])]
    tcp_trace_port = 443 if 443 in requested_ports else (requested_ports[0] if requested_ports else 443)
    trace_variants = {}
    if run_trace:
        trace_variants = {
            "udp": _trace_variant(primary, "udp"),
            "icmp": _trace_variant(primary, "icmp"),
            "tcp": _trace_variant(primary, "tcp", tcp_port=tcp_trace_port),
        }

    deep = {
        "system_context": _system_context(),
        "dns_deep": _deep_dns(_validate_hostname_or_ip(target), addresses, dns_server),
        "route_matrix": _route_matrix(addresses),
        "trace_variants": trace_variants,
        "path_mtu": _path_mtu(primary),
        "security_exposure": _exposure_review(primary) if security_surface else {"skipped": True, "reason": "security exposure review disabled"},
        "device_target_route": _device_target_route(device or {}, primary),
    }
    deep["fault_domains"] = _fault_domains(base, deep)

    extra_security = deep.get("security_exposure", {}).get("findings", [])
    base.setdefault("security", {}).setdefault("findings", []).extend(extra_security)
    base["security"]["deep_surface_review"] = security_surface

    # Add high-signal deep hypotheses without pretending that exposure alone proves compromise.
    hypotheses = list(base.get("hypotheses", []))
    resolver_cmp = deep.get("dns_deep", {}).get("resolver_comparison", {})
    if resolver_cmp.get("compared") and not resolver_cmp.get("match"):
        hypotheses.append({
            "severity": "medium", "score": 74, "title": "DNS resolver disagreement",
            "evidence": f"System resolver returned {resolver_cmp.get('system_addresses')}; selected resolver returned {resolver_cmp.get('selected_resolver_addresses')}",
            "next_step": "Check split-DNS views, resolver configuration, stale records, conditional forwarders, and client DNS-server selection before changing routing.",
        })
    mtu = deep.get("path_mtu", {})
    if mtu.get("supported") and mtu.get("largest_confirmed_ip_mtu") and mtu.get("largest_confirmed_ip_mtu") < 1500:
        hypotheses.append({
            "severity": "medium", "score": 66, "title": "Path-MTU constraint detected",
            "evidence": f"Largest confirmed IPv4 no-fragment MTU from this probe was {mtu.get('largest_confirmed_ip_mtu')} bytes.",
            "next_step": "Validate tunnel/overlay MTU, ICMP fragmentation-needed handling, MSS adjustment, and the same path from the affected client before changing interfaces.",
        })
    for finding in extra_security:
        if finding.get("severity") in {"critical", "high"}:
            hypotheses.append({
                "severity": finding["severity"], "score": 72 if finding["severity"] == "high" else 85,
                "title": finding.get("title"),
                "evidence": f"TCP/{finding.get('port')} ({finding.get('service')}) is reachable from the SchoolNet probe network.",
                "next_step": finding.get("impact"),
            })
    base["hypotheses"] = sorted(hypotheses, key=lambda item: item.get("score", 0), reverse=True)[:16]
    if base["hypotheses"]:
        base["confidence"] = round(base["hypotheses"][0].get("score", 0) / 100, 2)
        if base["hypotheses"][0].get("severity") in {"critical", "high"}:
            base["overall_state"] = "probable_fault_or_security_risk_found"

    base["deep_diagnostics"] = deep
    passport = base.setdefault("incident_passport", {})
    passport.update({
        "version": VERSION,
        "probe_hostname": deep["system_context"].get("probe_hostname"),
        "probe_fqdn": deep["system_context"].get("probe_fqdn"),
        "route_paths_evaluated": len(deep.get("route_matrix", [])),
        "trace_modes": list(deep.get("trace_variants", {}).keys()),
        "largest_confirmed_ip_mtu": deep.get("path_mtu", {}).get("largest_confirmed_ip_mtu"),
        "deep_security_findings": len(extra_security),
        "device_target_route_collected": deep.get("device_target_route", {}).get("collected", False),
        "generated_at": _now(),
    })
    base["safety_note"] = (
        "SchoolNet v1.7 gathers bounded read-only evidence from one authorized target and optional predefined read-only device SSH. "
        "Security exposure findings describe reachable attack surface, not proof of exploitation. Route/traceroute/MTU evidence reflects the SchoolNet server's path and must be validated from the affected client/VRF before production changes."
    )
    return base
