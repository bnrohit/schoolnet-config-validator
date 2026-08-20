"""Evidence-driven network incident investigation for SchoolNet.

The investigator behaves like a cautious network/system engineer: it gathers
read-only evidence from the SchoolNet backend host (DNS, route, ICMP, trace,
TCP, HTTP/TLS) and can correlate an optional read-only device/server SSH
snapshot. It never runs user supplied shell commands and never changes a target.
"""
from __future__ import annotations

from datetime import datetime, timezone
import http.client
import ipaddress
import os
import re
import socket
import ssl
import subprocess
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from troubleshoot.commands import TroubleshootCommands
from troubleshoot.ssh_client import SwitchSSHClient


HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$")
DEFAULT_PORTS = [22, 53, 80, 443]
MANAGEMENT_PORTS = [21, 22, 23, 80, 443, 445, 830, 3389, 5900, 8080, 8443]
TLS_PORTS = {443, 636, 993, 995, 8443, 9443}
MAX_PORTS = 16


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _validate_hostname_or_ip(value: str) -> str:
    value = (value or "").strip().rstrip(".")
    if not value:
        raise ValueError("A target hostname or IP address is required.")
    if _is_ip(value):
        return value
    if not HOST_RE.match(value):
        raise ValueError("Target must be a valid hostname or IP address.")
    return value


def _allow_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    if os.getenv("ALLOW_PUBLIC_DIAGNOSTICS", "false").lower() in ("1", "true", "yes"):
        return True
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _run(args: List[str], timeout: int = 8) -> Dict[str, Any]:
    """Run one fixed executable/argument list. No shell interpolation is used."""
    started = time.monotonic()
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "available": True,
            "ok": proc.returncode == 0,
            "return_code": proc.returncode,
            "stdout": proc.stdout.strip()[:16000],
            "stderr": proc.stderr.strip()[:4000],
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
    except FileNotFoundError:
        return {"available": False, "ok": False, "error": f"{args[0]} is not installed in the backend container"}
    except subprocess.TimeoutExpired as exc:
        return {
            "available": True,
            "ok": False,
            "timed_out": True,
            "stdout": (exc.stdout or "")[:16000] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[:4000] if isinstance(exc.stderr, str) else "",
            "duration_ms": round((time.monotonic() - started) * 1000),
        }


def _dig(name: str, qtype: str, dns_server: str = "") -> Dict[str, Any]:
    qtype = qtype.upper()
    if qtype not in {"A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "PTR"}:
        raise ValueError("Unsupported DNS query type")
    args = ["dig", "+time=2", "+tries=1", "+short"]
    if dns_server:
        args.append(f"@{dns_server}")
    args.extend([name, qtype])
    result = _run(args, timeout=5)
    answers = [line.strip() for line in result.get("stdout", "").splitlines() if line.strip()]
    return {"query": name, "type": qtype, "server": dns_server or "system/default", "answers": answers, **result}


def _resolve(target: str, dns_server: str = "") -> Dict[str, Any]:
    addresses: List[str] = []
    error = None
    if _is_ip(target):
        addresses = [target]
    else:
        try:
            infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
            addresses = sorted({item[4][0] for item in infos})
        except socket.gaierror as exc:
            error = str(exc)

    dig_a = _dig(target, "A", dns_server) if not _is_ip(target) else None
    dig_aaaa = _dig(target, "AAAA", dns_server) if not _is_ip(target) else None
    if not addresses:
        for record in ((dig_a or {}).get("answers", []) + (dig_aaaa or {}).get("answers", [])):
            candidate = record.rstrip(".")
            if _is_ip(candidate):
                addresses.append(candidate)
    addresses = sorted(set(addresses))

    reverse = []
    for address in addresses[:4]:
        try:
            reverse.append({"address": address, "name": socket.gethostbyaddr(address)[0]})
        except Exception:
            reverse.append({"address": address, "name": None})
    return {
        "target": target,
        "addresses": addresses,
        "system_error": error,
        "dig_a": dig_a,
        "dig_aaaa": dig_aaaa,
        "reverse": reverse,
    }


def _ping(address: str) -> Dict[str, Any]:
    result = _run(["ping", "-c", "3", "-W", "2", address], timeout=8)
    text = result.get("stdout", "")
    loss = None
    avg = None
    match = re.search(r"(\d+(?:\.\d+)?)% packet loss", text)
    if match:
        loss = float(match.group(1))
    rtt = re.search(r"(?:rtt|round-trip).*?=\s*[\d.]+/([\d.]+)/", text)
    if rtt:
        avg = float(rtt.group(1))
    return {"address": address, "reachable": bool(result.get("ok")), "packet_loss_percent": loss, "avg_rtt_ms": avg, **result}


def _route(address: str) -> Dict[str, Any]:
    result = _run(["ip", "route", "get", address], timeout=4)
    text = result.get("stdout", "")
    dev = re.search(r"\bdev\s+(\S+)", text)
    via = re.search(r"\bvia\s+(\S+)", text)
    src = re.search(r"\bsrc\s+(\S+)", text)
    return {
        "address": address,
        "interface": dev.group(1) if dev else None,
        "next_hop": via.group(1) if via else None,
        "source_ip": src.group(1) if src else None,
        **result,
    }


def _trace(address: str, max_hops: int = 15) -> Dict[str, Any]:
    result = _run(["traceroute", "-n", "-m", str(max_hops), "-w", "1", "-q", "1", address], timeout=max_hops + 5)
    hops = []
    for line in result.get("stdout", "").splitlines():
        match = re.match(r"\s*(\d+)\s+(.+)", line)
        if not match:
            continue
        rest = match.group(2).strip()
        hop_ip = None
        ip_match = re.search(r"([0-9a-fA-F:.]+)", rest)
        if ip_match and ip_match.group(1) != "*":
            hop_ip = ip_match.group(1)
        hops.append({"hop": int(match.group(1)), "address": hop_ip, "raw": rest[:300]})
    return {"address": address, "hops": hops, **result}


def _tcp_probe(address: str, port: int, timeout: float = 2.5) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return {"port": port, "open": True, "latency_ms": round((time.monotonic() - started) * 1000), "error": None}
    except Exception as exc:
        return {"port": port, "open": False, "latency_ms": round((time.monotonic() - started) * 1000), "error": str(exc)[:300]}


def _tls_probe(hostname: str, address: str, port: int) -> Dict[str, Any]:
    server_name = None if _is_ip(hostname) else hostname
    started = time.monotonic()
    try:
        context = ssl.create_default_context()
        with socket.create_connection((address, port), timeout=4) as raw:
            with context.wrap_socket(raw, server_hostname=server_name or address) as tls:
                cert = tls.getpeercert() or {}
                not_after = cert.get("notAfter")
                days_remaining = None
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_remaining = (expiry - datetime.now(timezone.utc)).days
                return {
                    "port": port,
                    "ok": True,
                    "verified": True,
                    "protocol": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_after": not_after,
                    "days_remaining": days_remaining,
                    "latency_ms": round((time.monotonic() - started) * 1000),
                    "error": None,
                }
    except Exception as exc:
        # A failed certificate validation is useful evidence. Retry only to prove
        # that a TLS listener exists and capture protocol/cipher, never to trust it.
        verification_error = str(exc)[:500]
        try:
            context = ssl._create_unverified_context()
            with socket.create_connection((address, port), timeout=4) as raw:
                with context.wrap_socket(raw, server_hostname=server_name or address) as tls:
                    return {
                        "port": port,
                        "ok": True,
                        "verified": False,
                        "protocol": tls.version(),
                        "cipher": tls.cipher()[0] if tls.cipher() else None,
                        "latency_ms": round((time.monotonic() - started) * 1000),
                        "error": verification_error,
                    }
        except Exception as retry_exc:
            return {"port": port, "ok": False, "verified": False, "error": f"{verification_error}; retry: {retry_exc}"[:800]}


def _http_probe(hostname: str, address: str, port: int) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        headers = {"Host": hostname, "User-Agent": "SchoolNet-Incident-Investigator/1.6"}
        if port in TLS_PORTS:
            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(address, port=port, timeout=5, context=context)
            scheme = "https"
        else:
            conn = http.client.HTTPConnection(address, port=port, timeout=5)
            scheme = "http"
        conn.request("HEAD", "/", headers=headers)
        response = conn.getresponse()
        result = {
            "url": f"{scheme}://{hostname}:{port}/",
            "status": response.status,
            "reason": response.reason,
            "server": response.getheader("Server"),
            "location": response.getheader("Location"),
            "latency_ms": round((time.monotonic() - started) * 1000),
            "ok": True,
            "error": None,
        }
        conn.close()
        return result
    except Exception as exc:
        return {"port": port, "ok": False, "status": None, "error": str(exc)[:500], "latency_ms": round((time.monotonic() - started) * 1000)}


def _flatten_device_results(results: Iterable[Dict[str, Any]]) -> str:
    chunks: List[str] = []
    for category in results:
        chunks.append(f"## {category.get('category', '')}")
        for item in category.get("results", []):
            chunks.append(f"$ {item.get('command', '')}")
            output = item.get("output")
            chunks.append(str(output)[:20000])
            if item.get("error"):
                chunks.append(f"ERROR: {item.get('error')}")
    return "\n".join(chunks)


def _device_findings(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    text = _flatten_device_results(results)
    low = text.lower()
    findings: List[Dict[str, Any]] = []

    signatures = [
        ("critical", "Layer-2 loop / MAC movement evidence", r"(loop detected|mac(?: address)?[- ]flap|moving between ports|duplicate mac)", "A loop or MAC move event can cause severe packet loss or broadcast instability."),
        ("critical", "Duplicate IP evidence", r"(duplicate ip|duplicate address|ip address conflict)", "Duplicate addressing can create intermittent reachability and ARP instability."),
        ("high", "Native VLAN mismatch evidence", r"native vlan mismatch", "Peer native VLAN disagreement can break untagged/control traffic and produce spanning-tree inconsistencies."),
        ("high", "Interface error-disabled evidence", r"(err-?disabled|error-?disabled)", "An error-disabled interface is administratively suppressed by a protection mechanism and will not forward normally."),
        ("high", "Routing adjacency not established", r"\b(idle|active|connect|exstart|exchange|init)\b", "A dynamic routing neighbor may not be fully established; verify the specific neighbor state and protocol context."),
        ("medium", "Recent link-down / flap evidence", r"(line protocol.*down|changed state to down|link.*down|interface.*flap)", "Recent link transitions may explain intermittent connectivity; correlate timestamps and interface counters."),
        ("medium", "Authentication/AAA warning evidence", r"(tacacs.*fail|radius.*fail|authentication.*fail|aaa.*fail)", "Management authentication dependencies may be degraded or unreachable."),
        ("medium", "DHCP-related warning evidence", r"(dhcp.*fail|dhcp.*drop|dhcp.*snoop.*deny|no address available)", "DHCP control-plane or lease issues may affect endpoint address assignment."),
    ]
    for severity, title, pattern, impact in signatures:
        match = re.search(pattern, low, re.I)
        if match:
            start = max(0, match.start() - 120)
            end = min(len(text), match.end() + 220)
            findings.append({"severity": severity, "title": title, "impact": impact, "evidence": text[start:end].replace("\n", " ")[:500]})

    # Numeric CRC/input errors: only report non-zero counters.
    for match in re.finditer(r"(?i)(\d+)\s+(crc|input errors?|frame errors?|collisions?|output errors?|drops?)", text):
        try:
            count = int(match.group(1))
        except ValueError:
            continue
        if count > 0:
            findings.append({
                "severity": "high" if count >= 10 else "medium",
                "title": f"Non-zero {match.group(2)} counter",
                "impact": "Physical-layer, duplex, congestion, optic/cabling, or interface-health problems may be dropping traffic.",
                "evidence": match.group(0),
            })
            break

    return findings[:12]


def _run_device_snapshot(device: Dict[str, Any]) -> Dict[str, Any]:
    if not device or not device.get("enabled"):
        return {"enabled": False, "collected": False, "results": [], "findings": []}
    if os.getenv("ENABLE_LIVE_SSH", "false").lower() not in ("1", "true", "yes"):
        return {"enabled": True, "collected": False, "error": "Live SSH diagnostics are disabled by server policy (ENABLE_LIVE_SSH=false).", "results": [], "findings": []}

    categories = device.get("categories") or ["basic", "interfaces", "errors", "neighbors", "routing", "vlan", "stp", "security"]
    allowed_categories = [name for name in categories if name in TroubleshootCommands.LABELS][:10]
    client = SwitchSSHClient(
        host=_validate_hostname_or_ip(device.get("host") or ""),
        username=device.get("username") or "",
        password=device.get("password") or "",
        device_type=device.get("device_type") or "cisco_ios",
        port=int(device.get("port") or 22),
        secret=device.get("secret") or "",
    )
    try:
        with client:
            results = [TroubleshootCommands.run_check(client, category) for category in allowed_categories]
        return {
            "enabled": True,
            "collected": True,
            "host": client.host,
            "device_type": client.device_type,
            "categories": allowed_categories,
            "results": results,
            "findings": _device_findings(results),
            "credentials_stored": False,
        }
    except Exception as exc:
        return {"enabled": True, "collected": False, "host": client.host, "device_type": client.device_type, "error": str(exc)[:800], "results": [], "findings": []}


def _security_findings(port_results: List[Dict[str, Any]], tls_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    opened = {item["port"] for item in port_results if item.get("open")}
    findings: List[Dict[str, Any]] = []
    if 23 in opened:
        findings.append({"severity": "high", "title": "Telnet is reachable", "impact": "Telnet provides plaintext remote administration. Disable it where possible and restrict management access to SSH/HTTPS from approved management networks."})
    if 21 in opened:
        findings.append({"severity": "high", "title": "FTP is reachable", "impact": "Plain FTP can expose credentials/content. Prefer SFTP/SCP/HTTPS and restrict management-plane reachability."})
    if 80 in opened:
        findings.append({"severity": "medium" if 443 not in opened else "low", "title": "Plain HTTP is reachable", "impact": "Verify that HTTP redirects to HTTPS or is intentionally limited to a trusted management segment."})
    for port, label in ((3389, "RDP"), (5900, "VNC"), (445, "SMB"), (8080, "alternate HTTP management")):
        if port in opened:
            findings.append({"severity": "medium", "title": f"{label} is reachable", "impact": "Confirm this administrative/service exposure is required and limited by management ACL/firewall policy."})
    for tls in tls_results:
        if tls.get("ok") and not tls.get("verified"):
            findings.append({"severity": "medium", "title": f"TLS certificate validation failed on port {tls.get('port')}", "impact": tls.get("error") or "Certificate trust/hostname validation failed."})
        days = tls.get("days_remaining")
        if isinstance(days, int) and days < 30:
            findings.append({"severity": "high" if days < 7 else "medium", "title": f"TLS certificate expires in {days} day(s)", "impact": "Certificate expiry can cause management or application outages."})
    return findings


def _hypothesis(severity: str, score: int, title: str, evidence: str, next_step: str) -> Dict[str, Any]:
    return {"severity": severity, "score": score, "title": title, "evidence": evidence, "next_step": next_step}


def _correlate(target: str, resolved: Dict[str, Any], ping: Dict[str, Any], route: Dict[str, Any], ports: List[Dict[str, Any]], http_results: List[Dict[str, Any]], tls_results: List[Dict[str, Any]], device: Dict[str, Any]) -> List[Dict[str, Any]]:
    hypotheses: List[Dict[str, Any]] = []
    addresses = resolved.get("addresses", [])
    open_ports = [item["port"] for item in ports if item.get("open")]
    closed_ports = [item["port"] for item in ports if not item.get("open")]

    if not addresses:
        hypotheses.append(_hypothesis("high", 95, "DNS/name-resolution failure", resolved.get("system_error") or "No A/AAAA address was returned.", "Verify the authoritative record, resolver reachability, search suffix, DNS server selection, and split-DNS policy."))
        return hypotheses

    if route.get("ok") is False and route.get("available") and "unreachable" in (route.get("stderr", "") + route.get("stdout", "")).lower():
        hypotheses.append(_hypothesis("critical", 96, "No usable route from the SchoolNet probe host", route.get("stdout") or route.get("stderr") or "ip route get reported unreachable", "Check routing tables, VRF/source context, gateway state, tunnel/overlay state, and upstream route advertisements."))

    if not ping.get("reachable") and open_ports:
        hypotheses.append(_hypothesis("info", 70, "ICMP appears filtered while services remain reachable", f"ICMP failed but TCP port(s) {open_ports} accepted connections.", "Do not treat ping loss alone as an outage; verify firewall/ACL ICMP policy and test the actual application path."))
    elif ping.get("reachable") and closed_ports and not open_ports:
        hypotheses.append(_hypothesis("high", 84, "Host reachable but expected TCP services are not accepting connections", f"ICMP succeeds; checked TCP port(s) {closed_ports} are closed/filtered.", "Check the service process/listener, host firewall, network ACL/firewall policy, NAT/VIP mapping, and correct destination port."))
    elif not ping.get("reachable") and not open_ports:
        hypotheses.append(_hypothesis("high", 78, "End-to-end reachability problem or target unavailable", "ICMP failed and none of the requested TCP services accepted connections.", "Use the traceroute and route evidence to isolate the last known reachable hop; then verify VLAN/SVI, ARP/ND, routing, ACL/firewall, target power/link, and service state."))

    for http in http_results:
        status = http.get("status")
        if isinstance(status, int) and status >= 500:
            hypotheses.append(_hypothesis("high", 88, "Application/server error despite network reachability", f"HTTP returned {status} {http.get('reason', '')} on {http.get('url')}", "Investigate the application/reverse proxy/backend service and logs; the network path is reaching the HTTP service."))
        elif status in (401, 403):
            hypotheses.append(_hypothesis("info", 82, "Application reachable; authentication/policy denied the request", f"HTTP returned {status}.", "Treat this as an application/authentication/policy path rather than a basic network outage unless access should be anonymous."))

    for tls in tls_results:
        if tls.get("ok") and not tls.get("verified"):
            hypotheses.append(_hypothesis("medium", 86, "TLS trust or hostname validation problem", tls.get("error") or "TLS handshake only succeeded without certificate verification.", "Check certificate chain, SAN/hostname, trust store, expiry, and interception/reverse-proxy certificates."))

    for finding in device.get("findings", []):
        score = {"critical": 96, "high": 88, "medium": 68, "low": 45}.get(finding.get("severity"), 40)
        hypotheses.append(_hypothesis(finding.get("severity", "medium"), score, finding.get("title", "Device evidence"), finding.get("evidence") or finding.get("impact", ""), "Correlate this device evidence with interface/neighbor/routing/log timestamps before making a production change."))

    return sorted(hypotheses, key=lambda item: item["score"], reverse=True)[:12]


def investigate_incident(
    target: str,
    ports: Optional[List[int]] = None,
    dns_server: str = "",
    run_trace: bool = True,
    security_surface: bool = False,
    device: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    target = _validate_hostname_or_ip(target)
    if dns_server:
        dns_server = _validate_hostname_or_ip(dns_server)

    requested_ports = list(dict.fromkeys(int(port) for port in (ports or DEFAULT_PORTS)))
    if security_surface:
        requested_ports = list(dict.fromkeys(requested_ports + MANAGEMENT_PORTS))
    if len(requested_ports) > MAX_PORTS or any(port < 1 or port > 65535 for port in requested_ports):
        raise ValueError(f"Provide at most {MAX_PORTS} valid TCP ports (1-65535).")

    resolved = _resolve(target, dns_server)
    addresses = resolved.get("addresses", [])
    disallowed = [address for address in addresses if not _allow_ip(address)]
    if disallowed:
        raise ValueError("Target resolves to a public address. Public diagnostics are disabled by default; set ALLOW_PUBLIC_DIAGNOSTICS=true only for systems you are authorized to test.")
    if dns_server and _is_ip(dns_server) and not _allow_ip(dns_server):
        raise ValueError("Public DNS-server probing is disabled by policy.")

    primary = addresses[0] if addresses else None
    ping = _ping(primary) if primary else {"reachable": False, "error": "No resolved address"}
    route = _route(primary) if primary else {"ok": False, "error": "No resolved address"}
    trace = _trace(primary) if primary and run_trace else {"skipped": True, "reason": "trace disabled or target unresolved"}

    port_results = [_tcp_probe(primary, port) for port in requested_ports] if primary else []
    tls_results = [_tls_probe(target, primary, item["port"]) for item in port_results if item.get("open") and item["port"] in TLS_PORTS]
    http_results = [_http_probe(target, primary, item["port"]) for item in port_results if item.get("open") and item["port"] in {80, 443, 8080, 8443}]
    device_result = _run_device_snapshot(device or {})
    security_findings = _security_findings(port_results, tls_results)
    hypotheses = _correlate(target, resolved, ping, route, port_results, http_results, tls_results, device_result)

    if not hypotheses:
        overall = "no_clear_fault_found"
        confidence = 0.45
    else:
        top = hypotheses[0]
        overall = "probable_fault_found" if top["severity"] in {"critical", "high"} else "evidence_requires_review"
        confidence = round(top["score"] / 100, 2)

    next_actions: List[str] = []
    for item in hypotheses[:5]:
        if item.get("next_step") and item["next_step"] not in next_actions:
            next_actions.append(item["next_step"])
    if not next_actions:
        next_actions = [
            "Compare this evidence against a known-good baseline and the time the incident started.",
            "Check adjacent switch/router/firewall logs and monitoring alerts for the same timestamp.",
            "If the issue is intermittent, repeat the investigation while the symptom is active and compare the Incident Passport results.",
        ]

    return {
        "mode": "read_only_incident_investigation",
        "version": "1.6.0",
        "generated_at": _now(),
        "target": target,
        "primary_address": primary,
        "overall_state": overall,
        "confidence": confidence,
        "auto_execute": False,
        "probe_origin": "SchoolNet backend container",
        "dns": resolved,
        "path": {"route": route, "ping": ping, "traceroute": trace},
        "services": {"tcp": port_results, "http": http_results, "tls": tls_results},
        "security": {"surface_scan_enabled": security_surface, "findings": security_findings},
        "device_snapshot": device_result,
        "hypotheses": hypotheses,
        "recommended_next_actions": next_actions,
        "incident_passport": {
            "target": target,
            "addresses": addresses,
            "route_interface": route.get("interface"),
            "route_next_hop": route.get("next_hop"),
            "open_tcp_ports": [item["port"] for item in port_results if item.get("open")],
            "icmp_reachable": ping.get("reachable", False),
            "top_hypothesis": hypotheses[0]["title"] if hypotheses else None,
            "top_confidence": confidence,
            "security_findings": len(security_findings),
            "device_findings": len(device_result.get("findings", [])),
            "generated_at": _now(),
        },
        "safety_note": "SchoolNet gathers bounded read-only evidence only. Results reflect the SchoolNet server's network/VRF/path perspective and optional read-only SSH output; they do not prove every client path or dependency. Validate evidence before making changes.",
    }
