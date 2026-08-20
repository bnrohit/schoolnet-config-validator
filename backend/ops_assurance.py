"""Operational hardening helpers for SchoolNet v1.8.

Provides configurable enterprise DNS context, transport-policy checks for live
credentials, and bounded one-target HTTP/TLS assurance. No scanning, brute force,
or exploitation is performed.
"""
from __future__ import annotations

from datetime import datetime, timezone
import http.client
import os
import socket
import ssl
from typing import Any, Dict, Iterable, List


WEB_PORTS = (80, 443, 8080, 8443)
TLS_PORTS = (443, 8443)
MAX_APP_PORTS = 4


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def effective_dns_server(explicit: str = "") -> Dict[str, str]:
    """Return the resolver SchoolNet should use and explain where it came from."""
    explicit = (explicit or "").strip()
    configured = os.getenv("DEFAULT_DNS_SERVER", "").strip()
    if explicit:
        return {"server": explicit, "source": "request", "label": "request-selected resolver"}
    if configured:
        return {"server": configured, "source": "environment", "label": "SchoolNet default resolver"}
    return {"server": "", "source": "system", "label": "container/system resolver"}


def request_is_secure(scheme: str, forwarded_proto: str = "") -> bool:
    forwarded = (forwarded_proto or "").split(",", 1)[0].strip().lower()
    return forwarded == "https" or (scheme or "").lower() == "https"


def credential_transport_allowed(scheme: str, forwarded_proto: str = "") -> Dict[str, Any]:
    required = env_bool("REQUIRE_HTTPS_FOR_LIVE_CREDENTIALS", True)
    secure = request_is_secure(scheme, forwarded_proto)
    override = env_bool("ALLOW_INSECURE_LIVE_CREDENTIALS", False)
    allowed = secure or not required or override
    return {
        "allowed": allowed,
        "secure_transport": secure,
        "https_required": required,
        "insecure_override": override,
    }


def _headers_dict(response: http.client.HTTPResponse) -> Dict[str, str]:
    wanted = {
        "server", "location", "content-type", "content-length", "cache-control",
        "strict-transport-security", "content-security-policy", "x-frame-options",
        "x-content-type-options", "referrer-policy", "permissions-policy",
    }
    headers: Dict[str, str] = {}
    for key, value in response.getheaders():
        low = key.lower()
        if low in wanted:
            headers[low] = value[:1000]
    return headers


def _http_probe(hostname: str, address: str, port: int) -> Dict[str, Any]:
    tls = port in TLS_PORTS
    started = datetime.now(timezone.utc)
    try:
        headers = {"Host": hostname, "User-Agent": "SchoolNet-Application-Assurance/1.8"}
        if tls:
            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(address, port=port, timeout=5, context=context)
            scheme = "https"
        else:
            conn = http.client.HTTPConnection(address, port=port, timeout=5)
            scheme = "http"
        conn.request("HEAD", "/", headers=headers)
        response = conn.getresponse()
        selected_headers = _headers_dict(response)
        conn.close()
        return {
            "port": port,
            "url": f"{scheme}://{hostname}:{port}/",
            "reachable": True,
            "status": response.status,
            "reason": response.reason,
            "headers": selected_headers,
            "duration_ms": round((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            "error": None,
        }
    except Exception as exc:
        return {
            "port": port,
            "url": f"{'https' if tls else 'http'}://{hostname}:{port}/",
            "reachable": False,
            "status": None,
            "headers": {},
            "duration_ms": round((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            "error": str(exc)[:800],
        }


def _tls_probe(hostname: str, address: str, port: int) -> Dict[str, Any]:
    server_name = None
    try:
        socket.inet_pton(socket.AF_INET, hostname)
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
        except OSError:
            server_name = hostname

    started = datetime.now(timezone.utc)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((address, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=server_name or address) as tls:
                cert = tls.getpeercert() or {}
                not_after = cert.get("notAfter")
                not_before = cert.get("notBefore")
                days_remaining = None
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_remaining = (expiry - datetime.now(timezone.utc)).days
                sans = [value for kind, value in cert.get("subjectAltName", []) if kind in {"DNS", "IP Address"}]
                return {
                    "port": port,
                    "reachable": True,
                    "verified": True,
                    "protocol": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "subject_alt_names": sans[:50],
                    "not_before": not_before,
                    "not_after": not_after,
                    "days_remaining": days_remaining,
                    "duration_ms": round((datetime.now(timezone.utc) - started).total_seconds() * 1000),
                    "error": None,
                }
    except Exception as exc:
        verified_error = str(exc)[:800]
        try:
            context = ssl._create_unverified_context()
            with socket.create_connection((address, port), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=server_name or address) as tls:
                    return {
                        "port": port,
                        "reachable": True,
                        "verified": False,
                        "protocol": tls.version(),
                        "cipher": tls.cipher()[0] if tls.cipher() else None,
                        "duration_ms": round((datetime.now(timezone.utc) - started).total_seconds() * 1000),
                        "error": verified_error,
                    }
        except Exception as retry_exc:
            return {
                "port": port,
                "reachable": False,
                "verified": False,
                "error": f"{verified_error}; listener retry: {retry_exc}"[:1000],
            }


def _application_findings(http_results: Iterable[Dict[str, Any]], tls_results: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for item in http_results:
        if not item.get("reachable"):
            continue
        status = item.get("status")
        headers = item.get("headers") or {}
        port = item.get("port")
        if isinstance(status, int) and status >= 500:
            findings.append({"severity": "high", "title": f"HTTP {status} on port {port}", "detail": "The application endpoint is reachable but is returning a server-side error; investigate the application/reverse proxy/backend rather than changing routing first."})
        if port in TLS_PORTS:
            if "strict-transport-security" not in headers:
                findings.append({"severity": "low", "title": f"HSTS not observed on HTTPS port {port}", "detail": "Review whether Strict-Transport-Security is appropriate for this managed web service."})
            if "content-security-policy" not in headers:
                findings.append({"severity": "info", "title": f"CSP header not observed on HTTPS port {port}", "detail": "For browser-facing applications, review whether a Content-Security-Policy should be present."})
        if headers.get("server"):
            findings.append({"severity": "info", "title": f"Server banner exposed on port {port}", "detail": f"HTTP Server header: {headers['server']}. Consider minimizing unnecessary product/version disclosure where practical."})

    for item in tls_results:
        if item.get("reachable") and not item.get("verified"):
            findings.append({"severity": "medium", "title": f"TLS validation failed on port {item.get('port')}", "detail": item.get("error") or "Certificate trust or hostname validation failed."})
        days = item.get("days_remaining")
        if isinstance(days, int) and days < 30:
            findings.append({"severity": "high" if days < 7 else "medium", "title": f"TLS certificate expires in {days} day(s)", "detail": "Renew or replace the certificate before service clients begin failing validation."})
    return findings[:16]


def application_assurance(hostname: str, address: str, requested_ports: Iterable[int], auto_probe: bool = True) -> Dict[str, Any]:
    """Perform a bounded web/TLS assurance pass against one already-authorized target."""
    ports = [int(port) for port in requested_ports if int(port) in WEB_PORTS]
    if auto_probe:
        for port in (80, 443):
            if port not in ports:
                ports.append(port)
    ports = ports[:MAX_APP_PORTS]

    http_results = [_http_probe(hostname, address, port) for port in ports]
    tls_results = [_tls_probe(hostname, address, port) for port in ports if port in TLS_PORTS]
    reachable_http = [item for item in http_results if item.get("reachable")]
    verified_tls = [item for item in tls_results if item.get("verified")]
    return {
        "auto_probe": auto_probe,
        "ports_checked": ports,
        "http": http_results,
        "tls": tls_results,
        "findings": _application_findings(http_results, tls_results),
        "application_status": "healthy" if any(isinstance(item.get("status"), int) and item["status"] < 500 for item in reachable_http) else ("fault" if reachable_http else "not_available"),
        "tls_status": "healthy" if verified_tls else ("review" if tls_results and any(item.get("reachable") for item in tls_results) else "not_available"),
    }
