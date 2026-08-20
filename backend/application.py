"""SchoolNet v1.8 application assembly.

Layers Network Safety Graph, Incident Investigator, Deep Network Engineer, and
operational-hardening controls onto the stable configuration-analysis API.
Production loads ``application:app``.
"""
import os
from typing import Any, Dict, List

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import api as base
from deep_diagnostics import deep_investigate
from incident_investigator import investigate_incident
from network_graph import analyze_network_bundle
from ops_assurance import (
    application_assurance,
    credential_transport_allowed,
    effective_dns_server,
    env_bool,
)
from troubleshoot import commands as command_catalog
from troubleshoot.linux_profile import LINUX_PROFILE
from troubleshoot.routing_deep import extend_routing_profiles


_original_profile_for = command_catalog._profile_for
command_catalog.COMMON_PROFILES["linux"] = LINUX_PROFILE


def _profile_for_with_linux(device_type: str):
    if "linux" in (device_type or "").lower():
        return LINUX_PROFILE
    return _original_profile_for(device_type)


command_catalog._profile_for = _profile_for_with_linux
extend_routing_profiles(command_catalog)

base.APP_VERSION = "1.8.0"
app = base.app
app.version = base.APP_VERSION
app.description = (
    "Multi-vendor configuration analysis, Network Safety Graph inference, evidence-driven "
    "incident investigation, deep DNS/route/traceroute/service/security diagnostics, "
    "application/TLS assurance, resolver-context controls, change-impact review, rollback-aware "
    "planning, and optional read-only network-device/Linux SSH. No automatic production changes "
    "or exploitation."
)


class NetworkGraphDevice(BaseModel):
    name: str = Field("", description="Friendly device name; hostname is used when omitted")
    vendor: str = Field("auto", description="Platform hint or auto")
    config_text: str = Field(..., description="Sanitized current configuration")
    proposed_config: str = Field("", description="Optional sanitized proposed post-change configuration")
    neighbor_text: str = Field("", description="Optional read-only CDP/LLDP/equivalent neighbor output")


class NetworkGraphRequest(BaseModel):
    devices: List[NetworkGraphDevice]


class IncidentDeviceSnapshot(BaseModel):
    enabled: bool = False
    host: str = ""
    username: str = ""
    password: str = ""
    secret: str = ""
    device_type: str = "cisco_ios"
    port: int = 22
    categories: List[str] = Field(default_factory=lambda: [
        "basic", "interfaces", "errors", "neighbors", "routing", "vlan", "stp", "security"
    ])


class IncidentRequest(BaseModel):
    target: str = Field(..., description="Authorized target hostname or IP")
    ports: List[int] = Field(default_factory=lambda: [22, 53, 80, 443], description="Expected TCP ports to test")
    dns_server: str = Field("", description="Optional DNS resolver. When empty, DEFAULT_DNS_SERVER is used if configured.")
    run_trace: bool = True
    security_surface: bool = False
    auto_application_probe: bool = True
    device: IncidentDeviceSnapshot = Field(default_factory=IncidentDeviceSnapshot)


def _resolver_for(req: IncidentRequest) -> Dict[str, str]:
    return effective_dns_server(req.dns_server)


def _enforce_live_credential_transport(http_request: Request, req: IncidentRequest) -> Dict[str, Any]:
    forwarded = http_request.headers.get("x-forwarded-proto", "")
    policy = credential_transport_allowed(http_request.url.scheme, forwarded)
    if req.device.enabled and not policy["allowed"]:
        raise HTTPException(
            status_code=403,
            detail=(
                "Live device credentials are blocked over insecure HTTP. Put SchoolNet behind HTTPS, "
                "then retry. Credential-free DNS/path/service diagnostics remain available."
            ),
        )
    return policy


def _no_store(payload: Dict[str, Any]) -> JSONResponse:
    response = JSONResponse(content=payload)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.post("/api/v1/network-graph", tags=["Network Safety Graph"])
async def network_safety_graph(request: NetworkGraphRequest):
    if not 2 <= len(request.devices) <= 50:
        raise HTTPException(status_code=400, detail="Provide between 2 and 50 devices.")

    sanitized = []
    for idx, device in enumerate(request.devices):
        if not device.config_text.strip():
            raise HTTPException(status_code=400, detail=f"Device {idx + 1} is missing config_text.")
        base._validate_text_size(device.config_text)
        if device.proposed_config:
            base._validate_text_size(device.proposed_config)
        if device.neighbor_text:
            base._validate_text_size(device.neighbor_text)
        sanitized.append({
            "name": device.name,
            "vendor": device.vendor,
            "config_text": base._sanitize_config(device.config_text),
            "proposed_config": base._sanitize_config(device.proposed_config) if device.proposed_config else "",
            "neighbor_text": base._sanitize_config(device.neighbor_text) if device.neighbor_text else "",
        })

    try:
        return JSONResponse(content=analyze_network_bundle(sanitized))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Network Safety Graph analysis failed: {exc}")


@app.get("/api/v1/network-graph/capabilities", tags=["Network Safety Graph"])
async def network_graph_capabilities():
    return {
        "version": base.APP_VERSION,
        "mode": "offline_inferred_safety_graph",
        "auto_execute": False,
        "inputs": ["current configs", "optional proposed configs", "optional CDP/LLDP/equivalent neighbor evidence"],
        "inference": ["peer relationships", "shared transit links", "BGP peer ownership", "trunks", "VLAN/gateway presence", "routing relationships", "single points of failure"],
        "change_analysis": ["network change gate", "cross-device invariants", "impact propagation", "peer coordination", "rollback contract", "post-change proof"],
    }


@app.get("/api/v1/runtime-policy", tags=["Operational Policy"])
async def runtime_policy():
    dns = effective_dns_server("")
    return {
        "version": base.APP_VERSION,
        "default_dns_server": dns["server"],
        "default_dns_source": dns["source"],
        "live_ssh_enabled": env_bool("ENABLE_LIVE_SSH", False),
        "https_required_for_live_credentials": env_bool("REQUIRE_HTTPS_FOR_LIVE_CREDENTIALS", True),
        "allow_insecure_live_credentials": env_bool("ALLOW_INSECURE_LIVE_CREDENTIALS", False),
        "public_diagnostics_enabled": env_bool("ALLOW_PUBLIC_DIAGNOSTICS", False),
        "auto_application_probe_default": env_bool("AUTO_APPLICATION_PROBE", True),
    }


@app.post("/api/v1/investigate", tags=["Network Incident Investigator"])
async def investigate(req: IncidentRequest, http_request: Request):
    try:
        transport = _enforce_live_credential_transport(http_request, req)
        resolver = _resolver_for(req)
        payload = investigate_incident(
            target=req.target,
            ports=req.ports,
            dns_server=resolver["server"],
            run_trace=req.run_trace,
            security_surface=req.security_surface,
            device=req.device.model_dump(),
        )
        payload["version"] = base.APP_VERSION
        payload["resolver_context"] = resolver
        payload["credential_transport"] = transport
        return _no_store(payload)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Incident investigation failed: {exc}")


@app.get("/api/v1/investigate/capabilities", tags=["Network Incident Investigator"])
async def investigate_capabilities() -> Dict[str, Any]:
    return {
        "version": base.APP_VERSION,
        "mode": "bounded_read_only_incident_investigation",
        "probe_origin": "SchoolNet backend container",
        "network_evidence": [
            "system/configured resolver + dig A/AAAA", "reverse lookup", "ICMP", "server route lookup",
            "traceroute", "bounded TCP service tests", "HTTP status", "TLS trust/protocol/certificate",
        ],
        "optional_device_evidence": [
            "network-device identity/uptime", "interfaces/counters", "logs/errors", "CDP/LLDP",
            "deep routing/OSPF/BGP/HA state", "VLAN/trunks", "spanning tree", "management/access security state",
            "Linux kernel/uptime", "Linux addresses/routes", "Linux sockets", "failed systemd units", "warning logs",
        ],
        "correlation": [
            "DNS vs path vs service isolation", "ICMP filtering detection", "application-vs-network distinction",
            "TLS failure diagnosis", "management exposure findings", "device/server log/counter/routing evidence",
            "ranked root-cause hypotheses", "Incident Passport export data",
        ],
        "guardrails": {
            "auto_execute": False,
            "arbitrary_shell": False,
            "public_targets_default": False,
            "live_ssh_default": False,
            "https_credentials_default": True,
            "max_tcp_ports": 16,
        },
    }


@app.post("/api/v1/deep-diagnostics", tags=["Deep Network Engineer"])
async def deep_diagnostics(req: IncidentRequest, http_request: Request):
    try:
        transport = _enforce_live_credential_transport(http_request, req)
        resolver = _resolver_for(req)
        auto_app = req.auto_application_probe and env_bool("AUTO_APPLICATION_PROBE", True)
        payload = deep_investigate(
            target=req.target,
            ports=req.ports,
            dns_server=resolver["server"],
            run_trace=req.run_trace,
            security_surface=req.security_surface,
            device=req.device.model_dump(),
        )
        payload["version"] = base.APP_VERSION
        payload["resolver_context"] = resolver
        payload["credential_transport"] = transport

        primary = payload.get("primary_address")
        if primary:
            assurance = application_assurance(req.target, primary, req.ports, auto_probe=auto_app)
        else:
            assurance = {"auto_probe": auto_app, "ports_checked": [], "http": [], "tls": [], "findings": [], "application_status": "not_available", "tls_status": "not_available"}
        payload["application_assurance"] = assurance

        fault_domains = payload.get("deep_diagnostics", {}).get("fault_domains", [])
        for item in fault_domains:
            if item.get("domain") == "Application" and assurance["application_status"] != "not_available":
                item["status"] = assurance["application_status"]
                item["evidence"] = "; ".join(f"{probe.get('status')} {probe.get('url')}" for probe in assurance["http"] if probe.get("reachable"))[:800]
            if item.get("domain") == "TLS" and assurance["tls_status"] != "not_available":
                item["status"] = assurance["tls_status"]
                item["evidence"] = "; ".join(f"port {probe.get('port')} {probe.get('protocol')} verified={probe.get('verified')}" for probe in assurance["tls"])[:800]

        payload.setdefault("security", {}).setdefault("findings", []).extend(assurance.get("findings", []))
        return _no_store(payload)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Deep diagnostics failed: {exc}")


@app.get("/api/v1/deep-diagnostics/capabilities", tags=["Deep Network Engineer"])
async def deep_diagnostics_capabilities() -> Dict[str, Any]:
    return {
        "version": base.APP_VERSION,
        "mode": "deep_bounded_read_only_network_engineer",
        "probe_origin": "SchoolNet backend container",
        "dns": ["configurable enterprise-default resolver", "A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "PTR/reverse", "resolver comparison"],
        "routing_and_path": [
            "probe hostname/FQDN", "IPv4/IPv6 route tables", "policy rules", "neighbor cache",
            "per-address route lookup", "UDP traceroute", "ICMP traceroute", "TCP traceroute",
            "IPv4 path-MTU hints",
        ],
        "services_and_security": [
            "requested TCP services", "automatic HTTP/HTTPS assurance", "HTTP response/security headers",
            "TLS protocol/cipher/trust/SAN/expiry", "bounded management/service exposure review",
            "server-initiated banner evidence for selected protocols", "security-risk explanation without exploitation",
        ],
        "optional_device_ssh": [
            "interfaces/errors/logs", "CDP/LLDP", "VLAN/trunks/STP", "ARP/MAC",
            "route table and target-specific route lookup", "OSPF process/neighbors/interfaces/database",
            "BGP summary/neighbors", "PIM", "VRRP/HSRP where supported", "Linux route/socket/system evidence",
        ],
        "correlation": ["fault-domain matrix", "ranked hypotheses", "DNS disagreement", "PMTU hints", "application/TLS assurance", "security surface", "Engineer Passport"],
        "guardrails": {
            "auto_execute": False,
            "arbitrary_shell": False,
            "credential_guessing": False,
            "exploitation": False,
            "single_target_only": True,
            "public_targets_default": False,
            "live_ssh_default": False,
            "https_credentials_default": True,
            "bounded_exposure_ports": 16,
        },
    }
