"""SchoolNet v1.7 application assembly.

Layers Network Safety Graph, Incident Investigator, and Deep Network Engineer
read-only diagnostics onto the stable configuration-analysis API. Production
loads ``application:app``.
"""
from typing import Any, Dict, List

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import api as base
from deep_diagnostics import deep_investigate
from incident_investigator import investigate_incident
from network_graph import analyze_network_bundle
from troubleshoot import commands as command_catalog
from troubleshoot.linux_profile import LINUX_PROFILE
from troubleshoot.routing_deep import extend_routing_profiles


# Extend the shared read-only command dispatcher with a Linux server profile.
_original_profile_for = command_catalog._profile_for
command_catalog.COMMON_PROFILES["linux"] = LINUX_PROFILE


def _profile_for_with_linux(device_type: str):
    if "linux" in (device_type or "").lower():
        return LINUX_PROFILE
    return _original_profile_for(device_type)


command_catalog._profile_for = _profile_for_with_linux
extend_routing_profiles(command_catalog)

base.APP_VERSION = "1.7.0"
app = base.app
app.version = base.APP_VERSION
app.description = (
    "Multi-vendor configuration analysis, Network Safety Graph inference, evidence-driven "
    "incident investigation, deep DNS/route/traceroute/service/security diagnostics, "
    "change-impact review, rollback-aware planning, and optional read-only network-device/Linux SSH. "
    "No automatic production changes or exploitation."
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
    dns_server: str = Field("", description="Optional DNS resolver to query")
    run_trace: bool = True
    security_surface: bool = False
    device: IncidentDeviceSnapshot = Field(default_factory=IncidentDeviceSnapshot)


@app.post("/api/v1/network-graph", tags=["Network Safety Graph"])
async def network_safety_graph(request: NetworkGraphRequest):
    """Infer multi-device relationships and evaluate cross-device change risk."""
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


@app.post("/api/v1/investigate", tags=["Network Incident Investigator"])
async def investigate(request: IncidentRequest):
    """Run bounded read-only diagnostics and correlate likely incident causes."""
    try:
        payload = investigate_incident(
            target=request.target,
            ports=request.ports,
            dns_server=request.dns_server,
            run_trace=request.run_trace,
            security_surface=request.security_surface,
            device=request.device.model_dump(),
        )
        payload["version"] = base.APP_VERSION
        return JSONResponse(content=payload)
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
            "system resolver + dig A/AAAA", "reverse lookup", "ICMP", "server route lookup",
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
            "max_tcp_ports": 16,
        },
    }


@app.post("/api/v1/deep-diagnostics", tags=["Deep Network Engineer"])
async def deep_diagnostics(request: IncidentRequest):
    """Run engineer-depth, bounded read-only diagnostics on one authorized target."""
    try:
        return JSONResponse(content=deep_investigate(
            target=request.target,
            ports=request.ports,
            dns_server=request.dns_server,
            run_trace=request.run_trace,
            security_surface=request.security_surface,
            device=request.device.model_dump(),
        ))
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
        "dns": ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "PTR/reverse", "optional resolver comparison"],
        "routing_and_path": [
            "probe hostname/FQDN", "IPv4/IPv6 route tables", "policy rules", "neighbor cache",
            "per-address route lookup", "UDP traceroute", "ICMP traceroute", "TCP traceroute",
            "IPv4 path-MTU hints",
        ],
        "services_and_security": [
            "requested TCP services", "HTTP/TLS evidence", "bounded management/service exposure review",
            "server-initiated banner evidence for selected protocols", "security-risk explanation without exploitation",
        ],
        "optional_device_ssh": [
            "interfaces/errors/logs", "CDP/LLDP", "VLAN/trunks/STP", "ARP/MAC",
            "route table and target-specific route lookup", "OSPF process/neighbors/interfaces/database",
            "BGP summary/neighbors", "PIM", "VRRP/HSRP where supported", "Linux route/socket/system evidence",
        ],
        "correlation": ["fault-domain matrix", "ranked hypotheses", "DNS disagreement", "PMTU hints", "security surface", "Incident Passport"],
        "guardrails": {
            "auto_execute": False,
            "arbitrary_shell": False,
            "credential_guessing": False,
            "exploitation": False,
            "single_target_only": True,
            "public_targets_default": False,
            "live_ssh_default": False,
            "bounded_exposure_ports": 16,
        },
    }
