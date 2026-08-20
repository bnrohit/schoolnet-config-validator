"""SchoolNet v1.6 application assembly.

Layers Network Safety Graph and Network Incident Investigator onto the stable
configuration-analysis API. Production loads ``application:app``.
"""
from typing import Any, Dict, List

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import api as base
from incident_investigator import investigate_incident
from network_graph import analyze_network_bundle


base.APP_VERSION = "1.6.0"
app = base.app
app.version = base.APP_VERSION
app.description = (
    "Multi-vendor configuration analysis, Network Safety Graph inference, evidence-driven "
    "read-only incident investigation, change-impact review, rollback-aware planning, and "
    "optional read-only SSH diagnostics. No automatic production changes."
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
    """Run bounded read-only diagnostics and correlate likely incident causes.

    Diagnostics originate from the SchoolNet backend container. Public targets
    are denied unless ALLOW_PUBLIC_DIAGNOSTICS=true. Optional SSH collection is
    separately gated by ENABLE_LIVE_SSH=true and uses the predefined read-only
    command catalog only.
    """
    try:
        return JSONResponse(content=investigate_incident(
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
            "identity/uptime", "interfaces/counters", "logs/errors", "CDP/LLDP", "routing neighbors/table",
            "VLAN/trunks", "spanning tree", "management/access security state", "Linux host health where supported",
        ],
        "correlation": [
            "DNS vs path vs service isolation", "ICMP filtering detection", "application-vs-network distinction",
            "TLS failure diagnosis", "management exposure findings", "device log/counter/routing evidence",
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
