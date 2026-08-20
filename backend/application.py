"""SchoolNet v1.5 application assembly.

This module layers the Network Safety Graph endpoint onto the stable API without
changing the safety model of existing endpoints. Docker/production should load
``application:app``.
"""
from typing import List

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import api as base
from network_graph import analyze_network_bundle


# Existing endpoint functions read APP_VERSION from the api module at request
# time, so this updates /health while preserving backward-compatible imports.
base.APP_VERSION = "1.5.0"
app = base.app
app.version = base.APP_VERSION
app.description = (
    "Multi-vendor network configuration analysis, offline change-impact review, "
    "multi-device Network Safety Graph inference, rollback-aware planning, and "
    "optional read-only diagnostics. No automatic production changes."
)


class NetworkGraphDevice(BaseModel):
    name: str = Field("", description="Friendly device name; hostname is used when omitted")
    vendor: str = Field("auto", description="Platform hint or auto")
    config_text: str = Field(..., description="Sanitized current configuration")
    proposed_config: str = Field("", description="Optional sanitized proposed post-change configuration")
    neighbor_text: str = Field("", description="Optional read-only CDP/LLDP/equivalent neighbor output")


class NetworkGraphRequest(BaseModel):
    devices: List[NetworkGraphDevice]


@app.post("/api/v1/network-graph", tags=["Network Safety Graph"])
async def network_safety_graph(request: NetworkGraphRequest):
    """Infer multi-device relationships and evaluate cross-device change risk.

    The result is advisory and non-executable. Relationships are confidence
    scored because configuration and neighbor snippets cannot prove all runtime
    topology or dependencies.
    """
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
