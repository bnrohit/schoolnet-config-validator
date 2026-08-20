"""SchoolNet v1.10 application layer: Secure Live Bridge.

Adds a no-HTTPS fallback that keeps device credentials off the browser channel and
requires an out-of-band terminal approval before any live SSH command is run.
Direct browser credential entry remains HTTPS-gated.
"""
from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import application as previous
from ops_assurance import credential_transport_allowed
from secure_live import (
    create_job,
    execute_profile,
    get_job,
    http_oob_enabled,
    list_public_profiles,
    profiles_enabled,
    secure_live_policy,
)
from troubleshoot.commands import TroubleshootCommands
from troubleshoot.ssh_client import SwitchSSHClient


app = previous.app
previous.base.APP_VERSION = "1.10.0"
app.version = previous.base.APP_VERSION
app.description = (
    previous.app.description
    + " Secure Live Bridge adds server-side credential profiles and out-of-band approval for trusted HTTP-only deployments, while keeping direct browser credentials HTTPS-gated."
)

# Remove the legacy live-troubleshoot route inherited from api.py so v1.10 can
# enforce transport policy consistently on every browser-credential path.
for route in list(app.routes):
    if getattr(route, "path", None) == "/api/v1/troubleshoot" and "POST" in getattr(route, "methods", set()):
        app.routes.remove(route)


class DirectTroubleshootRequest(BaseModel):
    host: str
    username: str
    password: str
    device_type: str = "cisco_ios"
    check: str = "all"
    port: int = 22


class SecureProfileRunRequest(BaseModel):
    profile_id: str = Field(..., min_length=1, max_length=80)
    target: str = Field(..., min_length=1, max_length=255)
    check: str = Field("all", max_length=40)


class SecureProfileJobRequest(SecureProfileRunRequest):
    pass


def _no_store(payload: Dict[str, Any]) -> JSONResponse:
    response = JSONResponse(content=payload)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


def _transport_policy(http_request: Request) -> Dict[str, Any]:
    return credential_transport_allowed(
        http_request.url.scheme,
        http_request.headers.get("x-forwarded-proto", ""),
    )


@app.post("/api/v1/troubleshoot", tags=["Read-Only Live"])
async def direct_troubleshoot(req: DirectTroubleshootRequest, http_request: Request):
    """Browser-supplied credentials: allowed only through the HTTPS transport policy."""
    if os.getenv("ENABLE_LIVE_SSH", "false").lower() not in {"1", "true", "yes"}:
        raise HTTPException(status_code=403, detail="ENABLE_LIVE_SSH=false")
    transport = _transport_policy(http_request)
    if not transport["allowed"]:
        raise HTTPException(
            status_code=403,
            detail=(
                "Browser-supplied SSH credentials are blocked over plain HTTP. Use HTTPS, or use the Secure Live Bridge server-side profile + out-of-band approval workflow."
            ),
        )
    try:
        client = SwitchSSHClient(
            host=req.host,
            username=req.username,
            password=req.password,
            device_type=req.device_type,
            port=req.port,
        )
        with client:
            results = TroubleshootCommands.run_all(client) if req.check == "all" else [TroubleshootCommands.run_check(client, req.check)]
        return _no_store({
            "host": req.host,
            "device_type": req.device_type,
            "check": req.check,
            "mode": "read_only_direct_https",
            "credential_transport": transport,
            "results": results,
        })
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/v1/secure-live/policy", tags=["Secure Live Bridge"])
async def secure_live_runtime_policy():
    return _no_store({"version": previous.base.APP_VERSION, **secure_live_policy()})


@app.get("/api/v1/secure-live/profiles", tags=["Secure Live Bridge"])
async def secure_live_profiles():
    try:
        return _no_store({
            "version": previous.base.APP_VERSION,
            "enabled": profiles_enabled(),
            "profiles": list_public_profiles() if profiles_enabled() else [],
        })
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/v1/secure-live/run", tags=["Secure Live Bridge"])
async def secure_profile_run(req: SecureProfileRunRequest, http_request: Request):
    """Execute a server-side profile directly, but only when the web transport is secure."""
    transport = _transport_policy(http_request)
    if not transport["secure_transport"]:
        raise HTTPException(
            status_code=403,
            detail="Direct server-profile execution requires HTTPS. On HTTP, create an out-of-band approval job instead.",
        )
    try:
        return _no_store({
            **execute_profile(req.profile_id, req.target, req.check),
            "version": previous.base.APP_VERSION,
            "credential_transport": "server_side_profile",
        })
    except (KeyError, ValueError, PermissionError) as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/v1/secure-live/jobs", tags=["Secure Live Bridge"])
async def create_secure_live_job(req: SecureProfileJobRequest):
    """Create a pending read-only job. Actual SSH execution requires terminal approval."""
    if not http_oob_enabled():
        raise HTTPException(status_code=403, detail="HTTP out-of-band live approval is disabled.")
    try:
        return _no_store({"version": previous.base.APP_VERSION, **create_job(req.profile_id, req.target, req.check)})
    except (KeyError, ValueError, PermissionError) as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/v1/secure-live/jobs/{job_id}", tags=["Secure Live Bridge"])
async def secure_live_job(job_id: str):
    item = get_job(job_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Secure live job not found.")
    return _no_store({"version": previous.base.APP_VERSION, **item})


@app.get("/api/v1/secure-live/capabilities", tags=["Secure Live Bridge"])
async def secure_live_capabilities():
    return _no_store({
        "version": previous.base.APP_VERSION,
        "preferred_mode": "HTTPS with direct or server-side profile credentials",
        "http_fallback": "server-side profile + out-of-band terminal approval",
        "credential_storage": "operator-managed read-only file mounted into backend; never returned by API",
        "profile_controls": ["explicit target allowlist", "explicit diagnostic allowlist", "optional SSH key", "optional strict host-key verification"],
        "approval": "pending HTTP job must be approved/executed from backend CLI, normally over SSH to SchoolNet host",
        "guardrails": ["read-only predefined commands", "no arbitrary shell", "no config mode", "no credential guessing", "no exploitation", "no browser credential transport on HTTP"],
        "important_limit": "Plain HTTP still does not protect diagnostic result confidentiality or browser-page integrity. Use a trusted management network and migrate to HTTPS when possible.",
    })
