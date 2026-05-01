"""
FastAPI backend for SchoolNet Config Validator.

SchoolNet is a safe-first, offline-first configuration validation API for K-12
school networks. It validates sanitized switch/router configs, explains risks in
plain English, generates review-first remediation snippets, and exposes a simple
web UI API.
"""
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import os
import csv
import io
import re
from datetime import datetime, timezone

from parsers import get_parser
from validators.engine import ValidationEngine
from troubleshoot.ssh_client import SwitchSSHClient
from troubleshoot.commands import TroubleshootCommands

APP_VERSION = "1.2.0"

app = FastAPI(
    title="SchoolNet Config Validator API",
    description=(
        "Open-source K-12 network configuration validation and outage-prevention toolkit. "
        "Use sanitized configs only. Live SSH is disabled by default."
    ),
    version=APP_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000").split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ValidateRequest(BaseModel):
    config_text: str = Field(..., description="Sanitized switch/router configuration text")
    vendor: str = Field("cisco_ios", description="cisco_ios, cisco_iosxe, aruba_aoscx, aruba_aos")

class TroubleshootRequest(BaseModel):
    host: str
    username: str
    password: str
    device_type: str = "cisco_ios"
    check: str = "all"
    port: int = 22

class RemediationRequest(BaseModel):
    findings: List[Dict[str, Any]]
    vendor: str = "cisco_ios"

class BatchValidateItem(BaseModel):
    name: str
    config_text: str
    vendor: str = "cisco_ios"

class ReportRequest(BaseModel):
    result: Dict[str, Any]
    title: str = "SchoolNet Configuration Validation Report"

SENSITIVE_PATTERNS = [
    (re.compile(r"(?im)^(\s*(?:enable\s+secret|enable\s+password|username\s+\S+\s+(?:password|secret)|password)\s+).+$"), r"\1<redacted>"),
    (re.compile(r"(?im)^(\s*snmp-server\s+community\s+)\S+(.*)$"), r"\1<redacted>\2"),
    (re.compile(r"(?im)^(\s*(?:tacacs-server|radius-server)\s+key\s+).+$"), r"\1<redacted>"),
    (re.compile(r"(?im)^(\s*crypto\s+isakmp\s+key\s+)\S+(.*)$"), r"\1<redacted>\2"),
    (re.compile(r"(?im)^(\s*pre-shared-key\s+).+$"), r"\1<redacted>"),
]

def _validate_text_size(config_text: str) -> None:
    max_mb = int(os.getenv("MAX_UPLOAD_SIZE_MB", "2"))
    if len(config_text.encode("utf-8")) > max_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"Config too large. Limit is {max_mb} MB.")

def _sanitize_config(text: str) -> str:
    sanitized = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized

def _risk_score(summary: Dict[str, int]) -> int:
    return min(100, summary.get("critical", 0) * 35 + summary.get("high", 0) * 20 + summary.get("medium", 0) * 8 + summary.get("low", 0) * 3)

def _risk_label(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    if score > 0:
        return "low"
    return "healthy"

def _executive_summary(result_dict: Dict[str, Any]) -> Dict[str, Any]:
    score = _risk_score(result_dict.get("summary", {}))
    findings = result_dict.get("findings", [])
    return {
        "risk_score": score,
        "risk_label": _risk_label(score),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "top_recommendations": [f.get("remediation") for f in findings[:5]],
        "leadership_summary": _leadership_summary(result_dict),
    }

def _leadership_summary(result_dict: Dict[str, Any]) -> str:
    hostname = result_dict.get("hostname") or "the device"
    summary = result_dict.get("summary", {})
    score = _risk_score(summary)
    label = _risk_label(score)
    total = summary.get("total", 0)
    if total == 0:
        return f"{hostname} passed the current SchoolNet checks. No high-risk configuration issues were detected."
    return (
        f"{hostname} has a {label} configuration risk score of {score}/100 with {total} finding(s). "
        "Prioritize critical/high items before production changes to reduce outage, VLAN, STP, and security risk."
    )

def _validate_one(config_text: str, vendor: str) -> Dict[str, Any]:
    _validate_text_size(config_text)
    sanitized = _sanitize_config(config_text)
    parser = get_parser(vendor)
    parsed = parser.parse(sanitized)
    engine = ValidationEngine()
    result = engine.validate(parsed, sanitized).to_dict()
    result["executive_summary"] = _executive_summary(result)
    return result

@app.get("/")
async def root():
    return {
        "name": "SchoolNet Config Validator",
        "version": APP_VERSION,
        "docs": "/docs",
        "health": "/api/v1/health",
        "message": "Validate sanitized school network configs before they become outages.",
    }

@app.get("/api/v1/health")
async def health_check():
    return {"status": "healthy", "version": APP_VERSION, "service": "schoolnet-config-validator"}

@app.get("/api/v1/vendors")
async def list_vendors():
    return {
        "vendors": [
            {"id": "cisco_ios", "name": "Cisco IOS", "status": "full"},
            {"id": "cisco_iosxe", "name": "Cisco IOS-XE", "status": "full"},
            {"id": "aruba_aoscx", "name": "Aruba AOS-CX", "status": "partial"},
            {"id": "aruba_aos", "name": "Aruba AOS-Switch", "status": "partial"},
        ]
    }

@app.get("/api/v1/rules")
async def list_rules():
    return {
        "rule_groups": [
            {"id": "vlan_mismatch", "name": "VLAN correctness", "examples": ["access VLAN exists", "avoid VLAN 1 for data"]},
            {"id": "native_vlan_mismatch", "name": "Native VLAN risk", "examples": ["avoid native VLAN 1", "native VLAN included in allowed list"]},
            {"id": "stp_issue", "name": "Spanning Tree safety", "examples": ["PortFast on access ports", "BPDU Guard", "Root Guard"]},
            {"id": "missing_trunk", "name": "Trunk hygiene", "examples": ["restricted allowed VLANs", "DTP disabled"]},
            {"id": "duplex_mismatch", "name": "Speed/duplex stability", "examples": ["avoid half-duplex", "consistent hard-coding"]},
            {"id": "security_gap", "name": "Access-layer security", "examples": ["SSH over Telnet", "DHCP snooping", "SNMPv3"]},
            {"id": "uplink_redundancy", "name": "Uplink resilience", "examples": ["port-channel", "UDLD on fiber"]},
        ]
    }

@app.get("/api/v1/examples")
async def examples():
    broken = ""
    good = ""
    try:
        with open("/app/configs/example-broken-switch.txt", "r", encoding="utf-8") as fh:
            broken = fh.read()
        with open("/app/configs/example-good-switch.txt", "r", encoding="utf-8") as fh:
            good = fh.read()
    except FileNotFoundError:
        # Local dev path
        for base in ("configs", "../configs"):
            try:
                with open(f"{base}/example-broken-switch.txt", "r", encoding="utf-8") as fh:
                    broken = fh.read()
                with open(f"{base}/example-good-switch.txt", "r", encoding="utf-8") as fh:
                    good = fh.read()
                break
            except FileNotFoundError:
                pass
    return {"broken_config": broken, "good_config": good}

@app.post("/api/v1/sanitize")
async def sanitize_config(request: ValidateRequest):
    _validate_text_size(request.config_text)
    sanitized = _sanitize_config(request.config_text)
    return {"sanitized_config_text": sanitized, "changed": sanitized != request.config_text}

@app.post("/api/v1/validate")
async def validate_config(request: ValidateRequest):
    try:
        return JSONResponse(content=_validate_one(request.config_text, request.vendor))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Validation failed: {exc}")

@app.post("/api/v1/validate/upload")
async def validate_upload(file: UploadFile = File(...), vendor: str = Form("cisco_ios")):
    try:
        content = await file.read()
        config_text = content.decode("utf-8", errors="replace")
        data = _validate_one(config_text, vendor)
        return JSONResponse(content={"filename": file.filename, **data})
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Upload validation failed: {exc}")

@app.post("/api/v1/validate/batch")
async def validate_batch(items: List[BatchValidateItem]):
    if len(items) > 25:
        raise HTTPException(status_code=400, detail="Batch limit is 25 configs per request.")
    results = []
    for item in items:
        results.append({"name": item.name, **_validate_one(item.config_text, item.vendor)})
    worst_score = max([r["executive_summary"]["risk_score"] for r in results], default=0)
    return {"count": len(results), "worst_risk_score": worst_score, "worst_risk_label": _risk_label(worst_score), "results": results}

@app.post("/api/v1/validate/csv")
async def validate_csv(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    items = []
    for row in reader:
        items.append(BatchValidateItem(
            name=row.get("name") or row.get("hostname") or "unnamed",
            vendor=row.get("vendor") or "cisco_ios",
            config_text=row.get("config_text") or row.get("config") or "",
        ))
    return await validate_batch(items)

@app.post("/api/v1/explain")
async def explain_findings(request: RemediationRequest):
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(request.findings, key=lambda f: severity_order.get(f.get("severity", "info"), 9))
    bullets = []
    for finding in findings[:10]:
        iface = finding.get("interface")
        location = f" on {iface}" if iface else ""
        bullets.append({
            "risk": finding.get("severity", "info"),
            "summary": f"{finding.get('check_type', 'configuration_issue')}{location}: {finding.get('message', '')}",
            "recommended_action": finding.get("remediation", "Review configuration and validate against district standard."),
        })
    return {
        "overview": "Configuration review completed. Prioritize critical and high findings before production changes.",
        "findings_analyzed": len(request.findings),
        "top_actions": bullets,
        "leadership_summary": "This report identifies network configuration risks that may affect connectivity, security, or outage recovery in school environments.",
        "note": "This is local rules-based explanation, not an external AI service.",
    }

@app.post("/api/v1/remediate")
async def generate_remediation(request: RemediationRequest):
    script_lines = [
        "! SchoolNet Auto-Remediation Script",
        "! REVIEW BEFORE APPLYING. Lab test first. Use maintenance window.",
        "! Generated by SchoolNet Config Validator",
        "!",
    ]
    for finding in request.findings:
        severity = finding.get("severity", "")
        check_type = finding.get("check_type", "")
        iface = finding.get("interface")
        remediation = finding.get("remediation", "")
        script_lines.append("!")
        script_lines.append(f"! [{severity.upper()}] {check_type}: {finding.get('message', '')}")
        if iface:
            script_lines.append(f"interface {iface}")
        for line in remediation.split("\n"):
            stripped = line.strip()
            if stripped.startswith("Configure:"):
                script_lines.append(f"  {stripped.replace('Configure:', '').strip()}")
            elif stripped.startswith("Enable:"):
                script_lines.append(stripped.replace("Enable:", "").strip())
            elif stripped.lower().startswith(("switchport", "spanning-tree", "ip dhcp", "ip arp", "udld", "duplex", "speed")):
                script_lines.append(f"  {stripped}")
        if iface:
            script_lines.append(" exit")
    script_lines.extend(["!", "! Save manually after validation if desired:", "! write memory"])
    return JSONResponse(content={"script": "\n".join(script_lines), "finding_count": len(request.findings)})

@app.post("/api/v1/report/markdown", response_class=PlainTextResponse)
async def markdown_report(request: ReportRequest):
    result = request.result
    summary = result.get("summary", {})
    executive = result.get("executive_summary", {})
    lines = [
        f"# {request.title}",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Device: {result.get('hostname', 'unknown')}",
        f"Vendor: {result.get('vendor', 'unknown')}",
        f"Risk: {executive.get('risk_label', 'unknown')} ({executive.get('risk_score', 0)}/100)",
        "",
        "## Summary",
        f"- Critical: {summary.get('critical', 0)}",
        f"- High: {summary.get('high', 0)}",
        f"- Medium: {summary.get('medium', 0)}",
        f"- Low: {summary.get('low', 0)}",
        f"- Total: {summary.get('total', 0)}",
        "",
        "## Leadership Summary",
        executive.get("leadership_summary", "No leadership summary available."),
        "",
        "## Findings",
    ]
    for idx, finding in enumerate(result.get("findings", []), 1):
        iface = f" ({finding.get('interface')})" if finding.get("interface") else ""
        lines.extend([
            f"### {idx}. {finding.get('severity', 'info').upper()} - {finding.get('check_type', 'configuration_issue')}{iface}",
            f"**Issue:** {finding.get('message', '')}",
            f"**Recommended action:** {finding.get('remediation', '')}",
            "",
        ])
    return "\n".join(lines)

@app.post("/api/v1/troubleshoot")
async def run_troubleshoot(request: TroubleshootRequest):
    if os.getenv("ENABLE_LIVE_SSH", "false").lower() not in ("1", "true", "yes"):
        raise HTTPException(status_code=403, detail="Live SSH troubleshooting is disabled by default. Set ENABLE_LIVE_SSH=true only on a trusted internal network.")
    try:
        client = SwitchSSHClient(
            host=request.host,
            username=request.username,
            password=request.password,
            device_type=request.device_type,
            port=request.port,
        )
        with client:
            results = TroubleshootCommands.run_all(client) if request.check == "all" else [TroubleshootCommands.run_check(client, request.check)]
        return JSONResponse(content={"host": request.host, "device_type": request.device_type, "check": request.check, "results": results})
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/api/v1/troubleshoot/commands")
async def list_troubleshoot_commands():
    return {"commands": TroubleshootCommands.available_commands() if hasattr(TroubleshootCommands, "available_commands") else {
        "basic": "Switch identity, version, uptime",
        "interfaces": "Interface status, errors, descriptions",
        "vlan": "VLAN configuration and trunk status",
        "stp": "Spanning Tree topology and health",
        "neighbors": "CDP/LLDP neighbors",
        "all": "Run complete suite",
    }}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
