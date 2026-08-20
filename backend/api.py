"""FastAPI backend for SchoolNet Config Validator.

SchoolNet is a safety-first network configuration analysis API. It combines
specialized parsing for mature platforms with conservative universal checks for
other network operating systems. The API never auto-pushes production changes.
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

from parsers import get_parser, SUPPORTED_VENDOR_IDS, VENDOR_NAMES
from validators.engine import ValidationEngine
from troubleshoot.ssh_client import SwitchSSHClient
from troubleshoot.commands import TroubleshootCommands

APP_VERSION = "1.3.0"

app = FastAPI(
    title="SchoolNet Config Validator API",
    description=(
        "Multi-vendor network configuration risk analysis with platform auto-detection, "
        "evidence-based findings, rollback-aware change planning, and optional read-only live diagnostics. "
        "Use sanitized configs only. Live SSH is disabled by default."
    ),
    version=APP_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3002,http://localhost:5173,http://127.0.0.1:3002",
    ).split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ValidateRequest(BaseModel):
    config_text: str = Field(..., description="Sanitized switch/router/network-appliance configuration text")
    vendor: str = Field("auto", description="Use 'auto' for platform detection or choose a supported vendor id")


class TroubleshootRequest(BaseModel):
    host: str
    username: str
    password: str
    device_type: str = "cisco_ios"
    check: str = "all"
    port: int = 22


class RemediationRequest(BaseModel):
    findings: List[Dict[str, Any]]
    vendor: str = "auto"


class BatchValidateItem(BaseModel):
    name: str
    config_text: str
    vendor: str = "auto"


class ReportRequest(BaseModel):
    result: Dict[str, Any]
    title: str = "SchoolNet Configuration Validation Report"


SENSITIVE_PATTERNS = [
    (re.compile(r"(?im)^(\s*(?:enable\s+secret|enable\s+password|username\s+\S+\s+(?:password|secret)|password)\s+).+$"), r"\1<redacted>"),
    (re.compile(r"(?im)^(\s*snmp-server\s+community\s+)\S+(.*)$"), r"\1<redacted>\2"),
    (re.compile(r"(?im)^(\s*snmp-agent\s+community\s+(?:read|write)\s+)\S+(.*)$"), r"\1<redacted>\2"),
    (re.compile(r"(?im)^(\s*set\s+snmp\s+community\s+)\S+(.*)$"), r"\1<redacted>\2"),
    (re.compile(r"(?im)^(\s*(?:tacacs-server|radius-server)\s+key\s+).+$"), r"\1<redacted>"),
    (re.compile(r"(?im)^(\s*crypto\s+isakmp\s+key\s+)\S+(.*)$"), r"\1<redacted>\2"),
    (re.compile(r"(?im)^(\s*pre-shared-key\s+).+$"), r"\1<redacted>"),
    (re.compile(r"(?im)^(\s*set\s+system\s+login\s+user\s+\S+\s+authentication\s+encrypted-password\s+)\S+.*$"), r"\1<redacted>"),
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
    return min(
        100,
        summary.get("critical", 0) * 35
        + summary.get("high", 0) * 20
        + summary.get("medium", 0) * 8
        + summary.get("low", 0) * 3,
    )


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


def _leadership_summary(result_dict: Dict[str, Any]) -> str:
    hostname = result_dict.get("hostname") or "the device"
    summary = result_dict.get("summary", {})
    score = _risk_score(summary)
    label = _risk_label(score)
    total = summary.get("total", 0)
    vendor = result_dict.get("vendor", "unknown")
    confidence = result_dict.get("analysis", {}).get("parser_confidence")
    confidence_note = f" Platform detection confidence is {round(float(confidence) * 100)}%." if confidence is not None else ""
    if total == 0:
        return (
            f"{hostname} ({vendor}) has no findings from the current evidence-based rules. "
            "This is not a guarantee that the configuration is risk-free; vendor-specific design review may still be required."
            f"{confidence_note}"
        )
    return (
        f"{hostname} ({vendor}) has a {label} configuration risk score of {score}/100 with {total} finding(s). "
        "Prioritize critical/high items, verify dependencies before change, preserve a rollback path, and validate service health afterward."
        f"{confidence_note}"
    )


def _executive_summary(result_dict: Dict[str, Any]) -> Dict[str, Any]:
    score = _risk_score(result_dict.get("summary", {}))
    findings = result_dict.get("findings", [])
    return {
        "risk_score": score,
        "risk_label": _risk_label(score),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "top_recommendations": [f.get("remediation") for f in findings[:5]],
        "leadership_summary": _leadership_summary(result_dict),
        "review_first": True,
        "auto_apply": False,
    }


def _validate_one(config_text: str, vendor: str) -> Dict[str, Any]:
    _validate_text_size(config_text)
    sanitized = _sanitize_config(config_text)
    parser = get_parser(vendor)
    parsed = parser.parse(sanitized)
    engine = ValidationEngine()
    result = engine.validate(parsed, sanitized).to_dict()
    result["executive_summary"] = _executive_summary(result)
    return result


def _vendor_catalog() -> List[Dict[str, str]]:
    names = {
        "auto": "Auto-detect platform",
        "cisco_ios": "Cisco IOS",
        "cisco_iosxe": "Cisco IOS-XE",
        "cisco_nxos": "Cisco NX-OS / Nexus",
        "cisco_asa": "Cisco ASA",
        "arista_eos": "Arista EOS",
        "juniper_junos": "Juniper Junos",
        "aruba_aoscx": "Aruba AOS-CX",
        "aruba_aos": "Aruba AOS-Switch / ProCurve",
        "hpe_comware": "HPE Comware",
        "extreme_exos": "ExtremeXOS",
        "extreme_voss": "Extreme VOSS",
        "brocade_fastiron": "Brocade / Ruckus FastIron / ICX",
        "dell_os10": "Dell OS10",
        "dell_os9": "Dell OS9 / FTOS",
        "mikrotik_routeros": "MikroTik RouterOS",
        "vyos": "VyOS",
        "fortios": "Fortinet FortiOS",
        "paloalto_panos": "Palo Alto PAN-OS",
        "sonic": "SONiC",
        "linux_frr": "FRRouting / Linux routing",
        "ubiquiti_edgeos": "Ubiquiti EdgeOS",
        "generic": "Other / Generic network device",
    }
    specialized = {"cisco_ios", "cisco_iosxe", "aruba_aoscx", "aruba_aos"}
    return [
        {
            "id": vendor,
            "name": names.get(vendor, VENDOR_NAMES.get(vendor, vendor)),
            "status": "specialized" if vendor in specialized else ("auto" if vendor == "auto" else "universal"),
        }
        for vendor in SUPPORTED_VENDOR_IDS
    ]


@app.get("/")
async def root():
    return {
        "name": "SchoolNet Config Validator",
        "version": APP_VERSION,
        "docs": "/docs",
        "health": "/api/v1/health",
        "message": "Analyze sanitized multi-vendor network configs with review-first safety guidance.",
        "auto_apply": False,
    }


@app.get("/api/v1/health")
async def health_check():
    return {"status": "healthy", "version": APP_VERSION, "service": "schoolnet-config-validator"}


@app.get("/api/v1/vendors")
async def list_vendors():
    return {"vendors": _vendor_catalog(), "default": "auto"}


@app.get("/api/v1/rules")
async def list_rules():
    return {
        "rule_groups": [
            {"id": "vlan_mismatch", "name": "VLAN correctness", "examples": ["access VLAN exists", "native/allowed VLAN consistency"]},
            {"id": "stp_issue", "name": "Loop prevention", "examples": ["STP disablement", "edge protection", "root design review"]},
            {"id": "missing_trunk", "name": "Trunk hygiene", "examples": ["all-VLAN trunks", "dynamic negotiation", "explicit allowed VLANs"]},
            {"id": "duplex_mismatch", "name": "Link stability", "examples": ["half-duplex", "peer validation", "error counters"]},
            {"id": "management_plane", "name": "Management plane", "examples": ["Telnet", "HTTP", "SNMP communities", "least privilege"]},
            {"id": "security_gap", "name": "Security controls", "examples": ["weak secrets", "legacy IP features", "segmentation risk"]},
            {"id": "routing_risk", "name": "Routing safety", "examples": ["OSPF/BGP/ISIS change awareness", "neighbor/route pre-checks", "rollback criteria"]},
            {"id": "observability", "name": "Observability", "examples": ["logging", "monitoring dependencies", "post-change verification"]},
        ],
        "principles": [
            "Evidence before assertion",
            "No automatic production changes",
            "Pre-check before high-impact change",
            "Rollback path before implementation",
            "Post-change service validation",
            "Low-confidence platform detection is explicitly disclosed",
        ],
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
async def validate_upload(file: UploadFile = File(...), vendor: str = Form("auto")):
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
    results = [{"name": item.name, **_validate_one(item.config_text, item.vendor)} for item in items]
    worst_score = max([r["executive_summary"]["risk_score"] for r in results], default=0)
    return {
        "count": len(results),
        "worst_risk_score": worst_score,
        "worst_risk_label": _risk_label(worst_score),
        "results": results,
    }


@app.post("/api/v1/validate/csv")
async def validate_csv(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    items = []
    for row in reader:
        items.append(BatchValidateItem(
            name=row.get("name") or row.get("hostname") or "unnamed",
            vendor=row.get("vendor") or "auto",
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
            "confidence": finding.get("confidence", "medium"),
            "summary": f"{finding.get('check_type', 'configuration_issue')}{location}: {finding.get('message', '')}",
            "impact": finding.get("impact", ""),
            "recommended_action": finding.get("remediation", "Review configuration and validate against the intended network design."),
            "pre_checks": finding.get("pre_checks", []),
            "change_plan": finding.get("change_plan", []),
            "rollback": finding.get("rollback", []),
            "post_checks": finding.get("post_checks", []),
        })
    return {
        "overview": "Configuration review completed. Prioritize critical/high findings and preserve a verified rollback path before production changes.",
        "findings_analyzed": len(request.findings),
        "top_actions": bullets,
        "leadership_summary": "This report identifies evidence-backed network configuration risks that may affect connectivity, security, resilience, or outage recovery.",
        "note": "Local rules-based engineering assistance; no external AI service and no automatic device changes.",
    }


@app.post("/api/v1/remediate")
async def generate_remediation(request: RemediationRequest):
    """Compatibility endpoint that now emits a non-executable review plan."""
    lines = [
        "# SchoolNet Safety-First Change Plan",
        "# REVIEW ONLY — NOT AN AUTO-DEPLOYMENT SCRIPT",
        f"# Vendor selection: {request.vendor}",
        "# Validate vendor syntax, dependencies, maintenance window, and OOB recovery before change.",
        "",
    ]
    for idx, finding in enumerate(request.findings, 1):
        lines.extend([
            f"## {idx}. {str(finding.get('severity', 'info')).upper()} — {finding.get('message', '')}",
            f"Recommendation: {finding.get('remediation', '')}",
        ])
        if finding.get("impact"):
            lines.append(f"Impact: {finding.get('impact')}")
        for title, key in [
            ("Pre-change checks", "pre_checks"),
            ("Controlled change", "change_plan"),
            ("Rollback", "rollback"),
            ("Post-change validation", "post_checks"),
        ]:
            items = finding.get(key) or []
            if items:
                lines.append(f"{title}:")
                for item_index, item in enumerate(items, 1):
                    lines.append(f"  {item_index}. {item}")
        lines.append("")
    return JSONResponse(content={
        "mode": "review_plan",
        "executable": False,
        "script": "\n".join(lines),
        "plan": "\n".join(lines),
        "finding_count": len(request.findings),
    })


@app.post("/api/v1/report/markdown", response_class=PlainTextResponse)
async def markdown_report(request: ReportRequest):
    result = request.result
    summary = result.get("summary", {})
    executive = result.get("executive_summary", {})
    analysis = result.get("analysis", {})
    lines = [
        f"# {request.title}",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Device: {result.get('hostname', 'unknown')}",
        f"Vendor: {result.get('vendor', 'unknown')}",
        f"Analysis mode: {analysis.get('mode', 'unknown')}",
        f"Parser confidence: {analysis.get('parser_confidence', 'unknown')}",
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
            f"**Confidence:** {finding.get('confidence', 'medium')}",
        ])
        if finding.get("impact"):
            lines.append(f"**Impact:** {finding.get('impact')}")
        if finding.get("evidence"):
            lines.append(f"**Evidence:** `{finding.get('evidence')}`")
        lines.append(f"**Recommended action:** {finding.get('remediation', '')}")
        for title, key in [
            ("Pre-change checks", "pre_checks"),
            ("Controlled change plan", "change_plan"),
            ("Rollback", "rollback"),
            ("Post-change validation", "post_checks"),
        ]:
            items = finding.get(key) or []
            if items:
                lines.append(f"**{title}:**")
                lines.extend([f"- {item}" for item in items])
        lines.append("")
    lines.extend([
        "---",
        "SchoolNet is review-first. Generated guidance must be validated against the actual topology, vendor documentation, and maintenance/rollback procedures before production changes.",
    ])
    return "\n".join(lines)


@app.post("/api/v1/troubleshoot")
async def run_troubleshoot(request: TroubleshootRequest):
    if os.getenv("ENABLE_LIVE_SSH", "false").lower() not in ("1", "true", "yes"):
        raise HTTPException(
            status_code=403,
            detail="Live SSH diagnostics are disabled by default. Set ENABLE_LIVE_SSH=true only on a trusted internal network and use a least-privilege account.",
        )
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
        return JSONResponse(content={
            "host": request.host,
            "device_type": request.device_type,
            "check": request.check,
            "mode": "read_only",
            "results": results,
        })
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/v1/troubleshoot/commands")
async def list_troubleshoot_commands():
    return {
        "mode": "read_only",
        "commands": TroubleshootCommands.available_commands(),
        "note": "The live client rejects obvious configuration/save/reload/delete/commit operations.",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
