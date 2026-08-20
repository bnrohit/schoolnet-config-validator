"""Core validation engine - runs structured and universal safety checks."""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckType(Enum):
    VLAN_MISMATCH = "vlan_mismatch"
    NATIVE_VLAN_MISMATCH = "native_vlan_mismatch"
    STP_ISSUE = "stp_issue"
    MISSING_TRUNK = "missing_trunk"
    DUPLEX_MISMATCH = "duplex_mismatch"
    IP_CONFLICT = "ip_conflict"
    SECURITY_GAP = "security_gap"
    UPLINK_REDUNDANCY = "uplink_redundancy"
    POE_BUDGET = "poe_budget"
    LOOP_PROTECTION = "loop_protection"
    MANAGEMENT_PLANE = "management_plane"
    ROUTING_RISK = "routing_risk"
    OBSERVABILITY = "observability"
    RESILIENCE = "resilience"
    CONFIG_HYGIENE = "config_hygiene"


@dataclass
class Finding:
    check_type: CheckType
    severity: Severity
    interface: Optional[str]
    message: str
    remediation: str
    line_number: Optional[int] = None
    raw_config: Optional[str] = None
    confidence: str = "medium"
    impact: str = ""
    evidence: str = ""
    pre_checks: List[str] = field(default_factory=list)
    change_plan: List[str] = field(default_factory=list)
    rollback: List[str] = field(default_factory=list)
    post_checks: List[str] = field(default_factory=list)
    automation_safe: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_type": self.check_type.value,
            "severity": self.severity.value,
            "interface": self.interface,
            "message": self.message,
            "remediation": self.remediation,
            "line_number": self.line_number,
            "raw_config": self.raw_config,
            "confidence": self.confidence,
            "impact": self.impact,
            "evidence": self.evidence,
            "pre_checks": self.pre_checks,
            "change_plan": self.change_plan,
            "rollback": self.rollback,
            "post_checks": self.post_checks,
            "automation_safe": self.automation_safe,
        }


@dataclass
class ValidationResult:
    hostname: str = ""
    vendor: str = ""
    model: str = ""
    ios_version: str = ""
    total_lines: int = 0
    findings: List[Finding] = field(default_factory=list)
    parsed_interfaces: List[Dict] = field(default_factory=list)
    parsed_vlans: List[Dict] = field(default_factory=list)
    analysis: Dict[str, Any] = field(default_factory=dict)
    routing: Dict[str, Any] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "vendor": self.vendor,
            "model": self.model,
            "ios_version": self.ios_version,
            "total_lines": self.total_lines,
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
                "total": len(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings],
            "parsed_interfaces": self.parsed_interfaces,
            "parsed_vlans": self.parsed_vlans,
            "analysis": self.analysis,
            "routing": self.routing,
        }


class ValidationEngine:
    """Orchestrates vendor-specific checks plus conservative universal checks."""

    def __init__(self):
        self.classic_checks = []
        self.expert_check = None
        self._register_default_checks()

    def _register_default_checks(self):
        from .checks import (
            VlanCheck, NativeVlanCheck, StpCheck, TrunkCheck,
            DuplexCheck, SecurityCheck, UplinkCheck, NetworkExpertCheck,
        )
        self.classic_checks = [
            VlanCheck(),
            NativeVlanCheck(),
            StpCheck(),
            TrunkCheck(),
            DuplexCheck(),
            SecurityCheck(),
            UplinkCheck(),
        ]
        self.expert_check = NetworkExpertCheck()

    def validate(self, parsed_config: Dict[str, Any], raw_config: str) -> ValidationResult:
        result = ValidationResult()
        result.hostname = parsed_config.get("hostname", "unknown")
        result.vendor = parsed_config.get("vendor", "unknown")
        result.model = parsed_config.get("model", "")
        result.ios_version = parsed_config.get("ios_version", "")
        result.total_lines = len(raw_config.splitlines())
        result.parsed_interfaces = parsed_config.get("interfaces", [])
        result.parsed_vlans = parsed_config.get("vlans", [])
        result.analysis = parsed_config.get("analysis", {})
        result.routing = parsed_config.get("routing", {})

        # Existing detailed L2 checks are accurate only where we have structured
        # platform parsing. Universal mode intentionally avoids inventing facts.
        detailed_vendors = {"cisco_ios", "cisco_iosxe", "aruba_aoscx", "aruba_aos"}
        analysis_mode = result.analysis.get("mode")
        if result.vendor in detailed_vendors or analysis_mode == "specialized":
            for check in self.classic_checks:
                result.findings.extend(check.run(parsed_config, raw_config))

        # The expert layer is always run. It only reports explicit evidence and
        # returns review-first change plans rather than auto-applying commands.
        result.findings.extend(self.expert_check.run(parsed_config, raw_config))

        # De-duplicate equivalent findings produced by detailed + universal rules.
        deduped = []
        seen = set()
        for finding in result.findings:
            key = (finding.check_type.value, finding.interface, finding.message.lower().strip())
            if key not in seen:
                seen.add(key)
                deduped.append(finding)
        result.findings = deduped

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        result.findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        return result
