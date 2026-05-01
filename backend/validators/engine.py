"""
Core validation engine - runs all checks and aggregates results
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import re

class Severity(Enum):
    CRITICAL = "critical"      # Will cause outage
    HIGH = "high"              # Security risk / major issue
    MEDIUM = "medium"          # Best practice violation
    LOW = "low"                # Minor optimization
    INFO = "info"              # FYI

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

@dataclass
class Finding:
    check_type: CheckType
    severity: Severity
    interface: Optional[str]
    message: str
    remediation: str
    line_number: Optional[int] = None
    raw_config: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_type": self.check_type.value,
            "severity": self.severity.value,
            "interface": self.interface,
            "message": self.message,
            "remediation": self.remediation,
            "line_number": self.line_number,
            "raw_config": self.raw_config
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
                "total": len(self.findings)
            },
            "findings": [f.to_dict() for f in self.findings],
            "parsed_interfaces": self.parsed_interfaces,
            "parsed_vlans": self.parsed_vlans
        }

class ValidationEngine:
    """Orchestrates all validation checks"""

    def __init__(self):
        self.checks = []
        self._register_default_checks()

    def _register_default_checks(self):
        from .checks import (
            VlanCheck, NativeVlanCheck, StpCheck, TrunkCheck,
            DuplexCheck, SecurityCheck, UplinkCheck
        )
        self.checks = [
            VlanCheck(),
            NativeVlanCheck(),
            StpCheck(),
            TrunkCheck(),
            DuplexCheck(),
            SecurityCheck(),
            UplinkCheck()
        ]

    def validate(self, parsed_config: Dict[str, Any], raw_config: str) -> ValidationResult:
        result = ValidationResult()
        result.hostname = parsed_config.get("hostname", "unknown")
        result.vendor = parsed_config.get("vendor", "unknown")
        result.model = parsed_config.get("model", "")
        result.ios_version = parsed_config.get("ios_version", "")
        result.total_lines = len(raw_config.splitlines())
        result.parsed_interfaces = parsed_config.get("interfaces", [])
        result.parsed_vlans = parsed_config.get("vlans", [])

        for check in self.checks:
            findings = check.run(parsed_config, raw_config)
            result.findings.extend(findings)

        # Sort by severity
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, 
                         Severity.LOW: 3, Severity.INFO: 4}
        result.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        return result
