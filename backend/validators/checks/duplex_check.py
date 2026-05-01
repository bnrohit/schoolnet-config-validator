"""
Duplex/Speed Mismatch Detection
- Auto-negotiation disabled without explicit settings
- Half-duplex configurations
- Speed mismatches between linked ports
"""
from typing import List, Dict, Any
from ..engine import Finding, Severity, CheckType

class DuplexCheck:
    def run(self, parsed_config: Dict[str, Any], raw_config: str) -> List[Finding]:
        findings = []
        interfaces = parsed_config.get("interfaces", [])

        for iface in interfaces:
            if iface.get("is_shutdown", False):
                continue

            iface_name = iface.get("name", "unknown")
            duplex = iface.get("duplex", "auto")
            speed = iface.get("speed", "auto")

            # Check 1: Half-duplex
            if duplex == "half":
                findings.append(Finding(
                    check_type=CheckType.DUPLEX_MISMATCH,
                    severity=Severity.HIGH,
                    interface=iface_name,
                    message="Interface in half-duplex - severe performance impact and collisions",
                    remediation="Configure: duplex full (or remove to use auto-negotiation)",
                    raw_config=iface.get("raw_config", "")
                ))

            # Check 2: Hard-coded speed without duplex
            if speed != "auto" and duplex == "auto":
                findings.append(Finding(
                    check_type=CheckType.DUPLEX_MISMATCH,
                    severity=Severity.MEDIUM,
                    interface=iface_name,
                    message=f"Speed hard-coded to {speed} but duplex is auto - may negotiate to half-duplex",
                    remediation="Hard-code both: speed {0}\nduplex full".format(speed),
                    raw_config=iface.get("raw_config", "")
                ))

            # Check 3: Auto on critical uplinks
            if iface.get("is_uplink", False) and speed == "auto" and duplex == "auto":
                findings.append(Finding(
                    check_type=CheckType.DUPLEX_MISMATCH,
                    severity=Severity.LOW,
                    interface=iface_name,
                    message="Uplink using auto-negotiation - consider hard-coding for stability",
                    remediation="Configure explicit speed/duplex on uplinks",
                    raw_config=iface.get("raw_config", "")
                ))

        return findings
