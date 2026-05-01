"""
Uplink/Redundancy Validation
- Single uplink (no redundancy)
- Uplink not in port-channel
- No UDLD on fiber uplinks
"""
from typing import List, Dict, Any
from ..engine import Finding, Severity, CheckType

class UplinkCheck:
    def run(self, parsed_config: Dict[str, Any], raw_config: str) -> List[Finding]:
        findings = []
        interfaces = parsed_config.get("interfaces", [])

        uplinks = [i for i in interfaces if i.get("is_uplink", False)]

        # Check 1: Only one uplink
        if len(uplinks) == 1:
            findings.append(Finding(
                check_type=CheckType.UPLINK_REDUNDANCY,
                severity=Severity.MEDIUM,
                interface=uplinks[0].get("name"),
                message="Only one uplink detected - no redundancy if link fails",
                remediation="Add second uplink and configure port-channel (LACP)",
                raw_config=uplinks[0].get("raw_config", "")
            ))

        # Check 2: Uplinks not in port-channel
        for uplink in uplinks:
            iface_name = uplink.get("name", "unknown")
            if not uplink.get("port_channel"):
                findings.append(Finding(
                    check_type=CheckType.UPLINK_REDUNDANCY,
                    severity=Severity.LOW,
                    interface=iface_name,
                    message="Uplink not in port-channel - manual failover only",
                    remediation="Bundle uplinks: interface port-channel 1 / channel-group 1 mode active",
                    raw_config=uplink.get("raw_config", "")
                ))

        # Check 3: Fiber uplink without UDLD
        for uplink in uplinks:
            iface_name = uplink.get("name", "unknown")
            media = uplink.get("media", "")
            if "fiber" in media.lower() and not uplink.get("udld_enabled", False):
                findings.append(Finding(
                    check_type=CheckType.UPLINK_REDUNDANCY,
                    severity=Severity.MEDIUM,
                    interface=iface_name,
                    message="Fiber uplink without UDLD - unidirectional links cause blackholes",
                    remediation="Configure: udld port aggressive (global: udld enable)",
                    raw_config=uplink.get("raw_config", "")
                ))

        return findings
