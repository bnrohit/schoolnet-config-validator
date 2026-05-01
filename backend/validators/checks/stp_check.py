"""
Spanning Tree Protocol Validation
- Missing PortFast on access ports
- No BPDU Guard on access ports
- No Root Guard on uplinks
- STP mode (Rapid-PVST recommended)
"""
from typing import List, Dict, Any
from ..engine import Finding, Severity, CheckType

class StpCheck:
    def run(self, parsed_config: Dict[str, Any], raw_config: str) -> List[Finding]:
        findings = []
        interfaces = parsed_config.get("interfaces", [])
        global_config = parsed_config.get("global_config", {})

        stp_mode = global_config.get("stp_mode", "")

        # Check 1: STP mode not Rapid-PVST
        if stp_mode and "rapid" not in stp_mode.lower():
            findings.append(Finding(
                check_type=CheckType.STP_ISSUE,
                severity=Severity.MEDIUM,
                interface=None,
                message=f"STP mode is '{stp_mode}' - Rapid-PVST recommended for faster convergence",
                remediation="Configure: spanning-tree mode rapid-pvst"
            ))

        # Check 2: No STP configured at all
        if not stp_mode:
            findings.append(Finding(
                check_type=CheckType.STP_ISSUE,
                severity=Severity.HIGH,
                interface=None,
                message="No STP mode configured - network loops will cause broadcast storms",
                remediation="Configure: spanning-tree mode rapid-pvst"
            ))

        for iface in interfaces:
            iface_name = iface.get("name", "unknown")
            is_access = iface.get("is_access", False)
            is_trunk = iface.get("is_trunk", False)

            if is_access:
                # Check 3: Access port without PortFast
                if not iface.get("spanning_tree_portfast"):
                    findings.append(Finding(
                        check_type=CheckType.STP_ISSUE,
                        severity=Severity.MEDIUM,
                        interface=iface_name,
                        message="Access port without PortFast - causes 30-50s delay on device connection",
                        remediation="Configure: spanning-tree portfast",
                        raw_config=iface.get("raw_config", "")
                    ))

                # Check 4: Access port without BPDU Guard
                if not iface.get("spanning_tree_bpdu_guard"):
                    findings.append(Finding(
                        check_type=CheckType.STP_ISSUE,
                        severity=Severity.HIGH,
                        interface=iface_name,
                        message="Access port without BPDU Guard - rogue switch can take over STP root",
                        remediation="Configure: spanning-tree bpduguard enable",
                        raw_config=iface.get("raw_config", "")
                    ))

            if is_trunk and iface.get("is_uplink", False):
                # Check 5: Uplink without Root Guard
                if not iface.get("spanning_tree_root_guard"):
                    findings.append(Finding(
                        check_type=CheckType.STP_ISSUE,
                        severity=Severity.MEDIUM,
                        interface=iface_name,
                        message="Uplink trunk without Root Guard - unauthorized switch can become root",
                        remediation="Configure: spanning-tree guard root",
                        raw_config=iface.get("raw_config", "")
                    ))

        return findings
