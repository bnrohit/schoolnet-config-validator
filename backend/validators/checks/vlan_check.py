"""
VLAN Mismatch Detection
- Access ports assigned to VLANs that don't exist
- VLAN 1 used for data (best practice violation)
- Missing management VLAN
"""
from typing import List, Dict, Any
from ..engine import Finding, Severity, CheckType

class VlanCheck:
    def run(self, parsed_config: Dict[str, Any], raw_config: str) -> List[Finding]:
        findings = []
        interfaces = parsed_config.get("interfaces", [])
        vlans = parsed_config.get("vlans", [])
        vlan_ids = {v.get("id") for v in vlans if v.get("id")}

        for iface in interfaces:
            if not iface.get("is_access"):
                continue

            access_vlan = iface.get("access_vlan")
            iface_name = iface.get("name", "unknown")

            # Check 1: VLAN doesn't exist
            if access_vlan and access_vlan not in vlan_ids and access_vlan != 1:
                findings.append(Finding(
                    check_type=CheckType.VLAN_MISMATCH,
                    severity=Severity.CRITICAL,
                    interface=iface_name,
                    message=f"Access port assigned to non-existent VLAN {access_vlan}",
                    remediation=f"Create VLAN {access_vlan} or reassign port to existing VLAN",
                    raw_config=iface.get("raw_config", "")
                ))

            # Check 2: VLAN 1 for data (security risk)
            if access_vlan == 1 and not iface.get("is_management", False):
                findings.append(Finding(
                    check_type=CheckType.VLAN_MISMATCH,
                    severity=Severity.HIGH,
                    interface=iface_name,
                    message="Port in default VLAN 1 - security risk and broadcast domain issues",
                    remediation="Assign to dedicated data/student VLAN (e.g., VLAN 10-99)",
                    raw_config=iface.get("raw_config", "")
                ))

        # Check 3: No management VLAN defined
        mgmt_vlans = [v for v in vlans if v.get("name", "").lower() in ["management", "mgmt"]]
        if not mgmt_vlans:
            findings.append(Finding(
                check_type=CheckType.VLAN_MISMATCH,
                severity=Severity.MEDIUM,
                interface=None,
                message="No dedicated management VLAN found",
                remediation="Create VLAN 999 or similar for switch management (out-of-band preferred)"
            ))

        return findings
