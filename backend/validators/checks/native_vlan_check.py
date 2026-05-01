"""
Native VLAN Mismatch Detection
- Native VLAN not 1 (security best practice)
- Mismatched native VLANs on trunk peers
- Native VLAN not in allowed list
"""
from typing import List, Dict, Any
from ..engine import Finding, Severity, CheckType

class NativeVlanCheck:
    def run(self, parsed_config: Dict[str, Any], raw_config: str) -> List[Finding]:
        findings = []
        interfaces = parsed_config.get("interfaces", [])

        for iface in interfaces:
            if not iface.get("is_trunk"):
                continue

            iface_name = iface.get("name", "unknown")
            native_vlan = iface.get("native_vlan", 1)
            allowed_vlans = iface.get("allowed_vlans", [])

            # Check 1: Native VLAN is 1 (security risk - VLAN hopping)
            if native_vlan == 1:
                findings.append(Finding(
                    check_type=CheckType.NATIVE_VLAN_MISMATCH,
                    severity=Severity.HIGH,
                    interface=iface_name,
                    message="Native VLAN is 1 - vulnerable to VLAN hopping attacks (double-tagging)",
                    remediation="Set native VLAN to unused VLAN (e.g., 'switchport trunk native vlan 999')",
                    raw_config=iface.get("raw_config", "")
                ))

            # Check 2: Native VLAN not in allowed list
            if allowed_vlans and native_vlan not in allowed_vlans:
                findings.append(Finding(
                    check_type=CheckType.NATIVE_VLAN_MISMATCH,
                    severity=Severity.CRITICAL,
                    interface=iface_name,
                    message=f"Native VLAN {native_vlan} not in allowed VLANs list",
                    remediation=f"Add VLAN {native_vlan} to allowed list or change native VLAN",
                    raw_config=iface.get("raw_config", "")
                ))

            # Check 3: Native VLAN same as access VLAN on same switch
            access_ports_same_vlan = [
                i for i in interfaces 
                if i.get("is_access") and i.get("access_vlan") == native_vlan
            ]
            if access_ports_same_vlan:
                findings.append(Finding(
                    check_type=CheckType.NATIVE_VLAN_MISMATCH,
                    severity=Severity.HIGH,
                    interface=iface_name,
                    message=f"Native VLAN {native_vlan} also used on access ports - security risk",
                    remediation="Use dedicated unused VLAN for native (never assign to access ports)",
                    raw_config=iface.get("raw_config", "")
                ))

        return findings
