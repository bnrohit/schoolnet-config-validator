"""
Trunk Configuration Validation
- Trunk without allowed VLAN list (all VLANs allowed)
- Trunk with VLAN 1 allowed
- Missing trunk negotiation settings
"""
from typing import List, Dict, Any
from ..engine import Finding, Severity, CheckType

class TrunkCheck:
    def run(self, parsed_config: Dict[str, Any], raw_config: str) -> List[Finding]:
        findings = []
        interfaces = parsed_config.get("interfaces", [])
        vlans = parsed_config.get("vlans", [])
        all_vlan_ids = {v.get("id") for v in vlans if v.get("id")}

        for iface in interfaces:
            if not iface.get("is_trunk"):
                continue

            iface_name = iface.get("name", "unknown")
            allowed_vlans = iface.get("allowed_vlans", [])

            # Check 1: No allowed VLAN list specified (all VLANs pass)
            if not allowed_vlans:
                findings.append(Finding(
                    check_type=CheckType.MISSING_TRUNK,
                    severity=Severity.HIGH,
                    interface=iface_name,
                    message="Trunk allows ALL VLANs - unnecessary traffic and security risk",
                    remediation="Restrict with: switchport trunk allowed vlan [list]",
                    raw_config=iface.get("raw_config", "")
                ))

            # Check 2: VLAN 1 in allowed list
            if 1 in allowed_vlans:
                findings.append(Finding(
                    check_type=CheckType.MISSING_TRUNK,
                    severity=Severity.MEDIUM,
                    interface=iface_name,
                    message="VLAN 1 allowed on trunk - unnecessary and extends broadcast domain",
                    remediation="Remove VLAN 1: switchport trunk allowed vlan remove 1",
                    raw_config=iface.get("raw_config", "")
                ))

            # Check 3: Trunk to non-trunk device (check for DTP)
            negotiation = iface.get("trunk_negotiation", "")
            if negotiation in ["dynamic desirable", "dynamic auto"]:
                findings.append(Finding(
                    check_type=CheckType.MISSING_TRUNK,
                    severity=Severity.HIGH,
                    interface=iface_name,
                    message=f"Trunk negotiation is '{negotiation}' - DTP can be exploited for VLAN hopping",
                    remediation="Configure: switchport nonegotiate (or switchport mode trunk)",
                    raw_config=iface.get("raw_config", "")
                ))

        return findings
