"""
Security Configuration Validation
- No port security on access ports
- No DHCP snooping
- No dynamic ARP inspection
- Weak SNMP communities
- Telnet enabled
"""
from typing import List, Dict, Any
import re
from ..engine import Finding, Severity, CheckType

class SecurityCheck:
    def run(self, parsed_config: Dict[str, Any], raw_config: str) -> List[Finding]:
        findings = []
        interfaces = parsed_config.get("interfaces", [])
        global_config = parsed_config.get("global_config", {})

        # Check 1: Telnet enabled
        if global_config.get("telnet_enabled", False):
            findings.append(Finding(
                check_type=CheckType.SECURITY_GAP,
                severity=Severity.CRITICAL,
                interface=None,
                message="Telnet is enabled - credentials sent in plaintext",
                remediation="Disable telnet: no service telnet / use SSH only"
            ))

        # Check 2: Weak SNMP community
        snmp_communities = global_config.get("snmp_communities", [])
        weak_communities = [c for c in snmp_communities 
                          if c.get("name", "").lower() in ["public", "private", "cisco"]]
        for comm in weak_communities:
            findings.append(Finding(
                check_type=CheckType.SECURITY_GAP,
                severity=Severity.HIGH,
                interface=None,
                message=f"Weak SNMP community '{comm['name']}' configured",
                remediation="Remove default communities, use SNMPv3 with auth+priv"
            ))

        # Check 3: No DHCP snooping
        if not global_config.get("dhcp_snooping_enabled", False):
            findings.append(Finding(
                check_type=CheckType.SECURITY_GAP,
                severity=Severity.HIGH,
                interface=None,
                message="DHCP Snooping not enabled - rogue DHCP server can hijack clients",
                remediation="Enable: ip dhcp snooping / ip dhcp snooping vlan [range]"
            ))

        # Check 4: Access ports without port security
        for iface in interfaces:
            if not iface.get("is_access", False):
                continue

            iface_name = iface.get("name", "unknown")

            if not iface.get("port_security", False):
                findings.append(Finding(
                    check_type=CheckType.SECURITY_GAP,
                    severity=Severity.MEDIUM,
                    interface=iface_name,
                    message="Access port without port security - MAC flooding possible",
                    remediation="Configure: switchport port-security / switchport port-security maximum 2",
                    raw_config=iface.get("raw_config", "")
                ))

        # Check 5: No dynamic ARP inspection
        if not global_config.get("dynamic_arp_inspection", False):
            findings.append(Finding(
                check_type=CheckType.SECURITY_GAP,
                severity=Severity.MEDIUM,
                interface=None,
                message="Dynamic ARP Inspection not enabled - ARP spoofing possible",
                remediation="Enable: ip arp inspection vlan [range] (requires DHCP snooping)"
            ))

        return findings
