"""
Aruba AOS-CX / AOS-Switch Configuration Parser
Leverages CiscoIOSParser with Aruba-specific overrides
"""
from .cisco_ios import CiscoIOSParser
import re
from typing import Dict, Any

class ArubaParser(CiscoIOSParser):
    def parse(self, config_text: str) -> Dict[str, Any]:
        result = super().parse(config_text)
        result["vendor"] = "aruba"

        # Aruba-specific: VLAN syntax is "vlan 10" without "vlan database"
        # Trunk syntax: "trunk 1/1/1-1/1/2 trk1 trunk"

        # Fix trunk detection for Aruba
        for iface in result["interfaces"]:
            raw = iface.get("raw_config", "")
            if "trunk" in raw.lower() and "no trunk" not in raw.lower():
                iface["is_trunk"] = True

            # Aruba port security
            if "port-security" in raw.lower():
                iface["port_security"] = True

        return result
