"""
Cisco IOS / IOS-XE Configuration Parser
Parses running-config into structured data for validation
"""
import re
from typing import Dict, List, Any, Optional

class CiscoIOSParser:
    def parse(self, config_text: str) -> Dict[str, Any]:
        lines = config_text.splitlines()
        result = {
            "hostname": "",
            "vendor": "cisco_ios",
            "model": "",
            "ios_version": "",
            "vlans": [],
            "interfaces": [],
            "global_config": {},
            "raw": config_text
        }

        current_interface = None
        interface_buffer = []

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Hostname
            if stripped.startswith("hostname "):
                result["hostname"] = stripped.split(" ", 1)[1].strip()

            # Version
            if "Cisco IOS Software" in stripped or "IOS-XE Software" in stripped:
                result["ios_version"] = stripped

            # VLAN definitions
            vlan_match = re.match(r'^vlan\s+(\d+)', stripped)
            if vlan_match:
                vlan_id = int(vlan_match.group(1))
                vlan_name = ""
                # Look ahead for name
                for next_line in lines[line_num:line_num+3]:
                    name_match = re.match(r'^\s+name\s+(.+)', next_line)
                    if name_match:
                        vlan_name = name_match.group(1).strip()
                        break
                result["vlans"].append({
                    "id": vlan_id,
                    "name": vlan_name,
                    "line": line_num
                })

            # Interface section start
            iface_match = re.match(r'^interface\s+(.+)', stripped)
            if iface_match:
                if current_interface:
                    current_interface["raw_config"] = "\n".join(interface_buffer)
                    result["interfaces"].append(current_interface)

                iface_name = iface_match.group(1).strip()
                current_interface = {
                    "name": iface_name,
                    "line": line_num,
                    "is_shutdown": False,
                    "is_access": False,
                    "is_trunk": False,
                    "is_uplink": False,
                    "access_vlan": 1,
                    "native_vlan": 1,
                    "allowed_vlans": [],
                    "duplex": "auto",
                    "speed": "auto",
                    "spanning_tree_portfast": False,
                    "spanning_tree_bpdu_guard": False,
                    "spanning_tree_root_guard": False,
                    "port_security": False,
                    "port_channel": None,
                    "media": "",
                    "udld_enabled": False,
                    "trunk_negotiation": "",
                    "raw_config": ""
                }
                interface_buffer = [stripped]

                # Detect uplink by name pattern
                if any(x in iface_name.lower() for x in ["gig", "ten", "te", "fo"]):
                    if any(x in iface_name.lower() for x in ["uplink", "trunk", "core"]):
                        current_interface["is_uplink"] = True

            elif current_interface is not None:
                interface_buffer.append(stripped)

                # Shutdown
                if stripped == "shutdown":
                    current_interface["is_shutdown"] = True

                # Access VLAN
                access_match = re.match(r'switchport\s+access\s+vlan\s+(\d+)', stripped)
                if access_match:
                    current_interface["is_access"] = True
                    current_interface["access_vlan"] = int(access_match.group(1))

                # Trunk mode
                if "switchport mode trunk" in stripped:
                    current_interface["is_trunk"] = True

                # Native VLAN
                native_match = re.match(r'switchport\s+trunk\s+native\s+vlan\s+(\d+)', stripped)
                if native_match:
                    current_interface["native_vlan"] = int(native_match.group(1))

                # Allowed VLANs
                allowed_match = re.match(r'switchport\s+trunk\s+allowed\s+vlan\s+(.+)', stripped)
                if allowed_match:
                    vlan_list = allowed_match.group(1)
                    current_interface["allowed_vlans"] = self._parse_vlan_list(vlan_list)

                # Duplex
                duplex_match = re.match(r'duplex\s+(\w+)', stripped)
                if duplex_match:
                    current_interface["duplex"] = duplex_match.group(1)

                # Speed
                speed_match = re.match(r'speed\s+(\w+)', stripped)
                if speed_match:
                    current_interface["speed"] = speed_match.group(1)

                # PortFast
                if "spanning-tree portfast" in stripped:
                    current_interface["spanning_tree_portfast"] = True

                # BPDU Guard
                if "bpduguard enable" in stripped or "bpduguard" in stripped:
                    current_interface["spanning_tree_bpdu_guard"] = True

                # Root Guard
                if "guard root" in stripped:
                    current_interface["spanning_tree_root_guard"] = True

                # Port Security
                if "switchport port-security" in stripped:
                    current_interface["port_security"] = True

                # Port-channel
                pc_match = re.match(r'channel-group\s+(\d+)', stripped)
                if pc_match:
                    current_interface["port_channel"] = int(pc_match.group(1))

                # Media type (fiber detection)
                if "media-type" in stripped or "sfp" in stripped.lower():
                    current_interface["media"] = "fiber"

                # UDLD
                if "udld enable" in stripped or "udld port" in stripped:
                    current_interface["udld_enabled"] = True

                # Trunk negotiation
                if "switchport nonegotiate" in stripped:
                    current_interface["trunk_negotiation"] = "nonegotiate"
                elif "switchport mode dynamic desirable" in stripped:
                    current_interface["trunk_negotiation"] = "dynamic desirable"
                elif "switchport mode dynamic auto" in stripped:
                    current_interface["trunk_negotiation"] = "dynamic auto"

        # Don't forget last interface
        if current_interface:
            current_interface["raw_config"] = "\n".join(interface_buffer)
            result["interfaces"].append(current_interface)

        # Parse global config
        result["global_config"] = self._parse_global_config(config_text)

        return result

    def _parse_vlan_list(self, vlan_text: str) -> List[int]:
        """Parse '1,10-15,20,30' into [1,10,11,12,13,14,15,20,30]"""
        vlans = []
        for part in vlan_text.replace(" ", "").split(","):
            if "-" in part:
                start, end = part.split("-")
                vlans.extend(range(int(start), int(end) + 1))
            else:
                try:
                    vlans.append(int(part))
                except ValueError:
                    pass
        return vlans

    def _parse_global_config(self, config_text: str) -> Dict[str, Any]:
        """Extract global configuration settings"""
        global_config = {
            "stp_mode": "",
            "telnet_enabled": False,
            "snmp_communities": [],
            "dhcp_snooping_enabled": False,
            "dynamic_arp_inspection": False
        }

        # STP mode
        stp_match = re.search(r'spanning-tree\s+mode\s+(\w+)', config_text)
        if stp_match:
            global_config["stp_mode"] = stp_match.group(1)

        # Telnet
        if re.search(r'line\s+vty\s+.*\n(?:.*\n)*?\s+transport\s+input.*telnet', config_text):
            global_config["telnet_enabled"] = True

        # SNMP communities
        for match in re.finditer(r'snmp-server\s+community\s+(\S+)', config_text):
            global_config["snmp_communities"].append({"name": match.group(1)})

        # DHCP snooping
        if "ip dhcp snooping" in config_text and "no ip dhcp snooping" not in config_text:
            global_config["dhcp_snooping_enabled"] = True

        # DAI
        if "ip arp inspection" in config_text:
            global_config["dynamic_arp_inspection"] = True

        return global_config
