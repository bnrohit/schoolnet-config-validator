"""Best-effort multi-vendor network configuration parser.

The goal of this parser is safe normalization, not vendor-perfect emulation. It
extracts high-confidence facts that can be consumed by vendor-neutral checks.
Unknown syntax is preserved in raw form and never converted into executable
changes automatically.
"""
import re
from typing import Any, Dict, List, Tuple


VENDOR_SIGNATURES: List[Tuple[str, str, List[str]]] = [
    ("cisco_nxos", "Cisco NX-OS", [r"nx-?os", r"feature\s+nxapi", r"feature\s+vpc", r"interface\s+Ethernet\d+/\d+"]),
    ("cisco_asa", "Cisco ASA", [r"ASA Version", r"same-security-traffic", r"object\s+network", r"access-group\s+\S+\s+in\s+interface"]),
    ("cisco_iosxe", "Cisco IOS-XE", [r"IOS[- ]XE", r"Cisco IOS XE", r"version\s+1[567]\."]),
    ("cisco_ios", "Cisco IOS", [r"Cisco IOS Software", r"switchport\s+mode", r"router\s+ospf", r"ip\s+routing"]),
    ("arista_eos", "Arista EOS", [r"Arista", r"daemon\s+TerminAttr", r"management\s+api\s+http-commands"]),
    ("juniper_junos", "Juniper Junos", [r"JUNOS", r"set\s+system\s+host-name", r"set\s+interfaces\s+ge-", r"protocols\s*\{"] ),
    ("aruba_aoscx", "Aruba AOS-CX", [r"AOS-CX", r"interface\s+1/1/\d+", r"vlan\s+access\s+\d+"]),
    ("aruba_aos", "Aruba AOS-Switch", [r"ArubaOS-Switch", r"ProCurve", r"HP\s+J\d+"] ),
    ("hpe_comware", "HPE Comware", [r"HPE Comware", r"^sysname\s+", r"port\s+link-type", r"undo\s+telnet\s+server"]),
    ("extreme_exos", "ExtremeXOS", [r"ExtremeXOS", r"configure\s+vlan", r"enable\s+sharing"]),
    ("extreme_voss", "Extreme VOSS", [r"VOSS", r"vlan\s+create", r"ethernet\s+tagging"]),
    ("brocade_fastiron", "Brocade/Ruckus FastIron", [r"FastIron", r"Ruckus\s+ICX", r"Brocade\s+ICX"]),
    ("dell_os10", "Dell OS10", [r"OS10", r"interface\s+ethernet1/1/"] ),
    ("dell_os9", "Dell OS9/FTOS", [r"Dell Networking OS", r"Force10", r"FTOS"]),
    ("mikrotik_routeros", "MikroTik RouterOS", [r"/interface\s+bridge", r"/ip\s+address", r"/routing\s+(?:ospf|bgp)"] ),
    ("vyos", "VyOS", [r"set\s+interfaces\s+(?:ethernet|bonding|wireguard)", r"set\s+protocols\s+(?:ospf|bgp)", r"set\s+service\s+ssh"]),
    ("fortios", "Fortinet FortiOS", [r"config\s+system\s+interface", r"config\s+router\s+(?:ospf|bgp)", r"config\s+firewall\s+policy"]),
    ("paloalto_panos", "Palo Alto PAN-OS", [r"set\s+deviceconfig\s+system", r"set\s+network\s+interface", r"set\s+network\s+virtual-router"]),
    ("sonic", "SONiC", [r"SONiC", r'"PORT"\s*:', r'"VLAN"\s*:']),
    ("linux_frr", "FRRouting/Linux", [r"frr\s+version", r"router\s+bgp\s+\d+", r"router\s+ospf", r"ip\s+route\s+"] ),
    ("ubiquiti_edgeos", "Ubiquiti EdgeOS", [r"set\s+service\s+ssh", r"set\s+interfaces\s+ethernet\s+eth\d+", r"set\s+protocols\s+static"]),
]

VENDOR_NAMES = {vendor: name for vendor, name, _ in VENDOR_SIGNATURES}


def detect_vendor(config_text: str) -> Dict[str, Any]:
    """Return the most likely platform with a conservative confidence score."""
    scores: Dict[str, int] = {}
    evidence: Dict[str, List[str]] = {}
    for vendor, _name, patterns in VENDOR_SIGNATURES:
        for pattern in patterns:
            if re.search(pattern, config_text, re.I | re.M):
                scores[vendor] = scores.get(vendor, 0) + 1
                evidence.setdefault(vendor, []).append(pattern)

    if not scores:
        return {"vendor": "generic", "name": "Generic Network Device", "confidence": 0.25, "evidence": []}

    vendor = max(scores, key=scores.get)
    hits = scores[vendor]
    confidence = min(0.98, 0.45 + (hits * 0.16))
    return {
        "vendor": vendor,
        "name": VENDOR_NAMES.get(vendor, vendor),
        "confidence": round(confidence, 2),
        "evidence": evidence.get(vendor, []),
    }


class GenericNetworkParser:
    """Extract common network concepts across switch/router/firewall platforms."""

    def __init__(self, vendor_hint: str = "auto"):
        self.vendor_hint = (vendor_hint or "auto").lower()

    def parse(self, config_text: str) -> Dict[str, Any]:
        detected = detect_vendor(config_text)
        vendor = detected["vendor"] if self.vendor_hint in ("auto", "generic", "") else self.vendor_hint
        if vendor != detected["vendor"] and self.vendor_hint not in ("auto", "generic", ""):
            detected = {
                "vendor": vendor,
                "name": VENDOR_NAMES.get(vendor, vendor),
                "confidence": 0.70,
                "evidence": ["operator supplied vendor hint"],
            }

        lines = config_text.splitlines()
        interfaces = self._parse_interfaces(lines)
        vlans = self._parse_vlans(lines)
        hostname = self._parse_hostname(config_text)
        version = self._parse_version(config_text)

        return {
            "hostname": hostname or "unknown",
            "vendor": vendor,
            "vendor_name": detected.get("name", vendor),
            "model": "",
            "ios_version": version,
            "vlans": vlans,
            "interfaces": interfaces,
            "global_config": self._parse_global(config_text),
            "routing": self._parse_routing(config_text),
            "analysis": {
                "mode": "universal",
                "parser_confidence": detected.get("confidence", 0.25),
                "detection_evidence": detected.get("evidence", []),
                "structured_l2": bool(interfaces or vlans),
                "safe_to_auto_remediate": False,
            },
            "raw": config_text,
        }

    def _parse_hostname(self, text: str) -> str:
        patterns = [
            r"(?im)^hostname\s+([^\s;]+)",
            r"(?im)^sysname\s+([^\s;]+)",
            r"(?im)^set\s+system\s+host-name\s+([^\s;]+)",
            r"(?im)^set\s+system\s+host-name\s+\"?([^\s\"]+)\"?",
            r"(?im)^/system\s+identity\s+set\s+name=([^\s]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1).strip('"')
        return ""

    def _parse_version(self, text: str) -> str:
        for pattern in [
            r"(?im)^(?:version|software version|junos:)\s*[: ]\s*(.+)$",
            r"(?im)^.*(?:IOS|NX-OS|EOS|ExtremeXOS|Comware|FortiOS|RouterOS).*Version.*$",
        ]:
            match = re.search(pattern, text)
            if match:
                return match.group(0).strip()[:240]
        return ""

    def _default_interface(self, name: str, line: int) -> Dict[str, Any]:
        return {
            "name": name,
            "line": line,
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
            "raw_config": "",
        }

    def _parse_interfaces(self, lines: List[str]) -> List[Dict[str, Any]]:
        interfaces: List[Dict[str, Any]] = []
        current = None
        buffer: List[str] = []

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            match = re.match(r"^(?:interface|edit)\s+[\"']?([^\"']+?)[\"']?$", stripped, re.I)
            if match and not stripped.lower().startswith("interface range"):
                if current:
                    current["raw_config"] = "\n".join(buffer)
                    interfaces.append(current)
                current = self._default_interface(match.group(1).strip(), line_num)
                buffer = [stripped]
                continue

            if current is None:
                continue

            # End common hierarchical sections.
            if stripped in ("!", "exit", "next"):
                buffer.append(stripped)
                current["raw_config"] = "\n".join(buffer)
                interfaces.append(current)
                current = None
                buffer = []
                continue

            buffer.append(stripped)
            low = stripped.lower()
            if low in ("shutdown", "disable") or low.startswith("set disable"):
                current["is_shutdown"] = True
            if re.search(r"(?:switchport\s+mode\s+trunk|port\s+link-type\s+trunk|vlan\s+trunk)", low):
                current["is_trunk"] = True
            access = re.search(r"(?:switchport\s+access\s+vlan|port\s+default\s+vlan|vlan\s+access)\s+(\d+)", low)
            if access:
                current["is_access"] = True
                current["access_vlan"] = int(access.group(1))
            native = re.search(r"(?:native\s+vlan|pvid)\s+(\d+)", low)
            if native:
                current["native_vlan"] = int(native.group(1))
            allowed = re.search(r"(?:allowed\s+vlan(?:s)?|permit\s+vlan)\s+(.+)", low)
            if allowed:
                current["allowed_vlans"] = self._parse_vlan_list(allowed.group(1))
            duplex = re.search(r"\bduplex\s+(auto|full|half)\b", low)
            if duplex:
                current["duplex"] = duplex.group(1)
            speed = re.search(r"\bspeed\s+([\w.-]+)", low)
            if speed:
                current["speed"] = speed.group(1)
            if "portfast" in low or "admin-edge" in low or "edge-port" in low:
                current["spanning_tree_portfast"] = True
            if "bpduguard" in low or "bpdu-protection" in low:
                current["spanning_tree_bpdu_guard"] = True
            if "root guard" in low or "root-protection" in low:
                current["spanning_tree_root_guard"] = True
            if "port-security" in low or "port security" in low:
                current["port_security"] = True
            pc = re.search(r"(?:channel-group|lag|trunk-group)\s+(\d+)", low)
            if pc:
                current["port_channel"] = int(pc.group(1))
            if any(token in low for token in ("sfp", "fiber", "optical")):
                current["media"] = "fiber"
            if "udld" in low:
                current["udld_enabled"] = True
            if "dynamic desirable" in low or "dynamic auto" in low:
                current["trunk_negotiation"] = low

        if current:
            current["raw_config"] = "\n".join(buffer)
            interfaces.append(current)
        return interfaces

    def _parse_vlans(self, lines: List[str]) -> List[Dict[str, Any]]:
        seen = set()
        vlans: List[Dict[str, Any]] = []
        patterns = [
            r"^vlan\s+(\d+)(?:\s+name\s+(.+))?",
            r"^create\s+vlan\s+\S+\s+tag\s+(\d+)",
            r"^set\s+vlans\s+\S+\s+vlan-id\s+(\d+)",
            r"^vlan\s+create\s+(\d+)",
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            for pattern in patterns:
                match = re.search(pattern, stripped, re.I)
                if match:
                    vlan_id = int(match.group(1))
                    if vlan_id not in seen:
                        seen.add(vlan_id)
                        name = match.group(2).strip() if match.lastindex and match.lastindex >= 2 and match.group(2) else ""
                        vlans.append({"id": vlan_id, "name": name, "line": line_num})
                    break
        return vlans

    def _parse_vlan_list(self, text: str) -> List[int]:
        result: List[int] = []
        clean = re.sub(r"\b(add|remove|except|tagged|untagged)\b", "", text, flags=re.I)
        for part in re.split(r"[,\s]+", clean.strip()):
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    result.extend(range(int(start), int(end) + 1))
                except ValueError:
                    pass
            else:
                try:
                    result.append(int(part))
                except ValueError:
                    pass
        return sorted(set(result))

    def _parse_global(self, text: str) -> Dict[str, Any]:
        return {
            "stp_mode": "",
            "telnet_enabled": bool(re.search(r"(?im)(transport\s+input[^\n]*telnet|set\s+system\s+services\s+telnet|telnet\s+server\s+enable|enable\s+telnet)", text)),
            "snmp_communities": [
                {"name": match.group(1)}
                for match in re.finditer(r"(?im)(?:snmp-server\s+community|snmp-agent\s+community\s+(?:read|write)|set\s+snmp\s+community)\s+[\"']?([^\s\"']+)", text)
            ],
            "dhcp_snooping_enabled": bool(re.search(r"(?im)(ip\s+dhcp\s+snooping|dhcp-snooping|dhcp snooping)", text)),
            "dynamic_arp_inspection": bool(re.search(r"(?im)(ip\s+arp\s+inspection|arp\s+inspection|dynamic arp inspection)", text)),
        }

    def _parse_routing(self, text: str) -> Dict[str, Any]:
        protocols = []
        protocol_patterns = {
            "ospf": r"(?im)(router\s+ospf|protocols\s+ospf|set\s+protocols\s+ospf|config\s+router\s+ospf)",
            "ospfv3": r"(?im)(router\s+ospfv3|ospf3|ospfv3)",
            "bgp": r"(?im)(router\s+bgp|protocols\s+bgp|set\s+protocols\s+bgp|config\s+router\s+bgp)",
            "isis": r"(?im)(router\s+isis|protocols\s+isis|is-is)",
            "rip": r"(?im)(router\s+rip|protocols\s+rip)",
            "pim": r"(?im)(ip\s+pim|protocols\s+pim|pim-sparse)",
            "vrrp": r"(?im)\bvrrp\b",
            "hsrp": r"(?im)\bstandby\s+\d+\s+ip\b",
        }
        for name, pattern in protocol_patterns.items():
            if re.search(pattern, text):
                protocols.append(name)
        return {"protocols": protocols}
