"""Read-only multi-vendor troubleshooting command library.

Live troubleshooting never enters configuration mode. Command profiles are
selected from the Netmiko device_type and unsupported commands are returned as
errors rather than stopping the whole diagnostic run.
"""
from typing import Dict, List, Any
from .ssh_client import SwitchSSHClient


COMMON_PROFILES = {
    "cisco": {
        "basic": ["show version", "show clock", "show users"],
        "interfaces": ["show ip interface brief", "show interfaces status", "show interfaces description"],
        "vlan": ["show vlan brief", "show interfaces trunk", "show interfaces switchport"],
        "stp": ["show spanning-tree summary", "show spanning-tree root", "show spanning-tree detail"],
        "mac": ["show mac address-table", "show mac address-table count"],
        "arp": ["show ip arp", "show ip route"],
        "errors": ["show interfaces counters errors", "show logging | include error|ERR|DOWN|UPDOWN"],
        "neighbors": ["show cdp neighbors detail", "show lldp neighbors detail"],
        "poe": ["show power inline", "show power inline detail"],
        "security": ["show port-security", "show ip dhcp snooping", "show ip arp inspection"],
        "routing": ["show ip route", "show ip ospf neighbor", "show bgp ipv4 unicast summary"],
    },
    "nxos": {
        "basic": ["show version", "show clock", "show users"],
        "interfaces": ["show interface brief", "show interface status", "show interface counters errors"],
        "vlan": ["show vlan brief", "show interface trunk"],
        "stp": ["show spanning-tree summary", "show spanning-tree root", "show spanning-tree detail"],
        "mac": ["show mac address-table", "show mac address-table count"],
        "arp": ["show ip arp", "show ip route"],
        "errors": ["show interface counters errors", "show logging last 100"],
        "neighbors": ["show cdp neighbors detail", "show lldp neighbors detail"],
        "poe": [],
        "security": ["show port-security", "show ip dhcp snooping"],
        "routing": ["show ip route", "show ip ospf neighbors", "show bgp ipv4 unicast summary"],
    },
    "junos": {
        "basic": ["show version", "show system uptime", "show system users"],
        "interfaces": ["show interfaces terse", "show interfaces descriptions", "show interfaces extensive | match error"],
        "vlan": ["show vlans", "show ethernet-switching interfaces"],
        "stp": ["show spanning-tree bridge", "show spanning-tree interface", "show spanning-tree statistics"],
        "mac": ["show ethernet-switching table"],
        "arp": ["show arp no-resolve", "show route summary", "show route"],
        "errors": ["show log messages | last 100", "show interfaces extensive | match \"error|drop|CRC\""],
        "neighbors": ["show lldp neighbors", "show lldp neighbors detail"],
        "poe": ["show poe controller", "show poe interface"],
        "security": ["show configuration system services | display set", "show configuration snmp | display set"],
        "routing": ["show route summary", "show ospf neighbor", "show bgp summary"],
    },
    "arista": {
        "basic": ["show version", "show clock", "show users"],
        "interfaces": ["show interfaces status", "show interfaces description", "show interfaces counters errors"],
        "vlan": ["show vlan", "show interfaces trunk"],
        "stp": ["show spanning-tree", "show spanning-tree root"],
        "mac": ["show mac address-table"],
        "arp": ["show ip arp", "show ip route"],
        "errors": ["show interfaces counters errors", "show logging last 100"],
        "neighbors": ["show lldp neighbors", "show lldp neighbors detail"],
        "poe": ["show poe"],
        "security": ["show port-security", "show management security"],
        "routing": ["show ip route summary", "show ip ospf neighbor", "show ip bgp summary"],
    },
    "aruba_cx": {
        "basic": ["show version", "show system", "show clock"],
        "interfaces": ["show interface brief", "show interface description", "show interface statistics"],
        "vlan": ["show vlan", "show interface trunk"],
        "stp": ["show spanning-tree", "show spanning-tree summary"],
        "mac": ["show mac-address-table"],
        "arp": ["show arp", "show ip route"],
        "errors": ["show interface statistics", "show logging -r"],
        "neighbors": ["show lldp neighbor-info", "show lldp neighbor-info detail"],
        "poe": ["show poe brief", "show poe interface"],
        "security": ["show port-access clients", "show dhcp-snooping"],
        "routing": ["show ip route", "show ip ospf neighbors", "show bgp summary"],
    },
    "comware": {
        "basic": ["display version", "display clock", "display users"],
        "interfaces": ["display interface brief", "display interface description", "display counters inbound interface"],
        "vlan": ["display vlan all", "display port trunk"],
        "stp": ["display stp brief", "display stp"],
        "mac": ["display mac-address"],
        "arp": ["display arp", "display ip routing-table"],
        "errors": ["display logbuffer", "display interface | include error|CRC|drop"],
        "neighbors": ["display lldp neighbor-information list", "display lldp neighbor-information verbose"],
        "poe": ["display poe interface"],
        "security": ["display current-configuration | include telnet|snmp|ssh", "display dhcp snooping"],
        "routing": ["display ip routing-table", "display ospf peer", "display bgp peer"],
    },
    "procurve": {
        "basic": ["show version", "show system-information", "show time"],
        "interfaces": ["show interfaces brief", "show interfaces status", "show interfaces"],
        "vlan": ["show vlans", "show trunks"],
        "stp": ["show spanning-tree", "show spanning-tree config"],
        "mac": ["show mac-address"],
        "arp": ["show arp", "show ip route"],
        "errors": ["show interfaces", "show logging -r"],
        "neighbors": ["show lldp info remote-device", "show lldp info remote-device detail"],
        "poe": ["show power-over-ethernet brief"],
        "security": ["show port-security", "show dhcp-snooping"],
        "routing": ["show ip route", "show ip ospf neighbor", "show ip bgp summary"],
    },
    "extreme": {
        "basic": ["show switch", "show version", "show time"],
        "interfaces": ["show ports", "show ports information detail", "show ports statistics"],
        "vlan": ["show vlan", "show ports vlan"],
        "stp": ["show stpd", "show stpd detail"],
        "mac": ["show fdb"],
        "arp": ["show iparp", "show iproute"],
        "errors": ["show ports statistics", "show log"],
        "neighbors": ["show lldp neighbors", "show lldp neighbors detailed"],
        "poe": ["show inline-power"],
        "security": ["show network-login", "show configuration | include telnet|snmp"],
        "routing": ["show iproute", "show ospf neighbor", "show bgp neighbor"],
    },
    "fastiron": {
        "basic": ["show version", "show clock", "show users"],
        "interfaces": ["show interfaces brief", "show interfaces", "show interfaces ethernet"],
        "vlan": ["show vlan", "show interfaces brief"],
        "stp": ["show spanning-tree", "show 802-1w"],
        "mac": ["show mac-address"],
        "arp": ["show arp", "show ip route"],
        "errors": ["show interfaces", "show logging"],
        "neighbors": ["show lldp neighbors", "show lldp neighbors detail"],
        "poe": ["show inline power"],
        "security": ["show port security", "show ip dhcp snooping"],
        "routing": ["show ip route", "show ip ospf neighbor", "show ip bgp summary"],
    },
    "dell_os10": {
        "basic": ["show version", "show clock", "show users"],
        "interfaces": ["show interface status", "show interface description", "show interface counters"],
        "vlan": ["show vlan", "show interface switchport"],
        "stp": ["show spanning-tree", "show spanning-tree brief"],
        "mac": ["show mac address-table"],
        "arp": ["show arp", "show ip route"],
        "errors": ["show interface counters", "show logging"],
        "neighbors": ["show lldp neighbors", "show lldp neighbors detail"],
        "poe": ["show power inline"],
        "security": ["show port-security", "show ip dhcp snooping"],
        "routing": ["show ip route", "show ip ospf neighbors", "show ip bgp summary"],
    },
    "vyos": {
        "basic": ["show version", "show system uptime", "show date"],
        "interfaces": ["show interfaces", "show interfaces detail"],
        "vlan": ["show interfaces"],
        "stp": ["show bridge"],
        "mac": ["show bridge macs"],
        "arp": ["show arp", "show ip route"],
        "errors": ["show log tail", "show interfaces detail"],
        "neighbors": ["show lldp neighbors", "show lldp neighbors detail"],
        "poe": [],
        "security": ["show configuration commands | match service", "show configuration commands | match snmp"],
        "routing": ["show ip route", "show ip ospf neighbor", "show bgp summary"],
    },
    "fortinet": {
        "basic": ["get system status", "get system performance status", "get system time"],
        "interfaces": ["get system interface physical", "diagnose netlink interface list"],
        "vlan": ["show system interface"],
        "stp": ["diagnose netlink brctl name host root.b"],
        "mac": ["diagnose netlink brctl list"],
        "arp": ["get system arp", "get router info routing-table all"],
        "errors": ["execute log filter category event", "execute log display"],
        "neighbors": ["get switch lldp neighbors-summary"],
        "poe": [],
        "security": ["show system admin", "show system snmp community"],
        "routing": ["get router info routing-table all", "get router info ospf neighbor", "get router info bgp summary"],
    },
    "paloalto": {
        "basic": ["show system info", "show system resources", "show clock"],
        "interfaces": ["show interface all"],
        "vlan": ["show vlan all"],
        "stp": [],
        "mac": ["show mac all"],
        "arp": ["show arp all", "show routing route"],
        "errors": ["show log system direction equal backward count 50"],
        "neighbors": ["show lldp neighbors all"],
        "poe": [],
        "security": ["show admins all", "show system setting ssl-decrypt exclude-cache"],
        "routing": ["show routing route", "show routing protocol ospf neighbor", "show routing protocol bgp peer"],
    },
    "mikrotik": {
        "basic": ["/system resource print", "/system clock print", "/system identity print"],
        "interfaces": ["/interface print detail", "/interface ethernet print stats"],
        "vlan": ["/interface vlan print detail", "/interface bridge vlan print detail"],
        "stp": ["/interface bridge print detail", "/interface bridge port print detail"],
        "mac": ["/interface bridge host print"],
        "arp": ["/ip arp print", "/ip route print detail"],
        "errors": ["/log print", "/interface ethernet print stats"],
        "neighbors": ["/ip neighbor print detail"],
        "poe": ["/interface ethernet poe print"],
        "security": ["/ip service print", "/snmp print"],
        "routing": ["/ip route print detail", "/routing ospf neighbor print detail", "/routing bgp session print detail"],
    },
}


def _profile_for(device_type: str) -> Dict[str, List[str]]:
    dt = (device_type or "").lower()
    if "nxos" in dt: return COMMON_PROFILES["nxos"]
    if "juniper" in dt or "junos" in dt: return COMMON_PROFILES["junos"]
    if "arista" in dt: return COMMON_PROFILES["arista"]
    if "aoscx" in dt: return COMMON_PROFILES["aruba_cx"]
    if "comware" in dt: return COMMON_PROFILES["comware"]
    if "procurve" in dt or "aruba_os" in dt: return COMMON_PROFILES["procurve"]
    if "extreme" in dt: return COMMON_PROFILES["extreme"]
    if "fastiron" in dt or "ruckus" in dt or "brocade" in dt: return COMMON_PROFILES["fastiron"]
    if "dell_os10" in dt: return COMMON_PROFILES["dell_os10"]
    if "vyos" in dt: return COMMON_PROFILES["vyos"]
    if "fortinet" in dt: return COMMON_PROFILES["fortinet"]
    if "paloalto" in dt: return COMMON_PROFILES["paloalto"]
    if "mikrotik" in dt: return COMMON_PROFILES["mikrotik"]
    return COMMON_PROFILES["cisco"]


class TroubleshootCommands:
    """Read-only troubleshooting workflows selected per network platform."""

    LABELS = {
        "basic": "Device identity, version, uptime and users",
        "interfaces": "Interface state, descriptions and counters",
        "vlan": "VLAN and trunk/switchport state",
        "stp": "Spanning-tree / bridge loop-prevention state",
        "mac": "MAC/FDB learning table",
        "arp": "ARP/neighbor cache and routing table",
        "errors": "Interface errors and recent logs",
        "neighbors": "LLDP/CDP/neighbor discovery",
        "poe": "Power-over-Ethernet state where supported",
        "security": "Read-only management/access-layer security state",
        "routing": "Routing table and dynamic routing neighbors",
    }

    @staticmethod
    def _run(client: SwitchSSHClient, category: str) -> Dict[str, Any]:
        commands = _profile_for(client.device_type).get(category, [])
        return {
            "category": category,
            "description": TroubleshootCommands.LABELS.get(category, category),
            "results": client.run_commands(commands),
        }

    @staticmethod
    def available_commands() -> Dict[str, str]:
        return dict(TroubleshootCommands.LABELS)

    @staticmethod
    def run_all(client: SwitchSSHClient) -> List[Dict[str, Any]]:
        return [TroubleshootCommands._run(client, category) for category in TroubleshootCommands.LABELS]

    @staticmethod
    def run_check(client: SwitchSSHClient, check_name: str) -> Dict[str, Any]:
        category = check_name if check_name in TroubleshootCommands.LABELS else "basic"
        return TroubleshootCommands._run(client, category)
