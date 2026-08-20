"""Deep read-only routing/adjacency command extensions for SchoolNet v1.7.

These commands are appended to the existing routing category. Unsupported show
commands are allowed to fail individually; no configuration/write command is
included.
"""
from __future__ import annotations

from typing import Dict, List


DEEP_ROUTING: Dict[str, List[str]] = {
    "cisco": [
        "show ip protocols",
        "show ip route summary",
        "show ip ospf",
        "show ip ospf neighbor detail",
        "show ip ospf interface brief",
        "show ip ospf database",
        "show ip bgp summary",
        "show ip bgp neighbors",
        "show ip eigrp neighbors",
        "show ip pim neighbor",
        "show standby brief",
        "show vrrp brief",
    ],
    "nxos": [
        "show ip route summary",
        "show ip ospf",
        "show ip ospf neighbors detail",
        "show ip ospf interface brief",
        "show ip ospf database",
        "show bgp ipv4 unicast summary",
        "show bgp ipv4 unicast neighbors",
        "show ip pim neighbor",
        "show hsrp brief",
        "show vrrp brief",
    ],
    "junos": [
        "show route summary",
        "show route protocol ospf",
        "show ospf overview",
        "show ospf neighbor detail",
        "show ospf interface detail",
        "show ospf database",
        "show bgp summary",
        "show bgp neighbor",
        "show pim neighbors",
        "show vrrp summary",
    ],
    "arista": [
        "show ip route summary",
        "show ip protocols",
        "show ip ospf",
        "show ip ospf neighbor detail",
        "show ip ospf interface brief",
        "show ip ospf database",
        "show ip bgp summary",
        "show ip bgp neighbors",
        "show ip pim neighbor",
        "show vrrp",
    ],
    "aruba_cx": [
        "show ip route summary",
        "show ip ospf",
        "show ip ospf neighbors detail",
        "show ip ospf interface brief",
        "show ip ospf database",
        "show bgp summary",
        "show bgp neighbors",
        "show ip pim neighbor",
        "show vrrp",
    ],
    "comware": [
        "display ip routing-table statistics",
        "display ospf brief",
        "display ospf peer verbose",
        "display ospf interface",
        "display ospf lsdb",
        "display bgp peer",
        "display pim neighbor",
        "display vrrp verbose",
    ],
    "procurve": [
        "show ip route",
        "show ip ospf",
        "show ip ospf neighbor",
        "show ip ospf interface",
        "show ip ospf link-state",
        "show ip bgp summary",
    ],
    "extreme": [
        "show iproute",
        "show ospf",
        "show ospf neighbor",
        "show ospf interface",
        "show ospf lsdb",
        "show bgp neighbor",
        "show pim neighbor",
        "show vrrp",
    ],
    "fastiron": [
        "show ip route",
        "show ip ospf",
        "show ip ospf neighbor",
        "show ip ospf interface",
        "show ip ospf database",
        "show ip bgp summary",
        "show ip bgp neighbors",
        "show ip pim neighbor",
        "show vrrp",
    ],
    "dell_os10": [
        "show ip route summary",
        "show ip ospf",
        "show ip ospf neighbors detail",
        "show ip ospf interface",
        "show ip ospf database",
        "show ip bgp summary",
        "show ip bgp neighbors",
        "show ip pim neighbor",
        "show vrrp",
    ],
    "vyos": [
        "show ip route",
        "show ip ospf",
        "show ip ospf neighbor detail",
        "show ip ospf interface",
        "show ip ospf database",
        "show bgp summary",
        "show bgp neighbors",
        "show ip pim neighbor",
        "show vrrp",
    ],
    "fortinet": [
        "get router info routing-table all",
        "get router info ospf status",
        "get router info ospf neighbor detail",
        "get router info ospf interface",
        "get router info ospf database brief",
        "get router info bgp summary",
        "get router info bgp neighbors",
        "get router info pim neighbor",
    ],
    "paloalto": [
        "show routing route",
        "show routing protocol ospf summary",
        "show routing protocol ospf neighbor",
        "show routing protocol ospf interface",
        "show routing protocol bgp summary",
        "show routing protocol bgp peer",
    ],
    "mikrotik": [
        "/ip route print detail",
        "/routing ospf instance print detail",
        "/routing ospf neighbor print detail",
        "/routing ospf interface-template print detail",
        "/routing bgp session print detail",
        "/routing bfd session print detail",
        "/interface vrrp print detail",
    ],
    "linux": [
        "ip -4 route show table all",
        "ip -6 route show table all",
        "ip rule show",
        "ip neigh show",
        "ss -lntup",
    ],
}


def extend_routing_profiles(command_catalog) -> None:
    """Append unique deep routing commands to the shared read-only catalog."""
    for profile, extra_commands in DEEP_ROUTING.items():
        target = command_catalog.COMMON_PROFILES.get(profile)
        if not target:
            continue
        routing = target.setdefault("routing", [])
        for command in extra_commands:
            if command not in routing:
                routing.append(command)
