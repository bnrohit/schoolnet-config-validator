"""Read-only Linux host diagnostic profile for Incident Investigator.

Commands are intentionally bounded to observation only. They do not use sudo,
install packages, restart services, modify files, or change firewall/routing state.
"""
from typing import Any, Dict, List

from .ssh_client import SwitchSSHClient


LINUX_PROFILE = {
    "basic": [
        "uname -a",
        "uptime",
        "who",
    ],
    "interfaces": [
        "ip -brief address",
        "ip -s link",
    ],
    "vlan": [
        "ip -d link show type vlan",
        "bridge vlan show",
    ],
    "stp": [
        "bridge link",
        "bridge vlan show",
    ],
    "mac": [
        "bridge fdb show",
    ],
    "arp": [
        "ip neigh show",
        "ip route show",
    ],
    "routing": [
        "ip route show",
        "ip -6 route show",
        "ss -s",
    ],
    "errors": [
        "ip -s link",
        "journalctl -p warning -n 80 --no-pager",
        "systemctl --failed --no-pager",
    ],
    "neighbors": [
        "ip neigh show",
        "lldpcli show neighbors",
    ],
    "poe": [],
    "security": [
        "ss -lntup",
        "systemctl --failed --no-pager",
        "cat /etc/resolv.conf",
    ],
}


LABELS = {
    "basic": "Kernel, uptime and logged-in users",
    "interfaces": "Addresses, link state and counters",
    "vlan": "802.1Q/bridge VLAN state where configured",
    "stp": "Linux bridge/link state",
    "mac": "Bridge forwarding database",
    "arp": "Neighbor cache and routes",
    "routing": "IPv4/IPv6 routes and socket summary",
    "errors": "Interface counters, warning logs and failed units",
    "neighbors": "Neighbor cache and LLDP where installed",
    "poe": "Not applicable",
    "security": "Listening sockets, failed services and resolver configuration",
}


def run_linux_check(client: SwitchSSHClient, category: str) -> Dict[str, Any]:
    category = category if category in LINUX_PROFILE else "basic"
    return {
        "category": category,
        "description": LABELS.get(category, category),
        "results": client.run_commands(LINUX_PROFILE.get(category, []), use_textfsm=False),
    }


def run_linux_snapshot(client: SwitchSSHClient, categories: List[str]) -> List[Dict[str, Any]]:
    return [run_linux_check(client, category) for category in categories if category in LINUX_PROFILE]
