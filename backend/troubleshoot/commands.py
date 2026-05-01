"""
Pre-defined troubleshooting command sets for school networks
"""
from typing import Dict, List, Any
from .ssh_client import SwitchSSHClient

class TroubleshootCommands:
    """Collection of troubleshooting workflows"""

    @staticmethod
    def get_basic_info(client: SwitchSSHClient) -> Dict[str, Any]:
        """Get switch identity and status"""
        commands = [
            "show version",
            "show running-config | include hostname",
            "show clock",
            "show users"
        ]
        return {
            "category": "basic_info",
            "description": "Switch identity and uptime",
            "results": client.run_commands(commands)
        }

    @staticmethod
    def get_interface_status(client: SwitchSSHClient) -> Dict[str, Any]:
        """Check all interface states"""
        commands = [
            "show ip interface brief",
            "show interfaces status",
            "show interfaces description"
        ]
        return {
            "category": "interfaces",
            "description": "Interface status and errors",
            "results": client.run_commands(commands)
        }

    @staticmethod
    def get_vlan_info(client: SwitchSSHClient) -> Dict[str, Any]:
        """VLAN troubleshooting"""
        commands = [
            "show vlan brief",
            "show vlan",
            "show interfaces trunk",
            "show interfaces switchport"
        ]
        return {
            "category": "vlan",
            "description": "VLAN configuration and trunk status",
            "results": client.run_commands(commands)
        }

    @staticmethod
    def get_stp_info(client: SwitchSSHClient) -> Dict[str, Any]:
        """Spanning Tree troubleshooting"""
        commands = [
            "show spanning-tree summary",
            "show spanning-tree root",
            "show spanning-tree blockedports",
            "show spanning-tree detail"
        ]
        return {
            "category": "stp",
            "description": "Spanning Tree topology and health",
            "results": client.run_commands(commands)
        }

    @staticmethod
    def get_mac_table(client: SwitchSSHClient) -> Dict[str, Any]:
        """MAC address table inspection"""
        commands = [
            "show mac address-table",
            "show mac address-table dynamic",
            "show mac address-table count"
        ]
        return {
            "category": "mac",
            "description": "MAC address table and learning",
            "results": client.run_commands(commands)
        }

    @staticmethod
    def get_arp_info(client: SwitchSSHClient) -> Dict[str, Any]:
        """ARP and routing info"""
        commands = [
            "show arp",
            "show ip arp",
            "show ip route"
        ]
        return {
            "category": "arp",
            "description": "ARP table and IP routing",
            "results": client.run_commands(commands)
        }

    @staticmethod
    def get_errors(client: SwitchSSHClient) -> Dict[str, Any]:
        """Check for interface errors"""
        commands = [
            "show interfaces counters errors",
            "show interfaces | include errors",
            "show logging | include error"
        ]
        return {
            "category": "errors",
            "description": "Interface errors and logs",
            "results": client.run_commands(commands)
        }

    @staticmethod
    def get_cdp_lldp(client: SwitchSSHClient) -> Dict[str, Any]:
        """Neighbor discovery"""
        commands = [
            "show cdp neighbors",
            "show cdp neighbors detail",
            "show lldp neighbors"
        ]
        return {
            "category": "neighbors",
            "description": "Connected devices via CDP/LLDP",
            "results": client.run_commands(commands)
        }

    @staticmethod
    def get_poe_status(client: SwitchSSHClient) -> Dict[str, Any]:
        """PoE inspection for APs/phones"""
        commands = [
            "show power inline",
            "show power inline detail"
        ]
        return {
            "category": "poe",
            "description": "PoE consumption and status",
            "results": client.run_commands(commands)
        }

    @staticmethod
    def get_port_security(client: SwitchSSHClient) -> Dict[str, Any]:
        """Port security violations"""
        commands = [
            "show port-security",
            "show port-security address",
            "show port-security interface"
        ]
        return {
            "category": "security",
            "description": "Port security violations and bindings",
            "results": client.run_commands(commands)
        }

    @staticmethod
    def run_all(client: SwitchSSHClient) -> List[Dict[str, Any]]:
        """Run complete troubleshooting suite"""
        return [
            TroubleshootCommands.get_basic_info(client),
            TroubleshootCommands.get_interface_status(client),
            TroubleshootCommands.get_vlan_info(client),
            TroubleshootCommands.get_stp_info(client),
            TroubleshootCommands.get_mac_table(client),
            TroubleshootCommands.get_errors(client),
            TroubleshootCommands.get_cdp_lldp(client),
            TroubleshootCommands.get_poe_status(client),
            TroubleshootCommands.get_port_security(client)
        ]

    @staticmethod
    def run_check(client: SwitchSSHClient, check_name: str) -> Dict[str, Any]:
        """Run specific check by name"""
        checks = {
            "basic": TroubleshootCommands.get_basic_info,
            "interfaces": TroubleshootCommands.get_interface_status,
            "vlan": TroubleshootCommands.get_vlan_info,
            "stp": TroubleshootCommands.get_stp_info,
            "mac": TroubleshootCommands.get_mac_table,
            "arp": TroubleshootCommands.get_arp_info,
            "errors": TroubleshootCommands.get_errors,
            "neighbors": TroubleshootCommands.get_cdp_lldp,
            "poe": TroubleshootCommands.get_poe_status,
            "security": TroubleshootCommands.get_port_security,
            "all": lambda c: {"category": "all", "results": TroubleshootCommands.run_all(c)}
        }

        func = checks.get(check_name, TroubleshootCommands.get_basic_info)
        return func(client)
