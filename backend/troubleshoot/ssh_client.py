"""Read-only SSH client for live network troubleshooting.

Uses Netmiko for multi-vendor access. This module never enters configuration
mode and only executes predefined show/display/get/diagnostic read commands from
the troubleshooting command catalog.
"""
from typing import Dict, List, Any
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


class SwitchSSHClient:
    def __init__(self, host: str, username: str, password: str,
                 device_type: str = "cisco_ios", port: int = 22,
                 secret: str = ""):
        self.host = host
        self.username = username
        self.password = password
        self.device_type = device_type
        self.port = port
        self.secret = secret
        self.connection = None

    def connect(self) -> bool:
        try:
            self.connection = ConnectHandler(
                device_type=self.device_type,
                host=self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                secret=self.secret,
                conn_timeout=10,
                banner_timeout=10,
                session_log=None,
            )
            if self.secret:
                # Enable mode is used only to read privileged show commands.
                # The command library never enters configuration mode.
                self.connection.enable()
            return True
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as exc:
            raise ConnectionError(f"Failed to connect to {self.host}: {exc}")

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()
            self.connection = None

    def run_command(self, command: str, use_textfsm: bool = True) -> Dict[str, Any]:
        if not self.connection:
            raise RuntimeError("Not connected. Call connect() first.")

        # Defense in depth: reject obvious configuration/write operations even
        # if a future command profile is edited incorrectly.
        normalized = command.strip().lower()
        blocked_prefixes = (
            "configure", "conf t", "config terminal", "write", "copy running",
            "commit", "save", "reload", "reboot", "delete", "erase", "request system reboot",
            "set ", "unset ", "undo ", "no ",
        )
        if normalized.startswith(blocked_prefixes):
            return {
                "command": command,
                "output": "",
                "raw": "",
                "error": "Blocked by SchoolNet read-only live diagnostics policy",
            }

        try:
            output = self.connection.send_command(command, use_textfsm=use_textfsm)
            return {
                "command": command,
                "output": output,
                "raw": str(output) if not isinstance(output, list) else output,
                "error": None,
            }
        except Exception as exc:
            return {
                "command": command,
                "output": "",
                "raw": "",
                "error": str(exc),
            }

    def run_commands(self, commands: List[str], use_textfsm: bool = True) -> List[Dict[str, Any]]:
        return [self.run_command(cmd, use_textfsm) for cmd in commands]

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False
