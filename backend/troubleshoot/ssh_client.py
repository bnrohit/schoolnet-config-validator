"""
SSH client for live switch troubleshooting
Uses Netmiko for multi-vendor support
"""
from typing import Dict, List, Any, Optional
import json
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
                banner_timeout=10
            )
            if self.secret:
                self.connection.enable()
            return True
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            raise ConnectionError(f"Failed to connect to {self.host}: {str(e)}")

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()
            self.connection = None

    def run_command(self, command: str, use_textfsm: bool = True) -> Dict[str, Any]:
        if not self.connection:
            raise RuntimeError("Not connected. Call connect() first.")

        output = self.connection.send_command(command, use_textfsm=use_textfsm)
        return {
            "command": command,
            "output": output,
            "raw": str(output) if not isinstance(output, list) else output
        }

    def run_commands(self, commands: List[str], use_textfsm: bool = True) -> List[Dict[str, Any]]:
        results = []
        for cmd in commands:
            results.append(self.run_command(cmd, use_textfsm))
        return results

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False
