import pytest
from parsers.cisco_ios import CiscoIOSParser
from validators.engine import ValidationEngine
from validators.checks.vlan_check import VlanCheck
from validators.checks.native_vlan_check import NativeVlanCheck
from validators.checks.stp_check import StpCheck

class TestVlanCheck:
    def test_missing_vlan(self):
        config = """
        hostname test
        vlan 10
         name Students
        interface GigabitEthernet0/1
         switchport mode access
         switchport access vlan 99
        """
        parser = CiscoIOSParser()
        parsed = parser.parse(config)
        check = VlanCheck()
        findings = check.run(parsed, config)

        assert any(f.severity.value == "critical" and "non-existent VLAN 99" in f.message for f in findings)

    def test_vlan_1_data(self):
        config = """
        hostname test
        interface GigabitEthernet0/1
         switchport mode access
         switchport access vlan 1
        """
        parser = CiscoIOSParser()
        parsed = parser.parse(config)
        check = VlanCheck()
        findings = check.run(parsed, config)

        assert any(f.severity.value == "high" and "default VLAN 1" in f.message for f in findings)

class TestNativeVlanCheck:
    def test_native_vlan_1(self):
        config = """
        hostname test
        interface GigabitEthernet0/1
         switchport mode trunk
        """
        parser = CiscoIOSParser()
        parsed = parser.parse(config)
        check = NativeVlanCheck()
        findings = check.run(parsed, config)

        assert len(findings) >= 1
        assert any("VLAN hopping" in f.message for f in findings)

class TestStpCheck:
    def test_missing_portfast(self):
        config = """
        hostname test
        interface GigabitEthernet0/1
         switchport mode access
         switchport access vlan 10
        """
        parser = CiscoIOSParser()
        parsed = parser.parse(config)
        check = StpCheck()
        findings = check.run(parsed, config)

        assert any("PortFast" in f.message for f in findings)

    def test_missing_bpdu_guard(self):
        config = """
        hostname test
        interface GigabitEthernet0/1
         switchport mode access
         switchport access vlan 10
         spanning-tree portfast
        """
        parser = CiscoIOSParser()
        parsed = parser.parse(config)
        check = StpCheck()
        findings = check.run(parsed, config)

        assert any("BPDU Guard" in f.message for f in findings)

class TestIntegration:
    def test_full_validation(self):
        config = """
        hostname broken-switch
        vlan 10
         name Test
        interface GigabitEthernet0/1
         switchport mode trunk
        interface GigabitEthernet0/2
         switchport mode access
         switchport access vlan 99
        """
        parser = CiscoIOSParser()
        parsed = parser.parse(config)
        engine = ValidationEngine()
        result = engine.validate(parsed, config)

        assert result.hostname == "broken-switch"
        assert result.critical_count >= 1
        assert result.high_count >= 1
