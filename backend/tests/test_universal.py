from parsers import get_parser
from validators.engine import ValidationEngine


def validate(text, vendor="auto"):
    parsed = get_parser(vendor).parse(text)
    return ValidationEngine().validate(parsed, text).to_dict()


def test_detects_junos_and_telnet_safely():
    config = """
set system host-name edge-junos-01
set system services ssh
set system services telnet
set interfaces ge-0/0/0 unit 0 family ethernet-switching interface-mode trunk
set protocols ospf area 0.0.0.0 interface ge-0/0/1.0
"""
    result = validate(config)
    assert result["vendor"] == "juniper_junos"
    messages = [f["message"] for f in result["findings"]]
    assert any("Telnet" in message for message in messages)
    telnet = next(f for f in result["findings"] if "Telnet" in f["message"])
    assert telnet["automation_safe"] is False
    assert telnet["pre_checks"]
    assert telnet["rollback"]
    assert telnet["post_checks"]


def test_detects_vyos_routing_without_inventing_l2_failures():
    config = """
set system host-name 'wan-router-01'
set service ssh port '22'
set interfaces ethernet eth0 address '192.0.2.2/30'
set protocols ospf area 0 network '192.0.2.0/30'
set protocols bgp system-as '65010'
"""
    result = validate(config)
    assert result["vendor"] == "vyos"
    assert "ospf" in result["routing"]["protocols"]
    assert "bgp" in result["routing"]["protocols"]
    # Generic routing configs should not get Cisco-specific missing DHCP snooping findings.
    assert not any("DHCP Snooping not enabled" in f["message"] for f in result["findings"])


def test_detects_comware_and_weak_snmp():
    config = """
sysname CORE-COMWARE
snmp-agent community read public
telnet server enable
interface GigabitEthernet1/0/1
 port link-type trunk
 port trunk permit vlan all
"""
    result = validate(config)
    assert result["vendor"] == "hpe_comware"
    assert any("SNMP community" in f["message"] for f in result["findings"])
    assert any("Telnet" in f["message"] for f in result["findings"])


def test_unknown_vendor_stays_conservative():
    config = """
SYSTEM-NAME mystery-device
some proprietary interface syntax
secure-management enabled
"""
    result = validate(config)
    assert result["vendor"] == "generic"
    assert result["analysis"]["mode"] == "universal"
    assert any("not identified with high confidence" in f["message"] for f in result["findings"])
