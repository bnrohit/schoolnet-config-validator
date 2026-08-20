from network_graph import analyze_network_bundle


def test_network_graph_infers_shared_transit_and_roles():
    devices = [
        {
            "name": "CORE1",
            "vendor": "cisco_ios",
            "config_text": """
hostname CORE1
ip routing
interface TenGigabitEthernet1/1/1
 ip address 10.255.0.1 255.255.255.252
router ospf 1
 network 10.255.0.0 0.0.0.3 area 0
""",
        },
        {
            "name": "CORE2",
            "vendor": "cisco_ios",
            "config_text": """
hostname CORE2
ip routing
interface TenGigabitEthernet1/1/1
 ip address 10.255.0.2 255.255.255.252
router ospf 1
 network 10.255.0.0 0.0.0.3 area 0
""",
        },
    ]
    result = analyze_network_bundle(devices)
    assert result["executable"] is False
    assert result["coverage"]["device_count"] == 2
    assert any(edge["kind"] == "shared_transit" and edge["network"] == "10.255.0.0/30" for edge in result["topology"]["edges"])
    assert result["topology"]["component_count"] == 1
    assert all("OSPF" in node["routing_protocols"] for node in result["topology"]["nodes"])


def test_network_graph_blocks_proposed_native_vlan_peer_mismatch():
    core = """
hostname CORE1
vlan 10
vlan 20
vlan 999
interface GigabitEthernet1/0/48
 description ACCESS1
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,999
"""
    access = """
hostname ACCESS1
vlan 10
vlan 20
vlan 999
interface GigabitEthernet1/0/48
 description CORE1
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,999
"""
    proposed_access = access.replace("native vlan 999", "native vlan 1")
    devices = [
        {
            "name": "CORE1",
            "vendor": "cisco_ios",
            "config_text": core,
            "neighbor_text": "Device ID: ACCESS1\nInterface: GigabitEthernet1/0/48, Port ID: GigabitEthernet1/0/48",
        },
        {
            "name": "ACCESS1",
            "vendor": "cisco_ios",
            "config_text": access,
            "proposed_config": proposed_access,
            "neighbor_text": "Device ID: CORE1\nInterface: GigabitEthernet1/0/48, Port ID: GigabitEthernet1/0/48",
        },
    ]
    result = analyze_network_bundle(devices)
    assert result["network_change_gate"]["status"] == "BLOCK"
    assert result["network_risk_label"] == "critical"
    assert any(f["type"] == "proposed_native_vlan_mismatch" for f in result["cross_device_change_findings"])
    assert any(item["origin_device"] == "ACCESS1" and item["device"] == "CORE1" for item in result["impact_propagation"])


def test_network_graph_discloses_limited_inference_without_peer_evidence():
    devices = [
        {"name": "A", "vendor": "generic", "config_text": "hostname A\ninterface Ethernet1\n description user-port"},
        {"name": "B", "vendor": "generic", "config_text": "hostname B\ninterface Ethernet1\n description user-port"},
    ]
    result = analyze_network_bundle(devices)
    assert result["topology"]["inference_quality"] == "limited"
    assert result["topology"]["component_count"] == 2
    assert result["limitations"]
