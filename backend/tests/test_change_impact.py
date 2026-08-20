from change_impact import analyze_change


def test_change_impact_detects_stp_disable_and_blocks():
    before = """
hostname access01
spanning-tree mode rapid-pvst
interface GigabitEthernet1/0/48
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
 no shutdown
"""
    after = """
hostname access01
no spanning-tree vlan 10
interface GigabitEthernet1/0/48
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
 no shutdown
"""
    result = analyze_change(before, after, "cisco_ios")
    assert result["risk_label"] == "critical"
    assert result["change_gate"]["status"] == "BLOCK"
    assert any(event["id"] == "stp_disabled" for event in result["high_risk_events"])
    assert result["executable"] is False


def test_change_impact_detects_trunk_and_management_risk():
    before = """
hostname dist01
line vty 0 4
 transport input ssh
interface Port-channel1
 switchport mode trunk
 switchport trunk allowed vlan 10,20
"""
    after = """
hostname dist01
line vty 0 4
 transport input ssh telnet
interface Port-channel1
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30,40
"""
    result = analyze_change(before, after, "auto")
    assert result["blast_radius"]["management_plane"] is True
    assert result["blast_radius"]["layer2_forwarding"] is True
    assert result["change_summary"]["total_changed_lines"] >= 2
    assert result["configuration_dna"]["changed"] is True


def test_change_impact_no_change_is_minimal_review():
    config = """
hostname core01
ip routing
interface Vlan10
 ip address 10.10.10.1 255.255.255.0
"""
    result = analyze_change(config, config, "cisco_ios")
    assert result["risk_score"] == 0
    assert result["risk_label"] == "minimal"
    assert result["change_gate"]["status"] == "REVIEW"
    assert result["change_summary"]["total_changed_lines"] == 0
    assert result["configuration_dna"]["changed"] is False


def test_change_impact_tracks_routing_protocol_delta():
    before = """
hostname router01
ip routing
ip route 0.0.0.0 0.0.0.0 10.0.0.1
"""
    after = """
hostname router01
ip routing
router ospf 10
 network 10.0.0.0 0.0.0.255 area 0
"""
    result = analyze_change(before, after, "cisco_ios")
    assert "OSPF" in result["routing_protocol_delta"]["added"]
    assert result["blast_radius"]["routing_control_plane"] is True
    assert result["risk_score"] > 0
