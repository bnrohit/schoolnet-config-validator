from deep_diagnostics import _device_route_command, _exposure_findings, _fault_domains, _parse_trace


def test_exposure_findings_flags_telnet_and_database_surfaces():
    probes = [
        {"port": 23, "open": True},
        {"port": 27017, "open": True},
        {"port": 443, "open": True},
        {"port": 80, "open": False},
    ]
    findings = _exposure_findings(probes)
    titles = {item["title"] for item in findings}
    assert "Telnet service reachable" in titles
    assert "MongoDB service reachable" in titles
    assert all("exploit" not in item.get("impact", "").lower() for item in findings)


def test_trace_parser_extracts_hops_and_timeouts():
    result = {
        "stdout": "traceroute to 10.0.0.10\n 1  10.0.0.1  0.4 ms\n 2  *\n 3  10.0.0.10  1.2 ms"
    }
    hops = _parse_trace(result)
    assert hops[0]["address"] == "10.0.0.1"
    assert hops[1]["address"] is None
    assert hops[2]["address"] == "10.0.0.10"


def test_target_route_templates_remain_read_only():
    assert _device_route_command("cisco_ios", "10.0.0.10") == "show ip route 10.0.0.10"
    assert _device_route_command("juniper_junos", "10.0.0.10") == "show route 10.0.0.10 detail"
    assert _device_route_command("linux", "10.0.0.10") == "ip route get 10.0.0.10"
    assert _device_route_command("mikrotik_routeros", "10.0.0.10") is None


def test_fault_domain_matrix_separates_network_and_application_layers():
    base = {
        "dns": {"addresses": ["10.0.0.10"]},
        "path": {"ping": {"reachable": False, "packet_loss_percent": 100, "avg_rtt_ms": None}, "route": {"ok": True, "stdout": "10.0.0.10 via 10.0.0.1 dev eth0"}},
        "services": {
            "tcp": [{"port": 443, "open": True}],
            "http": [{"status": 200, "ok": True, "url": "https://x"}],
            "tls": [{"port": 443, "verified": True, "protocol": "TLSv1.3"}],
        },
    }
    deep = {"security_exposure": {"findings": []}}
    matrix = {item["domain"]: item["status"] for item in _fault_domains(base, deep)}
    assert matrix["DNS"] == "healthy"
    assert matrix["Routing"] == "healthy"
    assert matrix["ICMP"] == "unknown_or_filtered"
    assert matrix["TCP services"] == "healthy"
    assert matrix["Application"] == "healthy"
    assert matrix["TLS"] == "healthy"
