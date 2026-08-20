import diagnostic_history
from diagnostic_history import compare_runs, list_runs, save_run
from path_intelligence import compare_trace_modes


def test_trace_mode_comparison_detects_divergence():
    traces = {
        "udp": {"hops": [{"hop": 1, "address": "10.0.0.1"}, {"hop": 2, "address": "10.0.0.2"}]},
        "icmp": {"hops": [{"hop": 1, "address": "10.0.0.1"}, {"hop": 2, "address": "10.0.0.3"}]},
        "tcp": {"hops": [{"hop": 1, "address": "10.0.0.1"}, {"hop": 2, "address": "10.0.0.3"}]},
    }
    result = compare_trace_modes(traces)
    assert result["first_address_divergence_hop"] == 2
    assert result["hop_comparison"][0]["same_address"] is True
    assert result["hop_comparison"][1]["same_address"] is False


def _payload(open_ports, routing_status="healthy", security_count=0):
    return {
        "overall_state": "evidence_requires_review",
        "confidence": 0.7,
        "primary_address": "10.0.0.10",
        "services": {"tcp": [{"port": port, "open": True} for port in open_ports]},
        "deep_diagnostics": {"fault_domains": [{"domain": "Routing", "status": routing_status}]},
        "application_assurance": {"application_status": "healthy", "tls_status": "healthy"},
        "security": {"findings": [{"title": "x"} for _ in range(security_count)]},
        "hypotheses": [{"title": "example"}],
        "resolver_context": {"server": "10.0.0.53"},
        "path_intelligence": {"trace_mode_comparison": {"sequences": {"tcp": ["10.0.0.1", "10.0.0.10"]}}},
    }


def test_history_save_list_compare(tmp_path, monkeypatch):
    monkeypatch.setenv("ENABLE_DIAGNOSTIC_HISTORY", "true")
    monkeypatch.setenv("DIAGNOSTIC_HISTORY_RETENTION", "20")
    monkeypatch.setattr(diagnostic_history, "DB_PATH", str(tmp_path / "history.sqlite3"))

    first = save_run(_payload([22, 443], "healthy", 1), "10.0.0.10", "before", "deep")
    second = save_run(_payload([22, 80, 443], "fault", 3), "10.0.0.10", "after", "deep")
    assert first["saved"] is True
    assert second["saved"] is True

    listing = list_runs(limit=10, target="10.0.0.10")
    assert listing["enabled"] is True
    assert len(listing["runs"]) == 2

    comparison = compare_runs(first["id"], second["id"])
    assert comparison["same_target"] is True
    assert comparison["open_tcp_delta"]["added"] == [80]
    assert comparison["security_findings"] == {"before": 1, "after": 3}
    assert comparison["fault_domain_changes"][0]["domain"] == "Routing"


def test_history_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ENABLE_DIAGNOSTIC_HISTORY", raising=False)
    result = save_run(_payload([443]), "10.0.0.10", "", "deep")
    assert result["saved"] is False
