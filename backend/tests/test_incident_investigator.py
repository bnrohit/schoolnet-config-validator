import os

import pytest

from incident_investigator import (
    _allow_ip,
    _correlate,
    _device_findings,
    _security_findings,
    _validate_hostname_or_ip,
)


def test_target_validation_blocks_shell_syntax():
    assert _validate_hostname_or_ip("10.0.0.1") == "10.0.0.1"
    assert _validate_hostname_or_ip("switch01.example.internal") == "switch01.example.internal"
    with pytest.raises(ValueError):
        _validate_hostname_or_ip("10.0.0.1;rm -rf /")


def test_public_diagnostics_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ALLOW_PUBLIC_DIAGNOSTICS", raising=False)
    assert _allow_ip("10.0.0.1") is True
    assert _allow_ip("8.8.8.8") is False


def test_security_findings_flag_plaintext_management():
    findings = _security_findings([
        {"port": 23, "open": True},
        {"port": 80, "open": True},
        {"port": 443, "open": False},
    ], [])
    titles = {item["title"] for item in findings}
    assert "Telnet is reachable" in titles
    assert "Plain HTTP is reachable" in titles


def test_correlation_distinguishes_filtered_icmp_from_outage():
    hypotheses = _correlate(
        "router.internal",
        {"addresses": ["10.0.0.1"], "system_error": None},
        {"reachable": False},
        {"ok": True, "available": True},
        [{"port": 443, "open": True}],
        [],
        [],
        {"findings": []},
    )
    assert any("ICMP appears filtered" in item["title"] for item in hypotheses)


def test_device_findings_extract_native_vlan_and_crc():
    results = [{
        "category": "errors",
        "results": [{
            "command": "show logging",
            "output": "CDP-4-NATIVE_VLAN_MISMATCH: Native VLAN mismatch detected\n17 CRC",
            "error": None,
        }],
    }]
    findings = _device_findings(results)
    titles = {item["title"] for item in findings}
    assert "Native VLAN mismatch evidence" in titles
    assert any("CRC" in title or "crc" in title for title in titles)
