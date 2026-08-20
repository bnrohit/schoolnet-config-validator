import os

from ops_assurance import credential_transport_allowed, effective_dns_server, request_is_secure


def test_explicit_dns_wins(monkeypatch):
    monkeypatch.setenv("DEFAULT_DNS_SERVER", "10.0.0.53")
    result = effective_dns_server("10.1.1.53")
    assert result["server"] == "10.1.1.53"
    assert result["source"] == "request"


def test_default_dns_used_when_request_blank(monkeypatch):
    monkeypatch.setenv("DEFAULT_DNS_SERVER", "10.0.0.53")
    result = effective_dns_server("")
    assert result["server"] == "10.0.0.53"
    assert result["source"] == "environment"


def test_system_dns_when_unconfigured(monkeypatch):
    monkeypatch.delenv("DEFAULT_DNS_SERVER", raising=False)
    result = effective_dns_server("")
    assert result["server"] == ""
    assert result["source"] == "system"


def test_forwarded_https_is_secure():
    assert request_is_secure("http", "https") is True


def test_live_credentials_blocked_on_http_by_default(monkeypatch):
    monkeypatch.delenv("REQUIRE_HTTPS_FOR_LIVE_CREDENTIALS", raising=False)
    monkeypatch.delenv("ALLOW_INSECURE_LIVE_CREDENTIALS", raising=False)
    result = credential_transport_allowed("http", "http")
    assert result["allowed"] is False
    assert result["https_required"] is True


def test_live_credentials_allowed_on_https(monkeypatch):
    monkeypatch.setenv("REQUIRE_HTTPS_FOR_LIVE_CREDENTIALS", "true")
    monkeypatch.setenv("ALLOW_INSECURE_LIVE_CREDENTIALS", "false")
    result = credential_transport_allowed("http", "https")
    assert result["allowed"] is True
    assert result["secure_transport"] is True
