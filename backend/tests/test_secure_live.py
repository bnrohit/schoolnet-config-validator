import json

import secure_live


def _profile_file(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({
        "profiles": {
            "ro": {
                "label": "Read only",
                "username": "ops-ro",
                "password": "super-secret-test-value",
                "device_type": "cisco_ios",
                "allowed_targets": ["10.0.0.0/8"],
                "allowed_checks": ["basic", "all"],
            }
        }
    }), encoding="utf-8")
    return path


def test_public_profiles_never_return_credentials(monkeypatch, tmp_path):
    path = _profile_file(tmp_path)
    monkeypatch.setenv("ENABLE_SERVER_CREDENTIAL_PROFILES", "true")
    monkeypatch.setenv("SSH_CREDENTIAL_PROFILES_FILE", str(path))
    profiles = secure_live.list_public_profiles()
    assert profiles[0]["id"] == "ro"
    assert "password" not in profiles[0]
    assert "username" not in profiles[0]
    assert "super-secret-test-value" not in json.dumps(profiles)


def test_profile_target_allowlist_is_deny_by_default(monkeypatch, tmp_path):
    path = _profile_file(tmp_path)
    monkeypatch.setenv("ENABLE_SERVER_CREDENTIAL_PROFILES", "true")
    monkeypatch.setenv("SSH_CREDENTIAL_PROFILES_FILE", str(path))
    secure_live.get_profile("ro", "10.5.6.7", "basic")
    try:
        secure_live.get_profile("ro", "192.168.1.10", "basic")
        assert False, "target outside allowlist should be rejected"
    except PermissionError:
        pass


def test_profile_check_allowlist(monkeypatch, tmp_path):
    path = _profile_file(tmp_path)
    monkeypatch.setenv("ENABLE_SERVER_CREDENTIAL_PROFILES", "true")
    monkeypatch.setenv("SSH_CREDENTIAL_PROFILES_FILE", str(path))
    try:
        secure_live.get_profile("ro", "10.5.6.7", "routing")
        assert False, "unapproved diagnostic category should be rejected"
    except PermissionError:
        pass


def test_oob_job_requires_explicit_enable(monkeypatch, tmp_path):
    path = _profile_file(tmp_path)
    monkeypatch.setenv("ENABLE_SERVER_CREDENTIAL_PROFILES", "true")
    monkeypatch.setenv("SSH_CREDENTIAL_PROFILES_FILE", str(path))
    monkeypatch.setenv("ENABLE_HTTP_OOB_LIVE", "false")
    try:
        secure_live.create_job("ro", "10.5.6.7", "basic")
        assert False, "OOB jobs must be disabled by default"
    except PermissionError:
        pass


def test_oob_job_can_be_approved_without_exposing_secret(monkeypatch, tmp_path):
    path = _profile_file(tmp_path)
    db = tmp_path / "jobs.sqlite3"
    monkeypatch.setenv("ENABLE_SERVER_CREDENTIAL_PROFILES", "true")
    monkeypatch.setenv("SSH_CREDENTIAL_PROFILES_FILE", str(path))
    monkeypatch.setenv("ENABLE_HTTP_OOB_LIVE", "true")
    monkeypatch.setenv("SECURE_LIVE_JOB_DB", str(db))

    job = secure_live.create_job("ro", "10.5.6.7", "basic")
    assert job["status"] == "pending"
    assert "super-secret-test-value" not in json.dumps(job)

    monkeypatch.setattr(secure_live, "execute_profile", lambda profile_id, target, check: {
        "host": target,
        "credential_profile": profile_id,
        "check": check,
        "mode": "read_only_server_profile",
        "credentials_returned": False,
        "results": [],
    })
    final = secure_live.approve_and_execute(job["job_id"])
    assert final["status"] == "completed"
    assert final["result"]["credentials_returned"] is False
    assert "super-secret-test-value" not in json.dumps(final)
