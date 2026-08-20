"""Secure live-diagnostics bridge for deployments without HTTPS.

The preferred mode remains HTTPS. This module provides a safer fallback for
trusted internal deployments where HTTPS is not yet available:

* credentials are loaded only from a server-side profile file mounted read-only
* the browser sends only a profile id, target, and read-only check name
* HTTP execution requires an out-of-band approval performed from the SchoolNet
  host/container CLI (normally reached through SSH)
* profiles are deny-by-default and must explicitly allow target ranges and checks

This protects credential confidentiality and execution authorization from the
plain-HTTP browser channel. It does NOT make HTTP confidential or tamper-proof;
diagnostic results and UI traffic can still be observed/modified on an untrusted
network. HTTPS remains the production recommendation.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
import socket
import sqlite3
import uuid
from typing import Any, Dict, List

from troubleshoot.commands import TroubleshootCommands
from troubleshoot.ssh_client import SwitchSSHClient


PROFILE_FILE_DEFAULT = "/run/secrets/schoolnet_ssh_profiles.json"
JOB_DB_DEFAULT = "/data/secure_live.sqlite3"
ALLOWED_CHECK_NAMES = {
    "basic", "interfaces", "vlan", "stp", "mac", "arp", "routing",
    "errors", "neighbors", "poe", "security", "all",
}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def profile_file_path() -> str:
    return os.getenv("SSH_CREDENTIAL_PROFILES_FILE", PROFILE_FILE_DEFAULT).strip() or PROFILE_FILE_DEFAULT


def job_db_path() -> str:
    return os.getenv("SECURE_LIVE_JOB_DB", JOB_DB_DEFAULT).strip() or JOB_DB_DEFAULT


def profiles_enabled() -> bool:
    return _env_bool("ENABLE_SERVER_CREDENTIAL_PROFILES", False)


def http_oob_enabled() -> bool:
    return _env_bool("ENABLE_HTTP_OOB_LIVE", False)


def _load_raw_profiles() -> Dict[str, Any]:
    if not profiles_enabled():
        return {}
    path = profile_file_path()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise ValueError(f"Credential profile file is not valid JSON: {exc}") from exc

    profiles = payload.get("profiles", payload) if isinstance(payload, dict) else {}
    if not isinstance(profiles, dict):
        raise ValueError("Credential profile file must contain an object named 'profiles'.")
    return profiles


def _safe_profile(profile_id: str, profile: Dict[str, Any]) -> Dict[str, Any]:
    auth_method = "ssh_key" if profile.get("key_file") else "password"
    return {
        "id": profile_id,
        "label": profile.get("label") or profile_id,
        "device_type": profile.get("device_type") or "cisco_ios",
        "port": int(profile.get("port") or 22),
        "allowed_targets": list(profile.get("allowed_targets") or []),
        "allowed_checks": list(profile.get("allowed_checks") or []),
        "auth_method": auth_method,
        "strict_host_key": bool(profile.get("strict_host_key", False)),
        "requires_oob_on_http": True,
    }


def list_public_profiles() -> List[Dict[str, Any]]:
    profiles = _load_raw_profiles()
    return [_safe_profile(profile_id, profile) for profile_id, profile in sorted(profiles.items())]


def _resolve_target_addresses(target: str) -> List[str]:
    try:
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        pass
    addresses: List[str] = []
    try:
        for item in socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP):
            address = item[4][0]
            try:
                normalized = str(ipaddress.ip_address(address))
            except ValueError:
                continue
            if normalized not in addresses:
                addresses.append(normalized)
    except socket.gaierror:
        return []
    return addresses[:16]


def _entry_allows_target(entry: str, target: str, addresses: List[str]) -> bool:
    entry = (entry or "").strip()
    if not entry:
        return False
    if entry.lower() == target.lower():
        return True
    try:
        network = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    if not addresses:
        return False
    return all(ipaddress.ip_address(address) in network for address in addresses)


def _validate_profile_target(profile: Dict[str, Any], target: str) -> None:
    allowed_targets = profile.get("allowed_targets") or []
    if not allowed_targets:
        raise PermissionError("Credential profile has no allowed_targets; access is deny-by-default.")
    addresses = _resolve_target_addresses(target)
    if not any(_entry_allows_target(str(entry), target, addresses) for entry in allowed_targets):
        raise PermissionError("Target is not allowed by this server-side credential profile.")


def _validate_profile_check(profile: Dict[str, Any], check: str) -> None:
    if check not in ALLOWED_CHECK_NAMES:
        raise PermissionError("Unsupported read-only diagnostic category.")
    allowed = set(profile.get("allowed_checks") or [])
    if check not in allowed:
        raise PermissionError("Diagnostic category is not allowed by this credential profile.")


def get_profile(profile_id: str, target: str, check: str) -> Dict[str, Any]:
    profiles = _load_raw_profiles()
    profile = profiles.get(profile_id)
    if not isinstance(profile, dict):
        raise KeyError("Unknown credential profile.")
    _validate_profile_target(profile, target)
    _validate_profile_check(profile, check)
    username = str(profile.get("username") or "").strip()
    password = str(profile.get("password") or "")
    key_file = str(profile.get("key_file") or "").strip()
    if not username:
        raise ValueError("Credential profile is missing username.")
    if not password and not key_file:
        raise ValueError("Credential profile must define either password or key_file.")
    return profile


def execute_profile(profile_id: str, target: str, check: str) -> Dict[str, Any]:
    if not profiles_enabled():
        raise PermissionError("Server-side credential profiles are disabled.")
    if not _env_bool("ENABLE_LIVE_SSH", False):
        raise PermissionError("ENABLE_LIVE_SSH=false")

    profile = get_profile(profile_id, target, check)
    client = SwitchSSHClient(
        host=target,
        username=str(profile.get("username") or ""),
        password=str(profile.get("password") or ""),
        device_type=str(profile.get("device_type") or "cisco_ios"),
        port=int(profile.get("port") or 22),
        secret=str(profile.get("secret") or ""),
        key_file=str(profile.get("key_file") or ""),
        strict_host_key=bool(profile.get("strict_host_key", False)),
        known_hosts_file=str(profile.get("known_hosts_file") or ""),
    )
    with client:
        results = TroubleshootCommands.run_all(client) if check == "all" else [TroubleshootCommands.run_check(client, check)]
    return {
        "host": target,
        "device_type": str(profile.get("device_type") or "cisco_ios"),
        "check": check,
        "mode": "read_only_server_profile",
        "credential_profile": profile_id,
        "credentials_returned": False,
        "results": results,
    }


def _connect() -> sqlite3.Connection:
    path = job_db_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS secure_live_jobs (
            id TEXT PRIMARY KEY,
            profile_id TEXT NOT NULL,
            target TEXT NOT NULL,
            check_name TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            completed_at TEXT,
            result_json TEXT,
            error TEXT
        )
        """
    )
    conn.commit()
    return conn


def create_job(profile_id: str, target: str, check: str) -> Dict[str, Any]:
    if not http_oob_enabled():
        raise PermissionError("HTTP out-of-band live approval is disabled.")
    # Validate before creating a pending job. Secrets are not returned.
    get_profile(profile_id, target, check)
    ttl = max(2, min(30, int(os.getenv("SECURE_LIVE_JOB_TTL_MINUTES", "10"))))
    created = _now()
    expires = created + timedelta(minutes=ttl)
    job_id = str(uuid.uuid4())
    with _connect() as conn:
        conn.execute(
            "INSERT INTO secure_live_jobs (id, profile_id, target, check_name, status, created_at, expires_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)",
            (job_id, profile_id, target, check, _iso(created), _iso(expires)),
        )
        conn.commit()
    return {
        "job_id": job_id,
        "status": "pending",
        "profile_id": profile_id,
        "target": target,
        "check": check,
        "created_at": _iso(created),
        "expires_at": _iso(expires),
        "approval_required": True,
        "approval_command": f"docker compose exec backend python secure_live_cli.py approve {job_id}",
        "note": "Approve from the SchoolNet host over a trusted administrative channel such as SSH. No device credential is sent through the browser.",
    }


def _row_to_public(row: sqlite3.Row) -> Dict[str, Any]:
    result = None
    if row["result_json"]:
        try:
            result = json.loads(row["result_json"])
        except json.JSONDecodeError:
            result = {"error": "stored result could not be decoded"}
    return {
        "job_id": row["id"],
        "profile_id": row["profile_id"],
        "target": row["target"],
        "check": row["check_name"],
        "status": row["status"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "completed_at": row["completed_at"],
        "result": result,
        "error": row["error"],
        "credentials_returned": False,
    }


def get_job(job_id: str) -> Dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM secure_live_jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            return None
        if row["status"] == "pending" and datetime.fromisoformat(row["expires_at"]) < _now():
            conn.execute("UPDATE secure_live_jobs SET status='expired', error='approval window expired' WHERE id=?", (job_id,))
            conn.commit()
            row = conn.execute("SELECT * FROM secure_live_jobs WHERE id = ?", (job_id,)).fetchone()
        return _row_to_public(row)


def list_pending_jobs(limit: int = 20) -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM secure_live_jobs WHERE status='pending' ORDER BY created_at DESC LIMIT ?",
            (max(1, min(100, int(limit))),),
        ).fetchall()
    return [_row_to_public(row) for row in rows]


def approve_and_execute(job_id: str) -> Dict[str, Any]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM secure_live_jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            raise KeyError("Secure live job not found.")
        if row["status"] != "pending":
            raise ValueError(f"Job is not pending (status={row['status']}).")
        if datetime.fromisoformat(row["expires_at"]) < _now():
            conn.execute("UPDATE secure_live_jobs SET status='expired', error='approval window expired' WHERE id=?", (job_id,))
            conn.commit()
            raise ValueError("Secure live job approval window expired.")
        conn.execute("UPDATE secure_live_jobs SET status='running' WHERE id=?", (job_id,))
        conn.commit()

    try:
        result = execute_profile(row["profile_id"], row["target"], row["check_name"])
        completed = _iso(_now())
        with _connect() as conn:
            conn.execute(
                "UPDATE secure_live_jobs SET status='completed', completed_at=?, result_json=?, error=NULL WHERE id=?",
                (completed, json.dumps(result), job_id),
            )
            conn.commit()
    except Exception as exc:
        completed = _iso(_now())
        with _connect() as conn:
            conn.execute(
                "UPDATE secure_live_jobs SET status='failed', completed_at=?, error=? WHERE id=?",
                (completed, str(exc)[:1500], job_id),
            )
            conn.commit()
    final = get_job(job_id)
    if final is None:
        raise RuntimeError("Secure live job disappeared after execution.")
    return final


def secure_live_policy() -> Dict[str, Any]:
    profiles = list_public_profiles() if profiles_enabled() else []
    return {
        "server_profiles_enabled": profiles_enabled(),
        "profile_file": profile_file_path() if profiles_enabled() else None,
        "profile_count": len(profiles),
        "http_oob_enabled": http_oob_enabled(),
        "job_ttl_minutes": max(2, min(30, int(os.getenv("SECURE_LIVE_JOB_TTL_MINUTES", "10")))),
        "direct_browser_credentials_over_http": False,
        "http_fallback_protects": ["device credential confidentiality", "execution authorization via out-of-band approval"],
        "http_fallback_does_not_protect": ["diagnostic result confidentiality", "browser-page integrity", "traffic metadata"],
    }
