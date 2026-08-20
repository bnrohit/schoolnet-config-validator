"""Opt-in diagnostic history for SchoolNet v1.9 using stdlib SQLite.

Only diagnostic result payloads are stored; request credentials are never passed
into this module. History is disabled unless ENABLE_DIAGNOSTIC_HISTORY=true.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional


DB_PATH = os.getenv("DIAGNOSTIC_HISTORY_DB", "/data/diagnostic_history.sqlite3")
MAX_RESULT_BYTES = 2_500_000


def _enabled() -> bool:
    return os.getenv("ENABLE_DIAGNOSTIC_HISTORY", "false").strip().lower() in {"1", "true", "yes", "on"}


def _retention() -> int:
    try:
        return max(10, min(1000, int(os.getenv("DIAGNOSTIC_HISTORY_RETENTION", "100"))))
    except ValueError:
        return 100


def _connect() -> sqlite3.Connection:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS diagnostic_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            target TEXT NOT NULL,
            label TEXT NOT NULL,
            kind TEXT NOT NULL,
            summary_json TEXT NOT NULL,
            payload_json TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_diag_target_time ON diagnostic_runs(target, created_at DESC)")
    conn.commit()
    return conn


def history_policy() -> Dict[str, Any]:
    return {
        "enabled": _enabled(),
        "retention_runs": _retention(),
        "database_path": DB_PATH if _enabled() else None,
        "stores_credentials": False,
    }


def _summary(payload: Dict[str, Any]) -> Dict[str, Any]:
    fault_domains = payload.get("deep_diagnostics", {}).get("fault_domains", [])
    open_ports = [item.get("port") for item in payload.get("services", {}).get("tcp", []) if item.get("open")]
    traces = payload.get("path_intelligence", {}).get("trace_mode_comparison", {}).get("sequences", {})
    app = payload.get("application_assurance", {})
    return {
        "overall_state": payload.get("overall_state"),
        "confidence": payload.get("confidence"),
        "primary_address": payload.get("primary_address"),
        "open_tcp_ports": open_ports,
        "fault_domains": {item.get("domain"): item.get("status") for item in fault_domains},
        "application_status": app.get("application_status"),
        "tls_status": app.get("tls_status"),
        "security_findings": len(payload.get("security", {}).get("findings", [])),
        "top_hypothesis": (payload.get("hypotheses") or [{}])[0].get("title"),
        "trace_sequences": traces,
        "resolver": payload.get("resolver_context", {}).get("server"),
    }


def save_run(payload: Dict[str, Any], target: str, label: str = "", kind: str = "deep") -> Dict[str, Any]:
    if not _enabled():
        return {"saved": False, "reason": "diagnostic history disabled"}
    label = (label or "").strip()[:120]
    summary = _summary(payload)
    raw = json.dumps(payload, separators=(",", ":"), default=str)
    if len(raw.encode("utf-8")) > MAX_RESULT_BYTES:
        return {"saved": False, "reason": "result exceeds history size limit"}

    now = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO diagnostic_runs(created_at,target,label,kind,summary_json,payload_json) VALUES(?,?,?,?,?,?)",
            (now, target[:253], label, kind[:32], json.dumps(summary, separators=(",", ":")), raw),
        )
        run_id = int(cur.lastrowid)
        keep = _retention()
        conn.execute(
            "DELETE FROM diagnostic_runs WHERE id NOT IN (SELECT id FROM diagnostic_runs ORDER BY id DESC LIMIT ?)",
            (keep,),
        )
        conn.commit()
    return {"saved": True, "id": run_id, "created_at": now, "label": label}


def list_runs(limit: int = 30, target: str = "") -> Dict[str, Any]:
    if not _enabled():
        return {"enabled": False, "runs": []}
    limit = max(1, min(100, int(limit or 30)))
    with _connect() as conn:
        if target:
            rows = conn.execute(
                "SELECT id,created_at,target,label,kind,summary_json FROM diagnostic_runs WHERE target=? ORDER BY id DESC LIMIT ?",
                (target, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id,created_at,target,label,kind,summary_json FROM diagnostic_runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
    runs = []
    for row in rows:
        runs.append({
            "id": row["id"], "created_at": row["created_at"], "target": row["target"],
            "label": row["label"], "kind": row["kind"], "summary": json.loads(row["summary_json"]),
        })
    return {"enabled": True, "runs": runs, "retention_runs": _retention()}


def get_run(run_id: int) -> Optional[Dict[str, Any]]:
    if not _enabled():
        return None
    with _connect() as conn:
        row = conn.execute("SELECT * FROM diagnostic_runs WHERE id=?", (int(run_id),)).fetchone()
    if not row:
        return None
    return {
        "id": row["id"], "created_at": row["created_at"], "target": row["target"],
        "label": row["label"], "kind": row["kind"],
        "summary": json.loads(row["summary_json"]), "payload": json.loads(row["payload_json"]),
    }


def _set_delta(before: List[Any], after: List[Any]) -> Dict[str, List[Any]]:
    a = set(before or [])
    b = set(after or [])
    return {"added": sorted(b - a), "removed": sorted(a - b), "unchanged": sorted(a & b)}


def compare_runs(before_id: int, after_id: int) -> Optional[Dict[str, Any]]:
    before = get_run(before_id)
    after = get_run(after_id)
    if not before or not after:
        return None
    b = before["summary"]
    a = after["summary"]
    domains = sorted(set((b.get("fault_domains") or {}).keys()) | set((a.get("fault_domains") or {}).keys()))
    domain_changes = [
        {"domain": domain, "before": (b.get("fault_domains") or {}).get(domain), "after": (a.get("fault_domains") or {}).get(domain)}
        for domain in domains
        if (b.get("fault_domains") or {}).get(domain) != (a.get("fault_domains") or {}).get(domain)
    ]
    return {
        "before": {"id": before["id"], "created_at": before["created_at"], "target": before["target"], "label": before["label"]},
        "after": {"id": after["id"], "created_at": after["created_at"], "target": after["target"], "label": after["label"]},
        "same_target": before["target"] == after["target"],
        "open_tcp_delta": _set_delta(b.get("open_tcp_ports", []), a.get("open_tcp_ports", [])),
        "fault_domain_changes": domain_changes,
        "application_status": {"before": b.get("application_status"), "after": a.get("application_status")},
        "tls_status": {"before": b.get("tls_status"), "after": a.get("tls_status")},
        "security_findings": {"before": b.get("security_findings", 0), "after": a.get("security_findings", 0)},
        "top_hypothesis": {"before": b.get("top_hypothesis"), "after": a.get("top_hypothesis")},
        "resolver": {"before": b.get("resolver"), "after": a.get("resolver")},
        "trace_sequences_changed": b.get("trace_sequences") != a.get("trace_sequences"),
        "before_trace_sequences": b.get("trace_sequences", {}),
        "after_trace_sequences": a.get("trace_sequences", {}),
    }
