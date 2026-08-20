"""Administrative CLI for SchoolNet Secure Live Bridge.

Run this from the SchoolNet backend container, normally reached through an
administrator's SSH session to the host. It never prints stored credentials.
"""
from __future__ import annotations

import argparse
import json
import sys

from secure_live import approve_and_execute, list_pending_jobs, list_public_profiles, secure_live_policy


def main() -> int:
    parser = argparse.ArgumentParser(description="SchoolNet Secure Live Bridge administration")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("profiles", help="List safe credential profile metadata")
    sub.add_parser("policy", help="Show secure-live runtime policy")
    pending = sub.add_parser("pending", help="List pending approval jobs")
    pending.add_argument("--limit", type=int, default=20)
    approve = sub.add_parser("approve", help="Approve and execute one pending read-only job")
    approve.add_argument("job_id")

    args = parser.parse_args()
    try:
        if args.command == "profiles":
            payload = {"profiles": list_public_profiles()}
        elif args.command == "policy":
            payload = secure_live_policy()
        elif args.command == "pending":
            payload = {"jobs": list_pending_jobs(args.limit)}
        else:
            payload = approve_and_execute(args.job_id)
        print(json.dumps(payload, indent=2))
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
