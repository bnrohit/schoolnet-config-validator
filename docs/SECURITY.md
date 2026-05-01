# Security Guidance

SchoolNet Config Validator is designed for safe offline review of sanitized network configs.

## Do not upload or commit

- Passwords or enable secrets
- SNMP communities
- Private keys
- TACACS/RADIUS shared secrets
- Student data
- Full internal diagrams
- Sensitive production backups

## Sanitization

Use the **Sanitize** button before validation. It redacts common secret patterns, but it is not a replacement for human review.

## Live SSH

Live SSH troubleshooting is disabled by default.

```bash
ENABLE_LIVE_SSH=false
```

Only set it to true on a trusted internal network. Never expose the app to the public internet when live SSH is enabled.

## Recommended production deployment

- Run behind VPN or internal reverse proxy.
- Add HTTPS at the reverse proxy layer.
- Restrict access to IT/admin networks.
- Keep Docker images updated.
- Do not persist uploaded configs unless you intentionally add storage later.
