# Secure Live Bridge — live SSH when HTTPS is not available

HTTPS remains the preferred way to use live device credentials. SchoolNet v1.10 adds a safer fallback for trusted internal deployments that do not yet have a certificate or reverse proxy.

The fallback is designed around one rule:

> **Device credentials never travel through the plain-HTTP browser session.**

Instead, credentials live only on the SchoolNet server in an operator-managed file mounted read-only into the backend. The browser may create a pending read-only diagnostic job, but the job cannot execute until an administrator approves it from the SchoolNet host/container CLI, normally after reaching the host through SSH.

## What this protects

- device passwords/private keys are not typed into or transmitted by the HTTP browser session
- the API never returns stored credentials
- each profile has an explicit target allowlist
- each profile has an explicit diagnostic-category allowlist
- pending jobs expire after a short window
- HTTP jobs require out-of-band approval before SSH execution
- the normal read-only command blocking remains in force
- SSH keys and strict host-key checking can be used instead of passwords

## What plain HTTP still cannot protect

This fallback is **not equivalent to HTTPS**. Plain HTTP still does not provide:

- confidentiality of diagnostic results
- integrity of the page or API responses against an on-path attacker
- privacy of hostnames/IPs and other traffic metadata

Use the fallback only on a trusted management network/VPN and migrate to HTTPS when practical.

## Recommended modes

| Mode | Credentials in browser | Execution approval | Recommendation |
|---|---:|---:|---|
| HTTPS + direct credentials | Yes, protected by TLS | Browser request | Supported; use least privilege |
| HTTPS + server profile | No | Browser request | Stronger operational model |
| HTTP + server profile + OOB approval | No | Terminal/SSH approval | Safe fallback for trusted internal networks |
| HTTP + browser password | **Blocked** | N/A | Do not use |

## 1. Create a local secret directory

On the SchoolNet host:

```bash
cd ~/schoolnet-config-validator
mkdir -p secrets
chmod 700 secrets
```

`secrets/` is ignored by Git and must never be committed.

## 2. Create a credential profile file

Create:

```text
secrets/ssh_profiles.json
```

Example using a password-backed read-only account:

```json
{
  "profiles": {
    "campus-readonly": {
      "label": "Campus network read-only",
      "username": "schoolnet-ro",
      "password": "REPLACE_ON_SERVER_ONLY",
      "device_type": "cisco_ios",
      "port": 22,
      "allowed_targets": [
        "10.10.0.0/16",
        "10.20.0.0/16",
        "core1.example.internal"
      ],
      "allowed_checks": [
        "basic",
        "interfaces",
        "errors",
        "neighbors",
        "routing",
        "vlan",
        "stp",
        "security",
        "all"
      ]
    }
  }
}
```

Lock down the file:

```bash
chmod 600 secrets/ssh_profiles.json
```

### Prefer SSH keys where possible

A profile can reference a private key mounted into the backend instead of storing a password:

```json
{
  "profiles": {
    "core-key-readonly": {
      "label": "Core switches — key auth",
      "username": "schoolnet-ro",
      "key_file": "/run/secrets/schoolnet_ro_key",
      "device_type": "cisco_ios",
      "port": 22,
      "strict_host_key": true,
      "known_hosts_file": "/run/secrets/schoolnet_known_hosts",
      "allowed_targets": ["10.250.0.0/16"],
      "allowed_checks": ["basic", "interfaces", "errors", "neighbors", "routing", "all"]
    }
  }
}
```

Use a dedicated read-only network account and restrict the key/account on the device side wherever the platform supports command authorization.

## 3. Mount the secret file into the backend

Create a local override file such as `docker-compose.secure-live.yml`:

```yaml
services:
  backend:
    volumes:
      - ./secrets/ssh_profiles.json:/run/secrets/schoolnet_ssh_profiles.json:ro
      # Optional key/known_hosts mounts:
      # - ./secrets/schoolnet_ro_key:/run/secrets/schoolnet_ro_key:ro
      # - ./secrets/known_hosts:/run/secrets/schoolnet_known_hosts:ro
```

Then enable the bridge in `.env`:

```env
ENABLE_LIVE_SSH=true
REQUIRE_HTTPS_FOR_LIVE_CREDENTIALS=true
ALLOW_INSECURE_LIVE_CREDENTIALS=false
ENABLE_SERVER_CREDENTIAL_PROFILES=true
ENABLE_HTTP_OOB_LIVE=true
SSH_CREDENTIAL_PROFILES_FILE=/run/secrets/schoolnet_ssh_profiles.json
SECURE_LIVE_JOB_TTL_MINUTES=10
```

Start with the override:

```bash
docker compose -f docker-compose.yml -f docker-compose.secure-live.yml up -d --build
```

## 4. Verify profiles without exposing secrets

```bash
docker compose -f docker-compose.yml -f docker-compose.secure-live.yml \
  exec backend python secure_live_cli.py profiles
```

The output contains only safe profile metadata. Passwords, enable secrets, and private-key contents are never printed.

## 5. HTTP out-of-band approval workflow

From the browser, select a server-side profile, target, and read-only diagnostic category. SchoolNet creates a pending job and returns a job id.

The UI/API will show an approval command similar to:

```bash
docker compose exec backend python secure_live_cli.py approve 7f7b0fd1-....
```

Run that command from the SchoolNet host after reaching it through a trusted administrative channel such as SSH.

The CLI:

1. confirms the job still exists and has not expired
2. re-validates the profile target allowlist
3. re-validates the permitted diagnostic category
4. performs only the predefined read-only diagnostic commands
5. stores the result for the browser to retrieve
6. never prints or returns the stored credential

List waiting jobs:

```bash
docker compose exec backend python secure_live_cli.py pending
```

## API

Safe profile metadata:

```text
GET /api/v1/secure-live/profiles
```

Create a pending OOB job:

```text
POST /api/v1/secure-live/jobs
```

Poll the job:

```text
GET /api/v1/secure-live/jobs/{job_id}
```

Direct profile execution:

```text
POST /api/v1/secure-live/run
```

Direct profile execution requires HTTPS. Plain HTTP is limited to creating a pending OOB-approved job.

## Security notes

- Keep backend port `8000` restricted to the management network; normally use the frontend proxy rather than exposing the API broadly.
- Use dedicated least-privilege/read-only accounts.
- Prefer SSH keys over shared passwords.
- Use strict host-key checking and a managed `known_hosts` file where practical.
- Keep profile target ranges narrow. Do not use `0.0.0.0/0` or broad public ranges.
- Keep allowed diagnostic categories to the minimum needed.
- Do not store production credentials in Git, `.env`, screenshots, tickets, or browser local storage.
- The Secure Live Bridge does not remove the need for HTTPS; it provides a safer transition path for internal environments that cannot deploy TLS immediately.
