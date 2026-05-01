# Installation Guide

## Option 1 — Docker Compose production install

```bash
git clone https://github.com/bnrohit/edunetguard-repo.git
cd edunetguard-repo
cp .env.example .env
docker compose up --build -d
```

Open:

- Web UI: `http://SERVER-IP:3000`
- API docs: `http://SERVER-IP:8000/docs`

## Option 2 — Windows Docker Desktop

1. Install Docker Desktop.
2. Open PowerShell.
3. Run:

```powershell
git clone https://github.com/bnrohit/edunetguard-repo.git
cd edunetguard-repo
copy .env.example .env
docker compose up --build -d
```

## Option 3 — Development install

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

## Production guidance

- Put behind VPN or a reverse proxy with HTTPS.
- Use sanitized configs only.
- Keep live SSH disabled unless needed.
- Do not store switch passwords in the app.
- Use a dedicated VM, not a domain controller or core network device.
