# Contributing

Thank you for helping improve SchoolNet Config Validator.

## Good first contributions

- Add a sanitized sample config.
- Improve remediation wording.
- Add a validation rule.
- Add vendor parser support.
- Improve docs or UI text.

## Safety rules

Do not commit:

- Real passwords or secrets
- Private keys
- Full production configs with sensitive values
- Student data
- Internal diagrams that should not be public

## Local development

```bash
# Backend
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

## Add a new validation rule

1. Create a file under `backend/validators/checks/`.
2. Return `Finding` objects.
3. Register it in `backend/validators/engine.py`.
4. Add tests in `backend/tests/`.
5. Add docs in README or `docs/API.md` if needed.
