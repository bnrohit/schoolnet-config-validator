# SchoolNet Config Validator v1.2.0

This release improves the project from a working MVP into a more usable open-source tool for school IT teams.

## Highlights

- Safer first-time demo workflow
- Config sanitization endpoint and UI button
- Markdown report export for leadership/change review
- Rule catalog API
- Improved Docker backend build context
- Improved README, install docs, usage guide, API docs, security docs, issue templates, PR template, and changelog
- Better risk scoring and plain-English leadership summary

## Install

```bash
git clone https://github.com/bnrohit/edunetguard-repo.git
cd edunetguard-repo
cp .env.example .env
docker compose up --build -d
```

Open `http://localhost:3000`.

## Recommended tag

`v1.2.0`
