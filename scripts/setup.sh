#!/usr/bin/env bash
set -euo pipefail
cp -n .env.example .env || true
docker compose up --build -d
echo "SchoolNet is starting. Web: http://localhost:3000 API: http://localhost:8000/docs"
