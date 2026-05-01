#!/usr/bin/env bash
set -euo pipefail
git pull --ff-only
docker compose up --build -d
echo "SchoolNet updated."
