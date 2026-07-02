#!/usr/bin/env bash
# BilvantisLLM-API installer — clones the repo and starts it with Docker Compose.
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/AI-Internal/bilvantis-llm-api.git}"
TARGET_DIR="${TARGET_DIR:-bilvantisllmapi}"

command -v git >/dev/null 2>&1 || { echo "git is required"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker is required"; exit 1; }

if [ ! -d "$TARGET_DIR/.git" ]; then
  git clone "$REPO_URL" "$TARGET_DIR"
fi
cd "$TARGET_DIR"

if [ ! -f .env ]; then
  ENCRYPTION_KEY="$(openssl rand -hex 32)"
  printf "ENCRYPTION_KEY=%s\nPORT=3001\n" "$ENCRYPTION_KEY" > .env
  echo "Wrote .env with a fresh ENCRYPTION_KEY."
fi

docker compose up -d
echo "BilvantisLLM-API is starting. Open the dashboard at http://localhost:3001"
