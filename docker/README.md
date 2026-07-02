# Docker Guide

Docker Compose is the recommended way to run BilvantisLLM-API for personal use. The container serves the Express API and the built React dashboard from one process on port 3001, with SQLite persisted in a named volume.

## Prerequisites

- Docker
- Docker Compose
- OpenSSL for generating `ENCRYPTION_KEY`

## Quick Start

Create a `.env` file with a 32-byte encryption key:

```bash
ENCRYPTION_KEY="$(openssl rand -hex 32)"
printf "ENCRYPTION_KEY=%s\nPORT=3001\n" "$ENCRYPTION_KEY" > .env
```

Start the app:

```bash
docker compose up -d
```

Open http://localhost:3001, add provider keys on the **Keys** page, then use the generated `bilvantisllmapi-...` key with any OpenAI-compatible client.

## Example API Call

```bash
curl http://localhost:3001/v1/chat/completions \
  -H "Authorization: Bearer bilvantisllmapi-your-unified-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "auto",
    "messages": [{"role": "user", "content": "Say hello from BilvantisLLM-API."}]
  }'
```

## Operations

Check status:

```bash
docker compose ps
```

Tail logs:

```bash
docker compose logs -f bilvantisllmapi
```

Stop the app:

```bash
docker compose down
```

Update to the latest GHCR image after a release:

```bash
docker compose pull
docker compose up -d
```

Rebuild locally from source:

```bash
docker compose up -d --build
```

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `ENCRYPTION_KEY` | Yes | None | 64-character hex key used to encrypt provider API keys at rest. Generate it once and keep it stable. |
| `PORT` | No | `3001` | Host port exposed by Docker Compose. The container listens on port 3001. |
| `BILVANTIS_DB_PATH` | No | `/app/server/data/bilvantisllmapi.db` | SQLite file path. Set this when your host only persists one mounted directory. |
| `BILVANTIS_DB_BACKUP_PATH` | No | None | Local encrypted backup file. Restored on startup if the DB file is missing, then refreshed while the app runs. |
| `BILVANTIS_DB_BACKUP_URL` | No | None | HTTP(S) encrypted backup target. Startup uses `GET`; periodic backups use `PUT`. |
| `BILVANTIS_DB_BACKUP_TOKEN` | No | None | Optional bearer token for `BILVANTIS_DB_BACKUP_URL`. |
| `BILVANTIS_DB_BACKUP_KEY` | No | `ENCRYPTION_KEY` | 64-character hex key for backup encryption. Use a separate stable key if possible. |
| `BILVANTIS_CONFIG_PATH` | No | None | JSON config file applied idempotently after migrations on every boot. |
| `BILVANTIS_CONFIG_JSON` | No | None | Inline JSON config. Takes precedence over `BILVANTIS_CONFIG_PATH`. |

The `bilvantisllmapi-data` volume stores SQLite data at `/app/server/data`. Keep the same volume and `ENCRYPTION_KEY` when upgrading, otherwise existing encrypted provider keys cannot be decrypted.

Example `bilvantisllmapi.config.json`:

```json
{
  "keys": [
    { "platform": "groq", "key": "gsk_...", "label": "main" }
  ],
  "customProviders": [
    {
      "baseUrl": "http://host.docker.internal:11434/v1",
      "label": "Ollama",
      "models": [
        { "model": "llama3.1:8b", "displayName": "Local Llama", "supportsTools": true }
      ]
    }
  ],
  "routing": { "strategy": "balanced" }
}
```

## Published Image

Images are published to GitHub Container Registry:

```bash
docker pull ghcr.io/ai-internal/bilvantis-llm-api:latest
```

The Docker workflow builds pull requests without pushing. After this repository receives the workflow on `main`, pushes to `main` and version tags publish images to GHCR automatically.
