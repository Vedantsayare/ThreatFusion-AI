# Troubleshooting

Issues below were encountered while building and running this project, or follow
directly from how the code behaves.

## Docker / infrastructure

**`ports are not available: ... 127.0.0.1:6379 (or 5432): bind: address already in use`**
Another Redis/PostgreSQL is already running on the host (common on macOS with Homebrew services). Don't stop it; remap the containers instead. In `.env`:

```dotenv
POSTGRES_HOST_PORT=5433
POSTGRES_PORT=5433        # the API connects to the remapped port
REDIS_HOST_PORT=6380
REDIS_PORT=6380
```

Then `docker compose up -d`. Check with `lsof -nP -iTCP:5432 -sTCP:LISTEN`.

**`Cannot connect to the Docker daemon`**
Start Docker Desktop (`open -a Docker` on macOS) and wait until `docker info` succeeds.

**`POSTGRES_PASSWORD must be set in .env` (compose aborts)**
Compose fails closed when a required secret is missing. Run `python scripts/bootstrap_env.py`.

**Neo4j shows `health: starting` for up to a minute**
Normal JVM startup. If the API starts first, it reports `neo4j: Unavailable at startup` and uses the per-alert resolution fallback. Restart the API after Neo4j is healthy to enable graph persistence. Neo4j is only connected at startup.

**Changed `NEO4J_PASSWORD` after the first `docker compose up`**
Neo4j keeps the password from the first initialization of the `neo4j_data` volume. Either restore the old password or reset the volume (destroys graph data): `docker compose down && docker volume rm threatfusion-ai_neo4j_data`.

## Python environment

**`pip install` extremely slow or `ReadTimeoutError` from files.pythonhosted.org**
Use longer timeouts and retries: `pip install --default-timeout=60 --retries 20 -e ".[dev]"`. If a large wheel keeps failing to resume, cancel and re-run; completed downloads are cached. Reusing an existing Python distribution that already has the heavy packages also works: `python3 -m venv --system-site-packages .venv`.

**`ValidationError: ... Field required` on startup**
`AppSettings` requires `SECRET_KEY` (≥32 chars), Wazuh/MISP URLs, and database passwords even when those integrations are disabled. Copy every variable from `.env.example`.

**`WAZUH_API_URL must use HTTPS`**
Intended: Wazuh credentials are never sent over plain HTTP.

## API

**API refuses to start: `ConnectionRefusedError` / `OSError` from asyncpg**
`PERSISTENCE_BACKEND=postgres` but PostgreSQL isn't reachable at `POSTGRES_HOST:POSTGRES_PORT`. This fails closed on purpose. Start the container, fix the port, or use `PERSISTENCE_BACKEND=sqlite` for a no-Docker run.

**Every request returns 401**
No valid keys in `API_KEYS` (keys containing `CHANGE_ME`, or shorter than 16 characters, are ignored), or the client is not sending `Authorization: Bearer <key>`. The startup log contains `no_api_keys_configured` in this case.

**403 `Separation of duties`**
The approver proposed the action. Another approver must decide it.

**409 on execute**
The request isn't `APPROVED`, it has expired (default 30 min, `APPROVAL_TIMEOUT_SECONDS`), it was already executed, or the stored action no longer matches the approved hash. Each of these is a deliberate guardrail.

**`/health` returns 503 with `audit_chain: down`**
The persisted audit chain failed verification at startup or later. Inspect with `GET /api/v1/audit/verify`. Do not "repair" the rows. Investigate who modified the database.

**Alerts are triaged but no incident appears**
Alerts triaged LOW that share no strong entity with an open incident intentionally stay as alerts.

## Dashboard

**"Cannot reach the ThreatFusion API"**
The Vite dev server proxies `/api` and `/health` to `127.0.0.1:8000`. Start the backend with `uvicorn api.app:app --port 8000`.

**Browser CORS errors when the dashboard is served from another origin**
Add the origin to `CORS_ORIGINS` (comma-separated). Wildcards are ignored on purpose.

**Signed out unexpectedly**
The key is stored in `sessionStorage` (per tab). Any 401 also signs you out, for example after keys were rotated in `.env` and the API restarted.

## Tests

**Live Neo4j test is skipped or not collected**
Live tests are marked `integration` and excluded by default. Run them with `pytest -m integration` while Neo4j is running and `.env` has `NEO4J_PASSWORD`.
