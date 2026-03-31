# Hanicar Security CTI Console

The project now exposes two separate interfaces:

- `http://HOST:8000`
  - The original scoring and recommendation UI served by FastAPI
- `http://HOST:5173`
  - The new React + Vite Hanicar Security CTI dashboard

The platform ingests raw Wazuh alerts, MISP events, and Cortex analyses, extracts IOCs, matches CVEs from an external database, scores the case, generates recommendations, stores everything in SQLite, and exposes a full dashboard with authentication.

## What it includes

- Hanicar Security dashboard UI with login, KPI cards, incident feed, filters, CVE panel, and case modal
- Seeded administrator account
  - Email: `admin@hanicar.tn`
  - Password: `bornasroot`
- Case persistence with raw payloads, normalized payloads, recommendations, email HTML, CVEs, IOCs, and PKIs
- External CVE enrichment through CIRCL CVE data
- Local Ollama-backed recommendation generation with automatic model pull in Docker Compose

## Main routes

- `GET /`
  - Original backend UI on port `8000`
- `POST /api/auth/login`
  - Session login for dashboard access
- `GET /api/dashboard/overview`
  - KPI cards and latest cases
- `GET /api/dashboard/cases`
  - Paginated case list with filters
- `GET /api/dashboard/cases/{id}`
  - Full case detail for modal view
- `GET /api/dashboard/cves`
  - Paginated CVE list
- `POST /api/dashboard/cases/ingest`
  - Authenticated dashboard ingestion
- `POST /api/score/raw`
  - Public raw scoring endpoint
- `POST /api/recommendation`
  - Public raw recommendation endpoint
- `POST /api/recommendation/email`
  - Public recommendation email HTML endpoint

## Dashboard login

- Email: `admin@hanicar.tn`
- Password: `bornasroot`

## Docker deployment

Run:

```bash
docker compose up
```

What happens automatically:

- Ollama starts
- The configured Ollama model is pulled
- The API starts
- The React Vite dashboard starts on port `5173`
- The SQLite database is created in the Docker volume
- The Hanicar admin account is seeded
- Recent CVEs are synchronized
- A starter demo case is inserted for the dashboard

## Default environment

The Compose file provides working defaults:

- `HANICAR_ADMIN_EMAIL=admin@hanicar.tn`
- `HANICAR_ADMIN_PASSWORD=bornasroot`
- `AI_PROVIDER=ollama`
- `OLLAMA_MODEL=llama3.1:8b`
- persistent volume for app data
- persistent volume for Ollama models

## Dashboard workflow

1. Open `http://YOUR_SERVER_IP:5173`
2. Log in with the seeded Hanicar admin account
3. Paste raw Wazuh, MISP, and Cortex JSON into the intake panel
4. Store the case
5. Review the incident list and open the case modal
6. Inspect accordions for:
   - recommendation
   - MISP event
   - Cortex analysis
   - Wazuh alert
   - IOCs
   - CVEs
   - normalized payload
   - email payload

## Legacy workflow

- Open `http://YOUR_SERVER_IP:8000` to use the original scoring UI
- This interface remains available separately from the React dashboard

## Notes

- This project uses prompt-specialized local agents with Ollama. It does not perform true model fine-tuning.
- CVE matching currently detects explicit CVE identifiers in ingested content and enriches them from the external CVE feed.
- The database is SQLite for simplicity and single-command deployment.
