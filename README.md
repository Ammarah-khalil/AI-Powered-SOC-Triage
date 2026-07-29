# SOC Alert Correlation & Triage Platform — AI Investigation Engine + Dashboard

This is the first working slice of the full platform: the **AI Investigation
Engine** and the **analyst dashboard**. It's built so the mock data layer is
the *only* thing that needs to be replaced once you wire up the real
Wazuh → Kafka → Correlation Engine pipeline described in the design doc.

```
Wazuh/Kafka/Correlation Engine  →  Incident (Pydantic model)  →  AI Investigation Engine  →  Dashboard
        (not yet built)              (mocked for now)              (built, calls Claude)      (built)
```

## What's here

**Backend** — `backend/app/`
- `models.py` — the Incident/Alert/MitreTechnique/RiskScore shapes. This is the
  contract the real correlation engine needs to satisfy later.
- `mock_data.py` — three example incidents matching the correlation patterns
  from the design doc (brute force → PowerShell → C2, phishing macro →
  living-off-the-land, credential dumping on a DC).
- `risk_scoring.py` — the weighted risk scoring engine (alert volume, MITRE
  tactic severity, threat intel confidence, asset criticality).
- `ai_investigation.py` — calls the Claude API with the incident's alerts,
  MITRE mapping, and threat intel, and gets back a structured summary,
  prioritized response actions, and an ordered attack chain.
- `main.py` — FastAPI routes: list incidents, get incident detail, trigger an
  investigation, and analytics.

**Frontend** — `frontend/src/`
- `components/IncidentTable.tsx` — the incident overview list, sorted by risk.
- `components/IncidentDetail.tsx` — incident header, AI investigation panel
  (with a "Run investigation" button), risk breakdown, threat intel, and the
  raw correlated-alert timeline.
- `components/KillChainTrace.tsx` — the signature visual: the MITRE technique
  chain rendered as a glowing vertical trace, because the whole point of
  correlation is showing one attack story instead of a pile of alerts.
- `components/AnalyticsPanel.tsx` — MTTD/MTTR, most common techniques,
  most-targeted hosts.

## Live feed (simulated real-time)

The backend now runs a background task (`app/simulator.py`) that spawns a new
incident every ~12-25 seconds and plays out a realistic attack scenario
stage-by-stage over a WebSocket (`/ws/incidents`) -- watch an incident's alert
count and risk score climb in real time (e.g. `low` → `medium` → `critical`)
instead of appearing pre-formed. The dashboard shows a `LIVE` indicator
(bottom of the nav rail) when connected, with auto-reconnect if the backend
restarts.

This is a stand-in for the real pipeline. To replace it with actual Wazuh/Kafka
data: write a consumer coroutine that reads correlated incidents off your Kafka
topic and calls `store.upsert(incident)` + `await manager.broadcast(event_type,
incident)` -- the exact same two calls `simulator.py` makes. Nothing in the
API routes, the frontend, or the WebSocket wiring needs to change.

## Running it

### Backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # required to run investigations
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The dev server proxies `/api/*` to
`http://localhost:8000` (see `vite.config.ts`).

> Note: the incident list and detail views work without an API key — only
> clicking **Run investigation** calls Claude. If the key isn't set, you'll
> get a clear 400 error in the UI instead of a crash.

## Wiring in the real pipeline later

Everything downstream of `mock_data.get_mock_incidents()` only depends on the
`Incident` model in `models.py`. To connect the real architecture from the
design doc:

1. Stand up Wazuh + Kafka as planned, with a consumer that runs your
   correlation rules (failed logins → success → PowerShell, etc.).
2. Have that consumer write out objects matching `Incident`/`Alert` — swap
   `PostgreSQL` in as the store instead of the in-memory dict in `main.py`.
3. Add your Threat Intel enrichment (VirusTotal/AbuseIPDB/GreyNoise/OTX/MISP)
   as a step that populates `ThreatIntelHit` before an incident is persisted.
4. Nothing in `ai_investigation.py`, `risk_scoring.py`, or the frontend needs
   to change — they only know about the `Incident` shape.

## Known simplifications (worth mentioning if this comes up in an interview)

- Incidents are stored in-memory (`main.py`), not PostgreSQL/Elasticsearch yet.
- MTTD/MTTR on the analytics endpoint are placeholders — real values need
  timestamped "detected at" / "contained at" events, which don't exist until
  the correlation engine is real.
- Risk scoring weights are illustrative constants, not tuned against
  historical incident outcomes.
