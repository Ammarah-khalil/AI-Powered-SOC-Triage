from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from . import ai_investigation, store
from .mock_data import get_mock_incidents
from .models import IncidentSummary
from .realtime import manager
from .simulator import run_simulator

app = FastAPI(title="SOC Alert Correlation & Triage Platform", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before deploying anywhere real
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup() -> None:
    store.seed(get_mock_incidents())
    asyncio.create_task(run_simulator())


@app.get("/api/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/api/incidents", response_model=list[IncidentSummary])
def list_incidents():
    summaries = []
    for inc in store.get_all():
        top_technique = inc.mitre_techniques[0].technique_id if inc.mitre_techniques else None
        summaries.append(
            IncidentSummary(
                id=inc.id,
                title=inc.title,
                status=inc.status,
                severity=inc.severity,
                risk_score=inc.risk_score.total,
                alert_count=len(inc.alerts),
                created_at=inc.created_at,
                top_technique=top_technique,
            )
        )
    return sorted(summaries, key=lambda s: s.risk_score, reverse=True)


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    inc = store.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return inc


@app.post("/api/incidents/{incident_id}/investigate")
async def run_investigation(incident_id: str):
    """Trigger (or re-trigger) the AI Investigation Engine for an incident."""
    inc = store.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    try:
        result = ai_investigation.investigate(
            alerts=inc.alerts,
            mitre_techniques=inc.mitre_techniques,
            threat_intel=inc.threat_intel,
            affected_hosts=inc.affected_hosts,
            affected_users=inc.affected_users,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=f"AI Investigation Engine error: {exc}") from exc

    inc.ai_investigation = result
    store.upsert(inc)
    await manager.broadcast("incident_updated", inc)
    return inc


@app.get("/api/analytics")
def analytics():
    incidents = store.get_all()
    technique_counter: Counter[str] = Counter()
    host_counter: Counter[str] = Counter()
    for inc in incidents:
        for t in inc.mitre_techniques:
            technique_counter[f"{t.technique_id} {t.name}"] += 1
        for h in inc.affected_hosts:
            host_counter[h] += 1

    return {
        "total_incidents": len(incidents),
        "active_incidents": sum(1 for i in incidents if i.status != "closed"),
        "high_risk_incidents": sum(1 for i in incidents if i.severity in ("high", "critical")),
        "top_techniques": technique_counter.most_common(5),
        "most_targeted_hosts": host_counter.most_common(5),
        # Placeholder MTTD/MTTR until real timestamped detection/response events exist.
        "mttd_minutes": 4.5,
        "mttr_minutes": 27.0,
    }


@app.websocket("/ws/incidents")
async def incidents_ws(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect messages from the client; this just keeps the
            # connection open and lets us detect disconnects.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
