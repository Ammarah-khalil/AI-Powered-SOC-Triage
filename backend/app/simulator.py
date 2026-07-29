"""
Live feed simulator.

Stands in for: Wazuh agents -> Kafka -> Correlation Engine. This background
task plays out attack scenarios stage-by-stage, appending alerts to a fresh
incident over a few seconds and broadcasting each change over the WebSocket,
so the dashboard shows an incident escalating in real time instead of
appearing pre-formed.

Swap-out plan for the real pipeline: replace `run_simulator()` with a Kafka
consumer coroutine that reads correlated incidents off a topic and calls the
same `store.upsert()` + `manager.broadcast()` pair. Nothing else changes.
"""
from __future__ import annotations

import asyncio
import random
from datetime import datetime, timezone

from . import store
from .models import Incident, IncidentStatus
from .realtime import manager
from .risk_scoring import score_incident
from .scenarios import build_alert, pick_host_and_user, pick_scenario

# Gap between new incidents spawning. Kept short for a lively demo;
# tune up if it feels too noisy.
MIN_GAP_SECONDS = 12
MAX_GAP_SECONDS = 25


async def _run_scenario(incident_id: str, host: str, user: str, title: str, stages) -> None:
    incident = Incident(
        id=incident_id,
        title=title,
        status=IncidentStatus.new,
        severity="low",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        affected_hosts=[host],
        affected_users=[user],
        alerts=[],
        mitre_techniques=[],
        threat_intel=[],
        risk_score=score_incident([], [], [], [host]),
    )
    store.upsert(incident)
    await manager.broadcast("incident_created", incident)

    for i, stage in enumerate(stages):
        await asyncio.sleep(stage.delay_seconds)

        current = store.get(incident_id)
        if current is None:
            return  # incident vanished somehow; bail quietly

        new_alert = build_alert(f"{incident_id}-a{i}", datetime.now(timezone.utc), stage.alert, host, user)
        current.alerts.append(new_alert)

        if stage.mitre:
            current.mitre_techniques.append(stage.mitre)

        if stage.intel:
            hit = stage.intel.model_copy(update={"indicator": random.choice(
                ["185.220.101.47", "91.240.118.33", "45.155.204.9", "194.26.29.150"]
            )})
            current.threat_intel.append(hit)

        current.risk_score = score_incident(
            current.alerts, current.mitre_techniques, current.threat_intel, current.affected_hosts
        )
        current.severity = current.risk_score.level
        current.status = IncidentStatus.investigating
        current.updated_at = datetime.now(timezone.utc)

        store.upsert(current)
        await manager.broadcast("incident_updated", current)


async def run_simulator() -> None:
    """Entry point run as a background task from FastAPI's startup event."""
    while True:
        await asyncio.sleep(random.uniform(MIN_GAP_SECONDS, MAX_GAP_SECONDS))

        scenario = pick_scenario()
        host, user = pick_host_and_user()
        incident_id = store.next_incident_id()

        # Don't await this: let scenarios overlap so multiple incidents can
        # be escalating at once, like a real shift.
        asyncio.create_task(_run_scenario(incident_id, host, user, scenario.title, scenario.stages))
