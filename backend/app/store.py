"""
Shared incident store.

Standing in for PostgreSQL. Pulled into its own module (rather than living in
main.py) so both the HTTP API and the background live-feed simulator can read
and write the same incidents without importing each other.
"""
from __future__ import annotations

from .models import Incident

_incidents: dict[str, Incident] = {}


def seed(incidents: list[Incident]) -> None:
    for inc in incidents:
        _incidents[inc.id] = inc


def get_all() -> list[Incident]:
    return list(_incidents.values())


def get(incident_id: str) -> Incident | None:
    return _incidents.get(incident_id)


def upsert(incident: Incident) -> None:
    _incidents[incident.id] = incident


def next_incident_id() -> str:
    """Generate the next INC-### id, continuing from whatever's already seeded."""
    existing_nums = [
        int(inc_id.split("-")[1])
        for inc_id in _incidents.keys()
        if inc_id.startswith("INC-") and inc_id.split("-")[1].isdigit()
    ]
    next_num = (max(existing_nums) + 1) if existing_nums else 1
    return f"INC-{next_num}"
