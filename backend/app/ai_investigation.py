"""
AI Investigation Engine.

Takes a correlated incident (grouped alerts + threat intel + MITRE mapping)
and asks Claude to produce:
  - a human-readable incident summary
  - a prioritized list of suggested containment/response actions
  - an ordered MITRE technique chain (the attack story, not just a bag of IDs)
  - a confidence score for its own assessment

Design notes:
  - We ask for strict JSON back so the FastAPI layer can validate it against
    the AIInvestigation pydantic model and the frontend never has to parse
    free text.
  - This module knows nothing about Kafka/Wazuh -- it only consumes the
    Incident shape defined in models.py, so swapping the mock pipeline for
    a real one requires zero changes here.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import anthropic

from .models import AIInvestigation, Alert, MitreTechnique, ThreatIntelHit

MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst assistant.
You are given a correlated security incident: a set of alerts that a correlation
engine has already grouped together as one attack, along with threat intelligence
enrichment and MITRE ATT&CK technique mappings.

Your job is to produce an investigation brief for a human analyst who has not yet
looked at this incident. Be precise, avoid speculation beyond what the evidence
supports, and write like an experienced analyst -- not a marketing summary.

Respond with ONLY a JSON object (no markdown fences, no preamble) matching exactly
this schema:
{
  "summary": string,               // 2-5 sentences, plain prose, the incident narrative
  "suggested_actions": string[],   // 3-7 concrete, prioritized response actions
  "mitre_chain": string[],         // MITRE technique IDs in chronological/logical order
  "confidence": number             // 0-100, your confidence in this assessment
}"""


def _build_user_prompt(
    alerts: list[Alert],
    mitre_techniques: list[MitreTechnique],
    threat_intel: list[ThreatIntelHit],
    affected_hosts: list[str],
    affected_users: list[str],
) -> str:
    alert_lines = [
        f"- [{a.timestamp.isoformat()}] {a.event_type} on {a.host}"
        + (f" (user: {a.user})" if a.user else "")
        + (f" (process: {a.process})" if a.process else "")
        + (f" (src_ip: {a.src_ip})" if a.src_ip else "")
        + (f" (dst_ip: {a.dst_ip})" if a.dst_ip else "")
        for a in alerts
    ]
    mitre_lines = [f"- {t.technique_id} {t.name} (tactic: {t.tactic})" for t in mitre_techniques]
    intel_lines = [
        f"- {hit.indicator} ({hit.indicator_type}): {hit.verdict}, {hit.confidence}% confidence via {hit.source}"
        + (f", attributed to {hit.threat_actor}" if hit.threat_actor else "")
        for hit in threat_intel
    ]

    return f"""INCIDENT DATA

Affected hosts: {", ".join(affected_hosts) or "none listed"}
Affected users: {", ".join(affected_users) or "none listed"}

Correlated alerts (chronological):
{chr(10).join(alert_lines) if alert_lines else "none"}

MITRE ATT&CK techniques observed:
{chr(10).join(mitre_lines) if mitre_lines else "none"}

Threat intelligence enrichment:
{chr(10).join(intel_lines) if intel_lines else "none"}

Produce the JSON investigation brief now."""


def investigate(
    alerts: list[Alert],
    mitre_techniques: list[MitreTechnique],
    threat_intel: list[ThreatIntelHit],
    affected_hosts: list[str],
    affected_users: list[str],
) -> AIInvestigation:
    """Call Claude to generate the investigation brief for one incident."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Export it before starting the backend, "
            "e.g. `export ANTHROPIC_API_KEY=sk-ant-...`"
        )

    client = anthropic.Anthropic(api_key=api_key)

    user_prompt = _build_user_prompt(alerts, mitre_techniques, threat_intel, affected_hosts, affected_users)

    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )

    raw_text = "".join(block.text for block in response.content if block.type == "text")

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Model did not return valid JSON: {raw_text[:500]}") from exc

    return AIInvestigation(
        summary=parsed["summary"],
        suggested_actions=parsed["suggested_actions"],
        mitre_chain=parsed["mitre_chain"],
        confidence=parsed["confidence"],
        generated_at=datetime.now(timezone.utc),
        model=MODEL,
    )
