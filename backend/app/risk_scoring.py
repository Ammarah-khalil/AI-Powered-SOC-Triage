"""
Risk Scoring Engine.

Weighted point system: severity of individual behaviors, threat intel
confidence, and asset criticality all contribute to a single incident-level
score. This is intentionally simple and *tunable* -- in a real deployment
these weights would be backed by historical incident outcomes, not just
gut-feel constants.
"""
from __future__ import annotations

from .models import (
    Alert,
    MitreTechnique,
    RiskScore,
    RiskScoreBreakdown,
    Severity,
    ThreatIntelHit,
)

# Points contributed per MITRE tactic -- later-stage tactics score higher
# because they represent deeper compromise.
TACTIC_WEIGHTS: dict[str, int] = {
    "Initial Access": 10,
    "Execution": 10,
    "Persistence": 20,
    "Privilege Escalation": 25,
    "Credential Access": 35,
    "Discovery": 10,
    "Lateral Movement": 30,
    "Command and Control": 40,
    "Exfiltration": 45,
    "Impact": 50,
}

CRITICAL_ASSET_KEYWORDS = ("dc", "domain-controller", "domaincontroller", "sql", "prod")


def score_incident(
    alerts: list[Alert],
    mitre_techniques: list[MitreTechnique],
    threat_intel: list[ThreatIntelHit],
    affected_hosts: list[str],
) -> RiskScore:
    breakdown: list[RiskScoreBreakdown] = []

    # 1. Volume of correlated alerts (more alerts = more confirmed activity)
    if alerts:
        volume_points = min(len(alerts) * 3, 30)
        breakdown.append(RiskScoreBreakdown(factor=f"{len(alerts)} correlated alerts", points=volume_points))

    # 2. MITRE technique / tactic severity
    for tech in mitre_techniques:
        pts = TACTIC_WEIGHTS.get(tech.tactic, 10)
        breakdown.append(RiskScoreBreakdown(factor=f"{tech.name} ({tech.technique_id})", points=pts))

    # 3. Threat intelligence confidence
    for hit in threat_intel:
        # scale confidence (0-100) down to a point contribution, capped
        pts = round(hit.confidence * 0.4)
        breakdown.append(
            RiskScoreBreakdown(factor=f"{hit.verdict} via {hit.source} ({hit.confidence}% confidence)", points=pts)
        )

    # 4. Asset criticality
    for host in affected_hosts:
        if any(kw in host.lower() for kw in CRITICAL_ASSET_KEYWORDS):
            breakdown.append(RiskScoreBreakdown(factor=f"Critical asset: {host}", points=30))

    total = sum(item.points for item in breakdown)

    if total >= 100:
        level = Severity.critical
    elif total >= 60:
        level = Severity.high
    elif total >= 30:
        level = Severity.medium
    else:
        level = Severity.low

    return RiskScore(total=total, level=level, breakdown=breakdown)
