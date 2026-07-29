"""
Core data models for the SOC Alert Correlation & Triage Platform.

These mirror the shape that would come out of the Correlation Engine
(Kafka consumer -> grouped alerts) further upstream. For this slice of the
project we mock that output, but the shapes here are what a real
correlation engine should emit so the AI Investigation Engine and
dashboard can be swapped onto the real pipeline later without changes.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IncidentStatus(str, Enum):
    new = "new"
    investigating = "investigating"
    contained = "contained"
    closed = "closed"


class Alert(BaseModel):
    id: str
    timestamp: datetime
    source: str  # e.g. "Sysmon", "Wazuh", "Suricata"
    event_type: str  # e.g. "Failed Login", "PowerShell Execution"
    host: str
    user: Optional[str] = None
    process: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    raw_detail: Optional[str] = None


class MitreTechnique(BaseModel):
    technique_id: str  # e.g. "T1059"
    name: str  # e.g. "Command and Scripting Interpreter"
    tactic: str  # e.g. "Execution"


class ThreatIntelHit(BaseModel):
    indicator: str  # ip / domain / hash
    indicator_type: str  # "ip" | "domain" | "hash" | "url"
    source: str  # "VirusTotal" | "AbuseIPDB" | "GreyNoise" | "OTX" | "MISP"
    verdict: str  # e.g. "Known C2 Server"
    confidence: int  # 0-100
    threat_actor: Optional[str] = None


class RiskScoreBreakdown(BaseModel):
    factor: str
    points: int


class RiskScore(BaseModel):
    total: int
    level: Severity
    breakdown: list[RiskScoreBreakdown]


class AIInvestigation(BaseModel):
    summary: str
    suggested_actions: list[str]
    mitre_chain: list[str]  # ordered technique IDs, e.g. ["T1059", "T1003", "T1071"]
    confidence: int = Field(ge=0, le=100)
    generated_at: datetime
    model: str


class Incident(BaseModel):
    id: str
    title: str
    status: IncidentStatus
    severity: Severity
    created_at: datetime
    updated_at: datetime
    affected_hosts: list[str]
    affected_users: list[str]
    alerts: list[Alert]
    mitre_techniques: list[MitreTechnique]
    threat_intel: list[ThreatIntelHit]
    risk_score: RiskScore
    ai_investigation: Optional[AIInvestigation] = None
    assigned_analyst: Optional[str] = None


class IncidentSummary(BaseModel):
    """Lightweight shape for list views (Incident Overview table)."""
    id: str
    title: str
    status: IncidentStatus
    severity: Severity
    risk_score: int
    alert_count: int
    created_at: datetime
    top_technique: Optional[str] = None
