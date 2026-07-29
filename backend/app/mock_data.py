"""
Mock correlated-incident data.

Stands in for the Correlation Engine + Kafka pipeline described in the
design doc. Shaped exactly like what that pipeline should emit, so this
module is the only thing that needs replacing once Wazuh/Kafka/Elasticsearch
are wired up for real.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .models import (
    Alert,
    Incident,
    IncidentStatus,
    MitreTechnique,
    Severity,
    ThreatIntelHit,
)
from .risk_scoring import score_incident

_BASE = datetime(2026, 7, 27, 9, 0, tzinfo=timezone.utc)


def _incident_brute_force_to_c2() -> Incident:
    alerts = [
        Alert(id="a1", timestamp=_BASE, source="Wazuh", event_type="Failed Login",
              host="WKS-0231", user="j.morales", src_ip="41.203.88.12"),
        Alert(id="a2", timestamp=_BASE + timedelta(minutes=1), source="Wazuh", event_type="Failed Login",
              host="WKS-0231", user="j.morales", src_ip="41.203.88.12"),
        Alert(id="a3", timestamp=_BASE + timedelta(minutes=3), source="Wazuh", event_type="Failed Login",
              host="WKS-0231", user="j.morales", src_ip="41.203.88.12"),
        Alert(id="a4", timestamp=_BASE + timedelta(minutes=4), source="Wazuh", event_type="Successful Login",
              host="WKS-0231", user="j.morales", src_ip="41.203.88.12"),
        Alert(id="a5", timestamp=_BASE + timedelta(minutes=6), source="Sysmon", event_type="PowerShell Execution",
              host="WKS-0231", user="j.morales", process="powershell.exe -enc <base64>"),
        Alert(id="a6", timestamp=_BASE + timedelta(minutes=7), source="Sysmon", event_type="Encoded Command",
              host="WKS-0231", user="j.morales", process="powershell.exe"),
        Alert(id="a7", timestamp=_BASE + timedelta(minutes=9), source="Suricata", event_type="C2 Beacon",
              host="WKS-0231", dst_ip="185.220.101.47"),
    ]
    mitre = [
        MitreTechnique(technique_id="T1110", name="Brute Force", tactic="Credential Access"),
        MitreTechnique(technique_id="T1059", name="Command and Scripting Interpreter", tactic="Execution"),
        MitreTechnique(technique_id="T1071", name="Application Layer Protocol", tactic="Command and Control"),
    ]
    intel = [
        ThreatIntelHit(indicator="185.220.101.47", indicator_type="ip", source="AbuseIPDB",
                        verdict="Known C2 Server", confidence=98, threat_actor="LockBit"),
    ]
    hosts = ["WKS-0231"]
    users = ["j.morales"]
    risk = score_incident(alerts, mitre, intel, hosts)

    return Incident(
        id="INC-142",
        title="Brute Force \u2192 PowerShell Execution \u2192 C2 Beaconing",
        status=IncidentStatus.investigating,
        severity=risk.level,
        created_at=_BASE,
        updated_at=_BASE + timedelta(minutes=9),
        affected_hosts=hosts,
        affected_users=users,
        alerts=alerts,
        mitre_techniques=mitre,
        threat_intel=intel,
        risk_score=risk,
        assigned_analyst=None,
    )


def _incident_lotl() -> Incident:
    base = _BASE + timedelta(hours=2)
    alerts = [
        Alert(id="b1", timestamp=base, source="Sysmon", event_type="Office Macro Execution",
              host="WKS-0117", user="d.chen", process="winword.exe -> cmd.exe"),
        Alert(id="b2", timestamp=base + timedelta(minutes=1), source="Sysmon", event_type="PowerShell Execution",
              host="WKS-0117", user="d.chen", process="powershell.exe -w hidden"),
        Alert(id="b3", timestamp=base + timedelta(minutes=2), source="Suricata", event_type="Network Download",
              host="WKS-0117", dst_ip="91.240.118.33"),
        Alert(id="b4", timestamp=base + timedelta(minutes=4), source="Wazuh", event_type="New Service Created",
              host="WKS-0117", user="SYSTEM"),
    ]
    mitre = [
        MitreTechnique(technique_id="T1566", name="Phishing", tactic="Initial Access"),
        MitreTechnique(technique_id="T1059", name="Command and Scripting Interpreter", tactic="Execution"),
        MitreTechnique(technique_id="T1105", name="Ingress Tool Transfer", tactic="Command and Control"),
        MitreTechnique(technique_id="T1543", name="Create or Modify System Process", tactic="Persistence"),
    ]
    intel = [
        ThreatIntelHit(indicator="91.240.118.33", indicator_type="ip", source="GreyNoise",
                        verdict="Malicious Scanner / Malware Host", confidence=87),
    ]
    hosts = ["WKS-0117"]
    users = ["d.chen"]
    risk = score_incident(alerts, mitre, intel, hosts)

    return Incident(
        id="INC-158",
        title="Malicious Office Macro \u2192 Living-off-the-Land \u2192 Persistence",
        status=IncidentStatus.new,
        severity=risk.level,
        created_at=base,
        updated_at=base + timedelta(minutes=4),
        affected_hosts=hosts,
        affected_users=users,
        alerts=alerts,
        mitre_techniques=mitre,
        threat_intel=intel,
        risk_score=risk,
        assigned_analyst="s.patel",
    )


def _incident_dc_credential_dump() -> Incident:
    base = _BASE + timedelta(hours=5)
    alerts = [
        Alert(id="c1", timestamp=base, source="Sysmon", event_type="LSASS Access",
              host="DC-PRIMARY", user="svc-backup", process="procdump.exe"),
        Alert(id="c2", timestamp=base + timedelta(minutes=2), source="Wazuh", event_type="New Administrator Account",
              host="DC-PRIMARY", user="svc-backup"),
        Alert(id="c3", timestamp=base + timedelta(minutes=5), source="Wazuh", event_type="Registry Persistence",
              host="DC-PRIMARY", user="svc-backup"),
    ]
    mitre = [
        MitreTechnique(technique_id="T1003", name="OS Credential Dumping", tactic="Credential Access"),
        MitreTechnique(technique_id="T1136", name="Create Account", tactic="Persistence"),
        MitreTechnique(technique_id="T1547", name="Boot or Logon Autostart Execution", tactic="Persistence"),
    ]
    intel: list[ThreatIntelHit] = []
    hosts = ["DC-PRIMARY"]
    users = ["svc-backup"]
    risk = score_incident(alerts, mitre, intel, hosts)

    return Incident(
        id="INC-163",
        title="Credential Dumping on Domain Controller",
        status=IncidentStatus.new,
        severity=risk.level,
        created_at=base,
        updated_at=base + timedelta(minutes=5),
        affected_hosts=hosts,
        affected_users=users,
        alerts=alerts,
        mitre_techniques=mitre,
        threat_intel=intel,
        risk_score=risk,
        assigned_analyst=None,
    )


def get_mock_incidents() -> list[Incident]:
    return [
        _incident_dc_credential_dump(),
        _incident_brute_force_to_c2(),
        _incident_lotl(),
    ]
