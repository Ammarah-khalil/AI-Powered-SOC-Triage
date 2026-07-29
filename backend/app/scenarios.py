"""
Attack scenario templates for the live simulator.

Each scenario is a sequence of stages. A stage fires after a delay (seconds
in the simulation, compressed from the real minutes/hours an actual attack
would take) and adds one or more alerts, optionally introduces a MITRE
technique, and optionally attaches a threat intel hit. The simulator plays
these out stage-by-stage against a fresh incident so you can watch an
incident escalate in real time instead of just appearing fully formed.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from .models import Alert, MitreTechnique, ThreatIntelHit

HOST_POOL = ["WKS-0231", "WKS-0117", "WKS-0409", "LAPTOP-3382", "DC-PRIMARY", "SRV-SQL01"]
USER_POOL = ["j.morales", "d.chen", "s.patel", "a.novak", "svc-backup", "r.singh"]
EXTERNAL_IPS = ["185.220.101.47", "91.240.118.33", "45.155.204.9", "194.26.29.150"]


@dataclass
class AlertStub:
    source: str
    event_type: str
    process: str | None = None
    uses_user: bool = True
    uses_external_ip: bool = False


@dataclass
class Stage:
    delay_seconds: float
    alert: AlertStub
    mitre: MitreTechnique | None = None
    intel: ThreatIntelHit | None = None


@dataclass
class ScenarioTemplate:
    title: str
    stages: list[Stage] = field(default_factory=list)


SCENARIOS: list[ScenarioTemplate] = [
    ScenarioTemplate(
        title="Brute Force \u2192 PowerShell Execution \u2192 C2 Beaconing",
        stages=[
            Stage(1.5, AlertStub("Wazuh", "Failed Login")),
            Stage(1.5, AlertStub("Wazuh", "Failed Login")),
            Stage(2.0, AlertStub("Wazuh", "Successful Login"),
                  mitre=MitreTechnique(technique_id="T1110", name="Brute Force", tactic="Credential Access")),
            Stage(2.5, AlertStub("Sysmon", "PowerShell Execution", process="powershell.exe -enc <base64>"),
                  mitre=MitreTechnique(technique_id="T1059", name="Command and Scripting Interpreter", tactic="Execution")),
            Stage(2.5, AlertStub("Suricata", "C2 Beacon", uses_user=False, uses_external_ip=True),
                  mitre=MitreTechnique(technique_id="T1071", name="Application Layer Protocol", tactic="Command and Control"),
                  intel=ThreatIntelHit(indicator="", indicator_type="ip", source="AbuseIPDB",
                                        verdict="Known C2 Server", confidence=98, threat_actor="LockBit")),
        ],
    ),
    ScenarioTemplate(
        title="Malicious Office Macro \u2192 Living-off-the-Land \u2192 Persistence",
        stages=[
            Stage(1.5, AlertStub("Sysmon", "Office Macro Execution", process="winword.exe -> cmd.exe"),
                  mitre=MitreTechnique(technique_id="T1566", name="Phishing", tactic="Initial Access")),
            Stage(2.0, AlertStub("Sysmon", "PowerShell Execution", process="powershell.exe -w hidden"),
                  mitre=MitreTechnique(technique_id="T1059", name="Command and Scripting Interpreter", tactic="Execution")),
            Stage(2.0, AlertStub("Suricata", "Network Download", uses_user=False, uses_external_ip=True),
                  mitre=MitreTechnique(technique_id="T1105", name="Ingress Tool Transfer", tactic="Command and Control"),
                  intel=ThreatIntelHit(indicator="", indicator_type="ip", source="GreyNoise",
                                        verdict="Malicious Scanner / Malware Host", confidence=87)),
            Stage(2.5, AlertStub("Wazuh", "New Service Created", uses_user=False),
                  mitre=MitreTechnique(technique_id="T1543", name="Create or Modify System Process", tactic="Persistence")),
        ],
    ),
    ScenarioTemplate(
        title="Credential Dumping on Domain Controller",
        stages=[
            Stage(1.5, AlertStub("Sysmon", "LSASS Access", process="procdump.exe"),
                  mitre=MitreTechnique(technique_id="T1003", name="OS Credential Dumping", tactic="Credential Access")),
            Stage(2.0, AlertStub("Wazuh", "New Administrator Account"),
                  mitre=MitreTechnique(technique_id="T1136", name="Create Account", tactic="Persistence")),
            Stage(2.0, AlertStub("Wazuh", "Registry Persistence"),
                  mitre=MitreTechnique(technique_id="T1547", name="Boot or Logon Autostart Execution", tactic="Persistence")),
        ],
    ),
    ScenarioTemplate(
        title="Ransomware Precursor: Encryption + Lateral Prep",
        stages=[
            Stage(1.5, AlertStub("Sysmon", "PowerShell Execution", process="powershell.exe -nop -w hidden"),
                  mitre=MitreTechnique(technique_id="T1059", name="Command and Scripting Interpreter", tactic="Execution")),
            Stage(1.5, AlertStub("Wazuh", "Suspicious Login")),
            Stage(2.0, AlertStub("Wazuh", "Mass File Encryption Detected"),
                  mitre=MitreTechnique(technique_id="T1486", name="Data Encrypted for Impact", tactic="Impact")),
            Stage(2.0, AlertStub("Suricata", "Connection to Malicious IP", uses_user=False, uses_external_ip=True),
                  intel=ThreatIntelHit(indicator="", indicator_type="ip", source="VirusTotal",
                                        verdict="Known Ransomware Infrastructure", confidence=95, threat_actor="LockBit")),
            Stage(2.0, AlertStub("Wazuh", "New Administrator Account"),
                  mitre=MitreTechnique(technique_id="T1136", name="Create Account", tactic="Persistence")),
        ],
    ),
]


def build_alert(alert_id: str, timestamp, stub: AlertStub, host: str, user: str) -> Alert:
    return Alert(
        id=alert_id,
        timestamp=timestamp,
        source=stub.source,
        event_type=stub.event_type,
        host=host,
        user=user if stub.uses_user else None,
        process=stub.process,
        dst_ip=random.choice(EXTERNAL_IPS) if stub.uses_external_ip else None,
    )


def pick_scenario() -> ScenarioTemplate:
    return random.choice(SCENARIOS)


def pick_host_and_user() -> tuple[str, str]:
    return random.choice(HOST_POOL), random.choice(USER_POOL)
