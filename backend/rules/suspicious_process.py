from datetime import datetime
from typing import List
from sqlalchemy.orm import Session


MITRE_EXEC = "T1059"
MITRE_POWERSHELL = "T1059.001"

SUSPICIOUS_PROCESSES = {
    "powershell.exe": {"severity": "high", "technique": MITRE_POWERSHELL, "tactic": "Execution"},
    "cmd.exe": {"severity": "medium", "technique": MITRE_EXEC, "tactic": "Execution"},
    "wscript.exe": {"severity": "high", "technique": MITRE_EXEC, "tactic": "Execution"},
    "cscript.exe": {"severity": "high", "technique": MITRE_EXEC, "tactic": "Execution"},
    "mshta.exe": {"severity": "critical", "technique": MITRE_EXEC, "tactic": "Execution"},
    "regsvr32.exe": {"severity": "high", "technique": MITRE_EXEC, "tactic": "Execution"},
    "rundll32.exe": {"severity": "high", "technique": MITRE_EXEC, "tactic": "Execution"},
}

SUSPICIOUS_FLAGS = ["-enc", "-encodedcommand", "bypass", "-nop", "-noni", "downloadstring", "invoke-expression", "iex", "start-process"]

SUSPICIOUS_PATHS = ["\\temp\\", "\\appdata\\", "\\public\\", "/tmp/", "/var/tmp/"]


def detect_suspicious_process(db: Session, events: List[dict]) -> List[dict]:
    """Rule #5: Suspicious Process Execution — powershell, cmd, wscript with suspicious context."""
    alerts = []

    process_events = [e for e in events if e.get("event_type") == "process"]

    for event in process_events:
        raw_log = (event.get("raw_log", "")).lower()
        severity = "medium"
        reasons = []
        technique = MITRE_EXEC
        tactic = "Execution"

        for proc, info in SUSPICIOUS_PROCESSES.items():
            if proc.lower() in raw_log:
                severity = info["severity"]
                technique = info["technique"]
                tactic = info["tactic"]
                reasons.append(f"Suspicious process: {proc}")

        for flag in SUSPICIOUS_FLAGS:
            if flag.lower() in raw_log:
                reasons.append(f"Suspicious flag: {flag}")
                if severity == "medium":
                    severity = "high"

        for path in SUSPICIOUS_PATHS:
            if path.lower() in raw_log:
                reasons.append(f"Execution from suspicious path: {path}")
                if severity in ("medium", "high"):
                    severity = "critical"

        if reasons:
            alerts.append({
                "title": f"Suspicious Process Execution - {event.get('source_ip', 'unknown')}",
                "description": "; ".join(reasons),
                "severity": severity,
                "source_ip": event.get("source_ip"),
                "username": event.get("username"),
                "rule_name": "suspicious_process",
                "mitre_technique": technique,
                "mitre_tactic": tactic,
                "event_count": 1,
                "first_seen": event.get("timestamp"),
                "last_seen": event.get("timestamp"),
            })

    return alerts
