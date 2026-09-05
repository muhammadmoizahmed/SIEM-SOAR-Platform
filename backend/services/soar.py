"""Phase 14-16 + Phase 20 — SOAR Engine with Database Audit Logging."""
import json
import os
from datetime import datetime
from typing import Optional, List
from sqlalchemy.orm import Session
from models.alert import Alert
from models.incident import Incident, IncidentStatus, IncidentPriority
from services.threat_intel import enrich_ip, lookup_ip_threat_intel
from services.risk_scoring import calculate_alert_risk_score
from services.audit_service import log_action


PLAYBOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "playbooks")


def load_playbook(name: str) -> Optional[dict]:
    path = os.path.join(PLAYBOOKS_DIR, f"{name}.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return None


def list_playbooks() -> List[dict]:
    playbooks = []
    if os.path.exists(PLAYBOOKS_DIR):
        for f in os.listdir(PLAYBOOKS_DIR):
            if f.endswith(".json"):
                name = f.replace(".json", "")
                path = os.path.join(PLAYBOOKS_DIR, f)
                with open(path, "r") as fh:
                    data = json.load(fh)
                playbooks.append({
                    "name": name,
                    "description": data.get("description", ""),
                    "actions_count": len(data.get("actions", [])),
                })
    return playbooks


def execute_playbook(db: Session, alert_id: int, playbook_name: str, analyst: str = "system") -> dict:
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        return {"error": "Alert not found"}

    playbook = load_playbook(playbook_name)
    if not playbook:
        return {"error": f"Playbook '{playbook_name}' not found"}

    execution_log = []
    source_ip = alert.source_ip

    log_action(db, analyst, "PLAYBOOK_START", "alert", alert.alert_id,
               f"Starting playbook '{playbook_name}' for alert {alert.alert_id}")
    execution_log.append({"step": 1, "action": "receive_alert", "status": "completed", "alert_id": alert.alert_id})

    log_action(db, analyst, "EXTRACT_IP", "alert", alert.alert_id, f"Extracted IP: {source_ip}")
    execution_log.append({"step": 2, "action": "extract_ip", "ip": source_ip, "status": "completed"})

    threat_data = enrich_ip(source_ip) if source_ip else {}
    rep = threat_data.get("threat_intel", {}).get("reputation", "unknown")
    log_action(db, analyst, "THREAT_INTEL", "alert", alert.alert_id, f"Threat intel for {source_ip}: {rep}")
    execution_log.append({"step": 3, "action": "threat_intelligence", "data": threat_data, "status": "completed"})

    risk_score = calculate_alert_risk_score({
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "event_count": alert.event_count,
    })
    log_action(db, analyst, "RISK_SCORE", "alert", alert.alert_id, f"Risk score: {risk_score}/100")
    execution_log.append({"step": 4, "action": "calculate_risk", "risk_score": risk_score, "status": "completed"})

    incident = Incident(
        incident_id=_gen_inc_id(db),
        title=f"Incident: {alert.title}",
        description=f"Auto-created via SOAR playbook '{playbook_name}'. Alert: {alert.alert_id}. IP: {source_ip}. Risk: {risk_score}/100.",
        status=IncidentStatus.new,
        priority=_risk_to_priority(risk_score),
        severity=alert.severity,
        source_ip=source_ip,
        username=alert.username,
        hostname=alert.hostname,
        mitre_technique=alert.mitre_technique,
        mitre_tactic=alert.mitre_tactic,
        risk_score=risk_score,
        alert_ids=json.dumps([alert_id]),
        assigned_to=analyst,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    log_action(db, analyst, "CREATE_INCIDENT", "incident", incident.id, f"Incident created from alert {alert.alert_id}")
    execution_log.append({"step": 5, "action": "create_incident", "incident_id": incident.id, "status": "completed"})

    log_action(db, analyst, "NOTIFY_ANALYST", "incident", incident.id, f"Notification sent to SOC team")
    execution_log.append({"step": 6, "action": "notify_analyst", "channel": "soc-alerts", "status": "simulated"})

    actions_results = []
    for action in playbook.get("actions", []):
        result = _execute_action(db, alert, action, source_ip, analyst)
        actions_results.append(result)
        execution_log.append({"step": 7, "action": action["type"], "result": result, "status": "completed"})

    log_action(db, analyst, "PLAYBOOK_COMPLETE", "alert", alert.alert_id,
               f"Playbook '{playbook_name}' completed. Incident: {incident.id}")

    alert.status = "investigating"
    db.commit()

    return {
        "incident_id": incident.id,
        "alert_id": alert.alert_id,
        "playbook": playbook_name,
        "risk_score": risk_score,
        "threat_intel": threat_data,
        "actions_executed": actions_results,
        "execution_log": execution_log,
        "status": "completed",
    }


def _execute_action(db: Session, alert: Alert, action: dict, source_ip: str, analyst: str) -> dict:
    action_type = action.get("type")

    if action_type == "block_ip":
        result = _simulate_block_ip(source_ip)
        log_action(db, analyst, "BLOCK_IP", "alert", alert.alert_id,
                   f"Simulated block for IP {source_ip}", result="simulated")
        return {"action": "block_ip", "target": source_ip, "mode": "simulation", "result": result["result"]}

    elif action_type == "disable_user":
        result = _simulate_disable_user(alert.username)
        log_action(db, analyst, "DISABLE_USER", "alert", alert.alert_id,
                   f"Simulated disable for user {alert.username}", result="simulated")
        return {"action": "disable_user", "target": alert.username, "mode": "simulation", "result": result["result"]}

    elif action_type == "notify":
        channel = action.get("channel", "soc-team")
        log_action(db, analyst, "NOTIFY", "system", None, f"Notification sent to {channel}", result="simulated")
        return {"action": "notify", "target": channel, "mode": "simulation", "result": "sent"}

    elif action_type == "isolate_host":
        result = _simulate_isolate_host(source_ip)
        log_action(db, analyst, "ISOLATE_HOST", "alert", alert.alert_id,
                   f"Simulated isolation for {source_ip}", result="simulated")
        return {"action": "isolate_host", "target": source_ip, "mode": "simulation", "result": result["result"]}

    elif action_type == "quarantine":
        target = alert.hostname or source_ip
        result = _simulate_quarantine(target)
        log_action(db, analyst, "QUARANTINE", "alert", alert.alert_id,
                   f"Simulated quarantine for {target}", result="simulated")
        return {"action": "quarantine", "target": target, "mode": "simulation", "result": result["result"]}

    return {"action": action_type, "status": "unknown_action", "result": "skipped"}


def _simulate_block_ip(ip: str) -> dict:
    return {"result": "successfully_blocked", "ip": ip, "timestamp": datetime.utcnow().isoformat()}


def _simulate_disable_user(username: str) -> dict:
    return {"result": "successfully_disabled", "username": username, "timestamp": datetime.utcnow().isoformat()}


def _simulate_isolate_host(host: str) -> dict:
    return {"result": "successfully_isolated", "host": host, "timestamp": datetime.utcnow().isoformat()}


def _simulate_quarantine(host: str) -> dict:
    return {"result": "successfully_quarantined", "host": host, "timestamp": datetime.utcnow().isoformat()}


def _risk_to_priority(score: int) -> IncidentPriority:
    if score >= 81:
        return IncidentPriority.p1
    elif score >= 51:
        return IncidentPriority.p2
    elif score >= 21:
        return IncidentPriority.p3
    return IncidentPriority.p4


def _gen_inc_id(db: Session) -> str:
    last = db.query(Incident).order_by(Incident.id.desc()).first()
    if last and last.incident_id:
        num = int(last.incident_id.replace("INC-", "")) + 1
    else:
        num = 1
    return f"INC-{num:05d}"
