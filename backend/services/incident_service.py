"""Phase 11 — Incident Management Service."""
import json
from datetime import datetime
from typing import Optional, List
from sqlalchemy.orm import Session
from models.incident import Incident, IncidentStatus, IncidentPriority
from models.alert import Alert


def create_incident_from_alerts(db: Session, alert_ids: List[int], title: str = None) -> Optional[Incident]:
    alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
    if not alerts:
        return None

    first_alert = alerts[0]
    incident_id = _generate_incident_id(db)

    highest_severity = "low"
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    for a in alerts:
        if severity_order.get(a.severity, 0) > severity_order.get(highest_severity, 0):
            highest_severity = a.severity

    incident = Incident(
        incident_id=incident_id,
        title=title or f"Incident: {first_alert.title}",
        description=f"Correlated from {len(alerts)} alert(s). Source IP: {first_alert.source_ip}",
        status=IncidentStatus.new,
        priority=_severity_to_priority(highest_severity),
        severity=highest_severity,
        source_ip=first_alert.source_ip,
        hostname=first_alert.hostname,
        username=first_alert.username,
        mitre_technique=first_alert.mitre_technique,
        mitre_tactic=first_alert.mitre_tactic,
        risk_score=max(a.risk_score or 0 for a in alerts),
        alert_ids=json.dumps(alert_ids),
        timeline=json.dumps([
            {"time": a.created_at.isoformat() if a.created_at else None, "event": a.title, "type": "alert"}
            for a in alerts
        ]),
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def get_incidents(db: Session, skip: int = 0, limit: int = 50) -> List[Incident]:
    return db.query(Incident).order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()


def get_incident_by_id(db: Session, incident_id: int) -> Optional[Incident]:
    return db.query(Incident).filter(Incident.id == incident_id).first()


def update_incident_status(db: Session, incident_id: int, status: str) -> Optional[Incident]:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident:
        incident.status = status
        if status in ("closed", "resolved"):
            incident.resolved_at = datetime.utcnow()
        db.commit()
        db.refresh(incident)
    return incident


def assign_incident(db: Session, incident_id: int, assigned_to: str) -> Optional[Incident]:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident:
        incident.assigned_to = assigned_to
        db.commit()
        db.refresh(incident)
    return incident


def get_incident_stats(db: Session) -> dict:
    total = db.query(Incident).count()
    by_status = {}
    for status in IncidentStatus:
        by_status[status.value] = db.query(Incident).filter(Incident.status == status).count()
    by_priority = {}
    for p in IncidentPriority:
        by_priority[p.value] = db.query(Incident).filter(Incident.priority == p).count()
    return {"total": total, "by_status": by_status, "by_priority": by_priority}


def _generate_incident_id(db: Session) -> str:
    last = db.query(Incident).order_by(Incident.id.desc()).first()
    if last and last.incident_id:
        num = int(last.incident_id.replace("INC-", "")) + 1
    else:
        num = 1
    return f"INC-{num:05d}"


def _severity_to_priority(severity: str) -> IncidentPriority:
    mapping = {
        "critical": IncidentPriority.p1,
        "high": IncidentPriority.p2,
        "medium": IncidentPriority.p3,
        "low": IncidentPriority.p4,
    }
    return mapping.get(severity, IncidentPriority.p3)
