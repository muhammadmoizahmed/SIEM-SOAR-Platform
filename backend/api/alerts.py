"""Phase 23 — Alerts API with Audit Logging."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.database import get_db
from services.detector import (
    get_recent_alerts, get_alert_by_id, update_alert_status,
    get_alert_stats, get_mitre_techniques,
)
from services.soar import execute_playbook
from services.audit_service import log_action
from services.auth import get_current_user, require_permission
from models.alert import Alert, AlertStatus
from models.user import User
from typing import Optional

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("/")
def list_alerts(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    rule_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_alerts")),
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if rule_name:
        query = query.filter(Alert.rule_name == rule_name)
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)
    if username:
        query = query.filter(Alert.username == username)

    alerts = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()
    return [
        {
            "id": a.id,
            "alert_id": a.alert_id,
            "title": a.title,
            "description": a.description,
            "severity": a.severity,
            "status": a.status.value if a.status else "open",
            "source_ip": a.source_ip,
            "username": a.username,
            "hostname": a.hostname,
            "rule_name": a.rule_name,
            "mitre_technique": a.mitre_technique,
            "mitre_tactic": a.mitre_tactic,
            "risk_score": a.risk_score,
            "event_count": a.event_count,
            "first_seen": a.first_seen.isoformat() if a.first_seen else None,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in alerts
    ]


@router.get("/stats")
def alert_statistics(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_alerts")),
):
    return get_alert_stats(db)


@router.get("/mitre")
def mitre_techniques(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_alerts")),
):
    return get_mitre_techniques(db)


@router.get("/{alert_id}")
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_alerts")),
):
    alert = get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "id": alert.id,
        "alert_id": alert.alert_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status.value if alert.status else "open",
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "username": alert.username,
        "hostname": alert.hostname,
        "rule_name": alert.rule_name,
        "mitre_technique": alert.mitre_technique,
        "mitre_tactic": alert.mitre_tactic,
        "risk_score": alert.risk_score,
        "event_count": alert.event_count,
        "first_seen": alert.first_seen.isoformat() if alert.first_seen else None,
        "last_seen": alert.last_seen.isoformat() if alert.last_seen else None,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }


@router.patch("/{alert_id}")
def patch_alert(
    alert_id: int,
    status: str = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("investigate_alerts")),
):
    alert = update_alert_status(db, alert_id, status)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    log_action(db, current_user.username, "UPDATE_ALERT_STATUS", "alert", alert.alert_id,
               f"Status changed to {status}", result="success")
    return {"id": alert.id, "alert_id": alert.alert_id, "status": alert.status.value}


@router.put("/{alert_id}/status")
def update_status(
    alert_id: int,
    status: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("investigate_alerts")),
):
    alert = update_alert_status(db, alert_id, status)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    log_action(db, current_user.username, "UPDATE_ALERT_STATUS", "alert", alert.alert_id,
               f"Status changed to {status}", result="success")
    return {"id": alert.id, "alert_id": alert.alert_id, "status": alert.status.value}


@router.post("/{alert_id}/respond")
def respond_to_alert(
    alert_id: int,
    playbook_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("execute_playbooks")),
):
    result = execute_playbook(db, alert_id, playbook_name, analyst=current_user.username)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result
