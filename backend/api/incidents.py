"""Phase 23 — Incidents API with Audit Logging."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database.database import get_db
from services.incident_service import (
    get_incidents, get_incident_by_id, update_incident_status,
    assign_incident, get_incident_stats, create_incident_from_alerts,
)
from services.audit_service import log_action
from services.auth import get_current_user, require_permission
from models.user import User

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


class CreateIncidentRequest(BaseModel):
    alert_ids: list
    title: str = None


@router.get("/")
def list_incidents(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_alerts")),
):
    incidents = get_incidents(db, skip, limit)
    return [
        {
            "id": i.id,
            "incident_id": i.incident_id,
            "title": i.title,
            "description": i.description,
            "status": i.status.value if i.status else "new",
            "priority": i.priority.value if i.priority else "P3",
            "severity": i.severity,
            "assigned_to": i.assigned_to,
            "source_ip": i.source_ip,
            "hostname": i.hostname,
            "username": i.username,
            "mitre_technique": i.mitre_technique,
            "risk_score": i.risk_score,
            "alert_ids": i.alert_ids,
            "created_at": i.created_at.isoformat() if i.created_at else None,
        }
        for i in incidents
    ]


@router.get("/stats")
def incident_statistics(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_alerts")),
):
    return get_incident_stats(db)


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_alerts")),
):
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        "id": incident.id,
        "incident_id": incident.incident_id,
        "title": incident.title,
        "description": incident.description,
        "status": incident.status.value if incident.status else "new",
        "priority": incident.priority.value if incident.priority else "P3",
        "severity": incident.severity,
        "assigned_to": incident.assigned_to,
        "source_ip": incident.source_ip,
        "destination_ip": incident.destination_ip,
        "hostname": incident.hostname,
        "username": incident.username,
        "mitre_technique": incident.mitre_technique,
        "mitre_tactic": incident.mitre_tactic,
        "risk_score": incident.risk_score,
        "alert_ids": incident.alert_ids,
        "timeline": incident.timeline,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
    }


@router.patch("/{incident_id}")
def patch_incident(
    incident_id: int,
    status: str = None,
    assigned_to: str = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_incidents")),
):
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if status:
        incident = update_incident_status(db, incident_id, status)
        log_action(db, current_user.username, "UPDATE_INCIDENT_STATUS", "incident", incident.incident_id,
                   f"Status changed to {status}", result="success")
    if assigned_to:
        incident = assign_incident(db, incident_id, assigned_to)
        log_action(db, current_user.username, "ASSIGN_INCIDENT", "incident", incident.incident_id,
                   f"Assigned to {assigned_to}", result="success")
    return {
        "id": incident.id,
        "incident_id": incident.incident_id,
        "status": incident.status.value,
        "assigned_to": incident.assigned_to,
    }


@router.put("/{incident_id}/status")
def update_status(
    incident_id: int,
    status: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_incidents")),
):
    incident = update_incident_status(db, incident_id, status)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    log_action(db, current_user.username, "UPDATE_INCIDENT_STATUS", "incident", incident.incident_id,
               f"Status changed to {status}", result="success")
    return {"id": incident.id, "incident_id": incident.incident_id, "status": incident.status.value}


@router.put("/{incident_id}/assign")
def assign(
    incident_id: int,
    assigned_to: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_incidents")),
):
    incident = assign_incident(db, incident_id, assigned_to)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    log_action(db, current_user.username, "ASSIGN_INCIDENT", "incident", incident.incident_id,
               f"Assigned to {assigned_to}", result="success")
    return {"id": incident.id, "incident_id": incident.incident_id, "assigned_to": incident.assigned_to}


@router.post("/create-from-alerts")
def create_from_alerts(
    req: CreateIncidentRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_incidents")),
):
    incident = create_incident_from_alerts(db, req.alert_ids, req.title)
    if not incident:
        raise HTTPException(status_code=400, detail="No alerts found")
    log_action(db, current_user.username, "CREATE_INCIDENT", "incident", incident.incident_id,
               f"Created from alerts: {req.alert_ids}", result="success")
    return {"id": incident.id, "incident_id": incident.incident_id, "title": incident.title}
