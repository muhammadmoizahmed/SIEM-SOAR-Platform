"""Phase 20 — Audit Logs API."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.database import get_db
from services.audit_service import get_audit_logs, get_audit_log_count, get_analyst_activity
from services.auth import get_current_user, require_permission
from models.user import User

router = APIRouter(prefix="/api/audit-logs", tags=["audit-logs"])


@router.get("/")
def list_audit_logs(
    analyst: str = None,
    action: str = None,
    target_type: str = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_audit_logs")),
):
    logs = get_audit_logs(db, analyst, action, target_type, skip, limit)
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "analyst": l.analyst,
            "action": l.action,
            "target_type": l.target_type,
            "target_id": l.target_id,
            "details": l.details,
            "ip_address": l.ip_address,
            "result": l.result,
        }
        for l in logs
    ]


@router.get("/count")
def audit_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_audit_logs")),
):
    return {"count": get_audit_log_count(db)}


@router.get("/activity")
def analyst_activity(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_audit_logs")),
):
    return get_analyst_activity(db)
