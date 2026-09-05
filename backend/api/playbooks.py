"""Phase 23 — Playbooks API."""
from fastapi import APIRouter, Depends, HTTPException
from services.soar import list_playbooks, load_playbook, execute_playbook
from services.auth import get_current_user, require_permission
from services.audit_service import get_audit_logs, get_audit_log_count
from models.user import User
from database.database import get_db
from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])


@router.get("/")
def get_playbooks(
    current_user: User = Depends(get_current_user),
):
    return list_playbooks()


@router.get("/{playbook_name}")
def get_playbook(
    playbook_name: str,
    current_user: User = Depends(get_current_user),
):
    pb = load_playbook(playbook_name)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb


@router.post("/{playbook_name}/execute")
def run_playbook(
    playbook_name: str,
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("execute_playbooks")),
):
    result = execute_playbook(db, alert_id, playbook_name, analyst=current_user.username)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.get("/audit/log")
def audit_log(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_audit_logs")),
):
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "analyst": l.analyst,
            "action": l.action,
            "target_type": l.target_type,
            "target_id": l.target_id,
            "details": l.details,
            "result": l.result,
        }
        for l in get_audit_logs(db, limit=100)
    ]


@router.get("/audit/count")
def audit_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("view_audit_logs")),
):
    return {"count": get_audit_log_count(db)}
