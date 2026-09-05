"""Phase 20 — Audit Log Service."""
from datetime import datetime
from typing import Optional, List
from sqlalchemy.orm import Session
from models.audit_log import AuditLog


def log_action(
    db: Session,
    analyst: str,
    action: str,
    target_type: str = None,
    target_id: str = None,
    details: str = None,
    ip_address: str = None,
    result: str = "success",
) -> AuditLog:
    entry = AuditLog(
        analyst=analyst,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id else None,
        details=details,
        ip_address=ip_address,
        result=result,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def get_audit_logs(
    db: Session,
    analyst: str = None,
    action: str = None,
    target_type: str = None,
    skip: int = 0,
    limit: int = 100,
) -> List[AuditLog]:
    query = db.query(AuditLog)
    if analyst:
        query = query.filter(AuditLog.analyst == analyst)
    if action:
        query = query.filter(AuditLog.action == action)
    if target_type:
        query = query.filter(AuditLog.target_type == target_type)
    return query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()


def get_audit_log_count(db: Session) -> int:
    return db.query(AuditLog).count()


def get_analyst_activity(db: Session) -> dict:
    from sqlalchemy import func
    results = (
        db.query(AuditLog.analyst, func.count(AuditLog.id).label("count"))
        .group_by(AuditLog.analyst)
        .order_by(func.count(AuditLog.id).desc())
        .all()
    )
    return {analyst: count for analyst, count in results}
