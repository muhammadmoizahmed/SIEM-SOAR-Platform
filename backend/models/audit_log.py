"""Phase 20 — Audit Log Model."""
from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from database.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    analyst = Column(String(255), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)
    target_type = Column(String(50))  # alert, incident, playbook, system
    target_id = Column(String(50))
    details = Column(Text)
    ip_address = Column(String(45))
    result = Column(String(50))  # success, failure, simulated
