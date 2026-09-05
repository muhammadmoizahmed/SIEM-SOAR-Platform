from sqlalchemy import Column, Integer, String, DateTime, Text, Enum as SAEnum
from sqlalchemy.sql import func
from database.database import Base
import enum


class AlertStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    investigating = "investigating"
    resolved = "resolved"
    false_positive = "false_positive"


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(20), unique=True, index=True)  # ALT-00001
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)
    status = Column(SAEnum(AlertStatus), default=AlertStatus.open)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45))
    username = Column(String(255))
    hostname = Column(String(255))
    rule_name = Column(String(255))
    mitre_technique = Column(String(20))  # T1110
    mitre_tactic = Column(String(100))    # Credential Access
    risk_score = Column(Integer, default=0)
    event_count = Column(Integer, default=1)
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
