from sqlalchemy import Column, Integer, String, DateTime, Text, Enum as SAEnum
from sqlalchemy.sql import func
from database.database import Base
import enum


class IncidentStatus(str, enum.Enum):
    new = "new"
    open = "open"
    triaged = "triaged"
    investigating = "investigating"
    contained = "contained"
    eradicated = "eradicated"
    recovered = "recovered"
    closed = "closed"
    false_positive = "false_positive"


class IncidentPriority(str, enum.Enum):
    p1 = "P1"
    p2 = "P2"
    p3 = "P3"
    p4 = "P4"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(20), unique=True, index=True)  # INC-00021
    title = Column(String(500), nullable=False)
    description = Column(Text)
    status = Column(SAEnum(IncidentStatus), default=IncidentStatus.new)
    priority = Column(SAEnum(IncidentPriority), default=IncidentPriority.p3)
    severity = Column(String(20))
    assigned_to = Column(String(255))
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    hostname = Column(String(255))
    username = Column(String(255))
    mitre_technique = Column(String(20))
    mitre_tactic = Column(String(100))
    risk_score = Column(Integer, default=0)
    alert_ids = Column(Text)
    timeline = Column(Text)  # JSON timeline of events
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    resolved_at = Column(DateTime(timezone=True))
