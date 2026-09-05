from sqlalchemy import Column, Integer, String, DateTime, Text, Enum as SAEnum
from sqlalchemy.sql import func
from database.database import Base
import enum


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), index=True)
    username = Column(String(255), index=True)
    event_type = Column(String(100), nullable=False, index=True)
    action = Column(String(100))
    status = Column(String(50))
    hostname = Column(String(255))
    severity = Column(SAEnum(Severity), default=Severity.low)
    raw_log = Column(Text)
    source_type = Column(String(50), index=True)  # windows, linux, nginx, firewall
    created_at = Column(DateTime(timezone=True), server_default=func.now())
