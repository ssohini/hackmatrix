from sqlalchemy import Column, Integer, String, Text, DateTime, Float
from sqlalchemy.sql import func
from .database import Base


class Investigation(Base):
    __tablename__ = "investigations"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), nullable=False)
    hostname = Column(String(255), index=True)
    score = Column(Integer, nullable=False)
    verdict = Column(String(32), nullable=False)
    signals_json = Column(Text, default="[]")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ThreatReport(Base):
    __tablename__ = "threat_reports"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), nullable=False)
    hostname = Column(String(255), index=True)
    report_type = Column(String(64), default="phishing")
    description = Column(Text, default="")
    reporter = Column(String(128), default="anonymous")
    votes = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class CertificateRecord(Base):
    __tablename__ = "certificates"
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), index=True)
    issuer = Column(String(512), default="")
    subject = Column(String(512), default="")
    not_before = Column(String(64), default="")
    not_after = Column(String(64), default="")
    key_type = Column(String(32), default="")
    key_size = Column(Integer, default=0)
    serial = Column(String(128), default="")
    fingerprint = Column(String(128), default="")
    is_valid = Column(Integer, default=0)
    issues_json = Column(Text, default="[]")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
