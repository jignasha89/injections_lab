import uuid
import enum
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, Boolean, Float, Integer, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, DeclarativeBase


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
    CANCELLED = "cancelled"


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_url = Column(String(2048), nullable=False)
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    status = Column(String(20), default="pending", nullable=False)
    config_json = Column(JSON, default=dict)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    current_phase = Column(String(50), default="")
    error_message = Column(Text, default="")
    findings_count = Column(Integer, default=0)
    urls_crawled = Column(Integer, default=0)
    endpoints_discovered = Column(Integer, default=0)
    payloads_sent = Column(Integer, default=0)
    scan_duration = Column(Float, default=0.0)
    errors_count = Column(Integer, default=0)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    attack_surfaces = relationship("AttackSurface", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text, default="")
    severity = Column(String(20), default="info")
    cvss_score = Column(Float, default=0.0)
    cvss_vector = Column(String(256), default="")
    confidence = Column(String(20), default="low")
    vulnerability_id = Column(String(50), default="")
    cwe_id = Column(String(50), default="")
    injection_family = Column(String(100), default="")
    injection_subtype = Column(String(100), default="")
    affected_url = Column(String(2048), default="")
    affected_parameter = Column(String(512), default="")
    payload = Column(Text, default="")
    request_data = Column(JSON, default=dict)
    response_data = Column(JSON, default=dict)
    baseline_request = Column(JSON, default=dict)
    baseline_response = Column(JSON, default=dict)
    evidence_json = Column(JSON, default=dict)
    mitigation_text = Column(Text, default="")
    references_json = Column(JSON, default=list)
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")


class AttackSurface(Base):
    __tablename__ = "attack_surfaces"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    url = Column(String(2048), nullable=False)
    http_method = Column(String(10), default="GET")
    parameters_json = Column(JSON, default=list)
    form_fields_json = Column(JSON, default=list)
    headers_json = Column(JSON, default=dict)
    technology_json = Column(JSON, default=dict)
    element_type = Column(String(50), default="url")
    source_tool = Column(String(50), default="crawler")
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="attack_surfaces")


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    title = Column(String(512), nullable=False)
    format = Column(String(20), nullable=False)
    config_json = Column(JSON, default=dict)
    file_path = Column(String(1024), default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="reports")


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(256), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    api_key_hash = Column(String(256), default="")
    preferences_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", backref="user")
    configs = relationship("ScanConfig", backref="user")


class ScanConfig(Base):
    __tablename__ = "scan_configs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(256), nullable=False)
    config_json = Column(JSON, default=dict)
    is_default = Column(Boolean, default=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
