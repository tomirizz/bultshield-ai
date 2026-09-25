import enum
import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    metadata = sa.MetaData(
        naming_convention={
            "ix": "ix_%(table_name)s_%(column_0_name)s",
            "uq": "uq_%(table_name)s_%(column_0_N_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )


class Record:
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())


class ScanStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    CLONING = "CLONING"
    SCANNING = "SCANNING"
    ANALYSING = "ANALYSING"
    NORMALIZING = "NORMALIZING"  # Historical scans remain readable.
    AI_ANALYSIS = "AI_ANALYSIS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    AI_ANALYZED = "AI_ANALYZED"
    FIX_PROPOSED = "FIX_PROPOSED"
    FIX_APPLIED = "FIX_APPLIED"
    RECHECKING = "RECHECKING"
    VERIFIED_FIXED = "VERIFIED_FIXED"
    STILL_DETECTED = "STILL_DETECTED"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class Scanner(str, enum.Enum):
    GITLEAKS = "gitleaks"
    SEMGREP = "semgrep"
    TRIVY = "trivy"
    NUCLEI = "nuclei"


class Category(str, enum.Enum):
    SECRET = "secret"
    CODE = "code"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"
    WEB = "web"


def enum_type(cls, name):
    return sa.Enum(cls, name=name, native_enum=False, create_constraint=True, values_callable=lambda values: [item.value for item in values])


class User(Record, Base):
    __tablename__ = "users"
    display_name: Mapped[str] = mapped_column(sa.String(100))
    email: Mapped[str | None] = mapped_column(sa.String(254), unique=True)


class Project(Record, Base):
    __tablename__ = "projects"
    __table_args__ = (sa.UniqueConstraint("owner_id", "name"),)
    owner_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(sa.String(100))
    description: Mapped[str] = mapped_column(sa.String(1000), default="", server_default="")
    target_url: Mapped[str | None] = mapped_column(sa.String(2048))
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now())


class Repository(Record, Base):
    __tablename__ = "repositories"
    __table_args__ = (sa.UniqueConstraint("project_id", "url"), sa.UniqueConstraint("project_id", "id"))
    project_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(sa.String(512))
    default_branch: Mapped[str] = mapped_column(sa.String(200), default="main", server_default="main")


class Scan(Record, Base):
    __tablename__ = "scans"
    __table_args__ = (
        sa.ForeignKeyConstraint(["project_id", "repository_id"], ["repositories.project_id", "repositories.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("project_id", "id"),
    )
    project_id: Mapped[uuid.UUID] = mapped_column(index=True)
    repository_id: Mapped[uuid.UUID]
    status: Mapped[ScanStatus] = mapped_column(enum_type(ScanStatus, "scan_status"), default=ScanStatus.QUEUED, server_default="QUEUED", index=True)
    current_step: Mapped[str | None] = mapped_column(sa.String(32))
    error_code: Mapped[str | None] = mapped_column(sa.String(64))
    commit_sha: Mapped[str | None] = mapped_column(sa.String(64))
    target_url: Mapped[str | None] = mapped_column(sa.String(2048))
    scanner_config: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=sa.text("'{}'::jsonb"))
    scanner_results: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=sa.text("'{}'::jsonb"))
    started_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(sa.Text)


class Finding(Record, Base):
    __tablename__ = "findings"
    __table_args__ = (
        sa.ForeignKeyConstraint(["project_id", "scan_id"], ["scans.project_id", "scans.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("scan_id", "scanner", "fingerprint"),
        sa.UniqueConstraint("project_id", "id"),
        sa.CheckConstraint("line_start IS NULL OR line_start > 0", name="positive_line"),
        sa.CheckConstraint("line_end IS NULL OR (line_start IS NOT NULL AND line_end >= line_start)", name="line_range"),
    )
    project_id: Mapped[uuid.UUID] = mapped_column(index=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(index=True)
    scanner: Mapped[Scanner] = mapped_column(enum_type(Scanner, "scanner"))
    category: Mapped[Category] = mapped_column(enum_type(Category, "category"))
    title: Mapped[str] = mapped_column(sa.String(300))
    description: Mapped[str] = mapped_column(sa.Text, default="", server_default="")
    severity: Mapped[Severity] = mapped_column(enum_type(Severity, "severity"), index=True)
    original_severity: Mapped[str | None] = mapped_column(sa.String(50))
    file: Mapped[str | None] = mapped_column(sa.String(2048))
    line_start: Mapped[int | None]
    line_end: Mapped[int | None]
    rule_id: Mapped[str] = mapped_column(sa.String(300))
    cwe: Mapped[str | None] = mapped_column(sa.String(64))
    cve: Mapped[str | None] = mapped_column(sa.String(64))
    evidence: Mapped[str] = mapped_column(sa.Text, default="", server_default="")
    status: Mapped[FindingStatus] = mapped_column(enum_type(FindingStatus, "finding_status"), default=FindingStatus.OPEN, server_default="OPEN", index=True)
    fingerprint: Mapped[str] = mapped_column(sa.String(128), index=True)
    extra: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, server_default=sa.text("'{}'::jsonb"))


class AIAnalysis(Record, Base):
    __tablename__ = "ai_analyses"
    __table_args__ = (sa.UniqueConstraint("finding_id", "id"),)
    finding_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    model: Mapped[str] = mapped_column(sa.String(200))
    status: Mapped[str] = mapped_column(
        sa.Enum("PENDING", "RUNNING", "COMPLETED", "FAILED", name="analysis_status", native_enum=False, create_constraint=True),
        default="PENDING",
        server_default="PENDING",
    )
    started_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    result: Mapped[dict | None] = mapped_column(JSONB)
    explanation: Mapped[str | None] = mapped_column(sa.Text)
    recommended_fix: Mapped[str | None] = mapped_column(sa.Text)
    error_message: Mapped[str | None] = mapped_column(sa.Text)


class Fix(Record, Base):
    __tablename__ = "fixes"
    __table_args__ = (sa.ForeignKeyConstraint(["finding_id", "analysis_id"], ["ai_analyses.finding_id", "ai_analyses.id"]),)
    finding_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    analysis_id: Mapped[uuid.UUID | None]
    description: Mapped[str] = mapped_column(sa.Text)
    diff: Mapped[str | None] = mapped_column(sa.Text)
    status: Mapped[str] = mapped_column(
        sa.Enum("PROPOSED", "APPLIED", name="fix_status", native_enum=False, create_constraint=True), default="PROPOSED", server_default="PROPOSED"
    )
    applied_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))


class Rescan(Record, Base):
    __tablename__ = "rescans"
    __table_args__ = (
        sa.ForeignKeyConstraint(["project_id", "original_scan_id"], ["scans.project_id", "scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id", "verification_scan_id"], ["scans.project_id", "scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id", "finding_id"], ["findings.project_id", "findings.id"], ondelete="CASCADE"),
        sa.CheckConstraint("original_scan_id <> verification_scan_id", name="different_scans"),
    )
    project_id: Mapped[uuid.UUID] = mapped_column(index=True)
    original_scan_id: Mapped[uuid.UUID]
    verification_scan_id: Mapped[uuid.UUID]
    finding_id: Mapped[uuid.UUID | None]
    outcome: Mapped[str | None] = mapped_column(
        sa.Enum("VERIFIED_FIXED", "STILL_DETECTED", "INCONCLUSIVE", name="rescan_outcome", native_enum=False, create_constraint=True)
    )


class ScanJob(Record, Base):
    __tablename__ = "scan_jobs"
    scan_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("scans.id", ondelete="CASCADE"), unique=True)
    status: Mapped[str] = mapped_column(
        sa.Enum("QUEUED", "RUNNING", "COMPLETED", "FAILED", name="job_status", native_enum=False, create_constraint=True),
        default="QUEUED",
        server_default="QUEUED",
        index=True,
    )
    worker_id: Mapped[str | None] = mapped_column(sa.String(64))
    attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    locked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
