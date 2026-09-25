import re
from datetime import datetime
from typing import Annotated
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import Category, FindingStatus, Scanner, ScanStatus, Severity


class Schema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class RepositoryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    url: str = Field(max_length=512)
    default_branch: str = Field(default="main", min_length=1, max_length=200)

    @field_validator("url")
    @classmethod
    def github_repository(cls, value: str) -> str:
        match = re.fullmatch(r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_.-]+)/?", value)
        if not match:
            raise ValueError("Укажите HTTPS URL репозитория: https://github.com/owner/repo")
        owner, repo = match.groups()
        repo = repo.removesuffix(".git")
        if not repo or repo in {".", ".."}:
            raise ValueError("Неверное имя репозитория")
        return f"https://github.com/{owner}/{repo}"

    @field_validator("default_branch")
    @classmethod
    def branch_name(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value) or ".." in value or value.endswith(("/", ".")):
            raise ValueError("Укажите корректное имя ветки")
        return value


class ProjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)
    target_url: str | None = Field(default=None, max_length=2048)
    repository: RepositoryCreate | None = None

    @field_validator("target_url")
    @classmethod
    def clean_target(cls, value: str | None) -> str | None:
        if not value:
            return None
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.fragment:
            raise ValueError("Укажите HTTP(S) URL без пароля и фрагмента")
        return value


class RepositoryOut(Schema):
    id: UUID
    project_id: UUID
    url: str
    default_branch: str
    created_at: datetime


class ProjectOut(Schema):
    id: UUID
    name: str
    description: str
    target_url: str | None
    created_at: datetime
    updated_at: datetime
    repositories: list[RepositoryOut] = Field(default_factory=list)
    scan_count: int = 0
    finding_count: int = 0


class ScanOut(Schema):
    id: UUID
    project_id: UUID
    repository_id: UUID
    status: ScanStatus
    current_step: str | None
    error_code: str | None
    commit_sha: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    scanner_config: dict
    scanner_results: dict


class FindingOut(Schema):
    id: UUID
    project_id: UUID
    scan_id: UUID
    scanner: Scanner
    category: Category
    title: str
    description: str
    severity: Severity
    original_severity: str | None
    file: str | None
    line_start: int | None
    line_end: int | None
    rule_id: str
    cwe: str | None
    cve: str | None
    evidence: str
    status: FindingStatus
    fingerprint: str
    metadata: dict = Field(validation_alias="extra")
    created_at: datetime


class AIAnalysisOut(Schema):
    result: dict | None
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    id: UUID
    finding_id: UUID
    model: str
    status: str
    explanation: str | None
    recommended_fix: str | None
    created_at: datetime


class FixOut(Schema):
    id: UUID
    finding_id: UUID
    analysis_id: UUID | None
    description: str
    diff: str | None
    status: str
    applied_at: datetime | None
    created_at: datetime


class RescanOut(Schema):
    id: UUID
    project_id: UUID
    original_scan_id: UUID
    verification_scan_id: UUID
    finding_id: UUID | None
    outcome: str | None
    created_at: datetime


class ScanRequest(BaseModel):
    repository_id: UUID


class RescanRequest(BaseModel):
    original_scan_id: UUID


PageLimit = Annotated[int, Field(ge=1, le=100)]
