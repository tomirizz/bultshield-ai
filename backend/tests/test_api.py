import uuid

import pytest
from app.models import AIAnalysis, Category, Finding, FindingStatus, Fix, Project, Repository, Rescan, Scan, ScanJob, Scanner, ScanStatus, Severity, User
from sqlalchemy import func, inspect, select
from sqlalchemy.exc import IntegrityError


def make_project(client, name="Demo project"):
    response = client.post(
        "/api/projects",
        json={
            "name": name,
            "description": "Stage 2 persistence check",
            "repository": {"url": "https://github.com/example/demo.git", "default_branch": "main"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_migrations_create_all_tables_and_database_is_ready(client, engine):
    names = set(inspect(engine).get_table_names())
    assert {"users", "projects", "repositories", "scans", "findings", "ai_analyses", "fixes", "rescans", "scan_jobs", "alembic_version"} <= names
    assert client.get("/health/live").status_code == 200
    ready = client.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json()["database"] == "connected"
    assert ready.json()["ai_enabled"] is False


def test_project_and_repository_persist_across_requests(client, db):
    project = make_project(client)
    assert project["repositories"][0]["url"] == "https://github.com/example/demo"
    assert project["scan_count"] == project["finding_count"] == 0
    stored = client.get("/api/projects").json()
    assert stored[0]["id"] == project["id"]
    assert db.get(Project, uuid.UUID(project["id"])).name == "Demo project"
    stats = client.get("/api/overview").json()
    assert (stats["projects"], stats["repositories"], stats["scans"], stats["findings"]) == (1, 1, 0, 0)
    assert client.get(f"/api/projects/{project['id']}").json()["repositories"] == project["repositories"]


def test_duplicate_creation_is_atomic(client, db):
    make_project(client)
    response = client.post("/api/projects", json={"name": "Demo project", "repository": {"url": "https://github.com/other/repo"}})
    assert response.status_code == 409
    assert db.scalar(select(func.count()).select_from(Project)) == 1
    assert db.scalar(select(func.count()).select_from(Repository)) == 1
    assert db.scalar(select(func.count()).select_from(User)) == 1


def test_add_repository_and_reject_duplicate(client):
    project = make_project(client)
    path = f"/api/projects/{project['id']}/repositories"
    payload = {"url": "https://github.com/another/service", "default_branch": "develop"}
    assert client.post(path, json=payload).status_code == 201
    assert client.post(path, json=payload).status_code == 409
    assert len(client.get(path).json()) == 2


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://github.com.evil.example/a/b",
        "https://token@github.com/a/b",
        "https://github.com/a/b?token=secret",
        "http://github.com/a/b",
        "https://github.com/a/..",
    ],
)
def test_reject_non_repository_or_credential_urls(client, url):
    assert client.post("/api/projects", json={"name": "invalid", "repository": {"url": url}}).status_code == 422
    assert client.get("/api/overview").json()["projects"] == 0


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "   "},
        {"name": "x", "target_url": "javascript:alert(1)"},
        {"name": "x", "target_url": "https://user:password@staging.example.com"},
        {"name": "x", "repository": {"url": "https://github.com/a/b", "default_branch": "--upload-pack=evil"}},
    ],
)
def test_reject_invalid_project_fields(client, payload):
    assert client.post("/api/projects", json=payload).status_code == 422


def test_missing_project_and_unknown_api_are_404(client):
    assert client.get(f"/api/projects/{uuid.uuid4()}").status_code == 404
    assert client.get("/api/does-not-exist").status_code == 404
    assert client.get("/api/projects?limit=50000").status_code == 422


def test_scan_is_queued_without_fake_results(client, db):
    project = make_project(client)
    repository_id = project["repositories"][0]["id"]

    response = client.post(
        "/api/scans",
        json={"repository_id": repository_id},
    )
    assert response.status_code == 202, response.text
    scan = response.json()
    assert scan["status"] == "QUEUED"
    assert scan["project_id"] == project["id"]
    assert scan["repository_id"] == repository_id

    job = db.scalar(
        select(ScanJob).where(
            ScanJob.scan_id == uuid.UUID(scan["id"])
        )
    )
    assert job is not None
    assert job.status == "QUEUED"

    duplicate = client.post(
        "/api/scans",
        json={"repository_id": repository_id},
    )
    assert duplicate.status_code == 409
    assert client.get("/api/overview").json()["scans"] == 1
    assert db.scalar(select(func.count()).select_from(ScanJob)) == 1

    for endpoint in ["findings", "ai-analyses", "fixes", "rescans"]:
        assert client.get(f"/api/{endpoint}").json() == []

    assert client.post(
        "/api/rescans",
        json={"original_scan_id": scan["id"]},
    ).status_code == 501


def test_scan_rejects_missing_repository(client):
    response = client.post(
        "/api/scans",
        json={"repository_id": str(uuid.uuid4())},
    )
    assert response.status_code == 404
    assert client.get("/api/scans").json() == []


def test_findings_contract_filters_and_related_records(client, db):
    project = make_project(client)
    scan = Scan(project_id=uuid.UUID(project["id"]), repository_id=uuid.UUID(project["repositories"][0]["id"]), status=ScanStatus.COMPLETED)
    db.add(scan)
    db.flush()
    finding = Finding(
        project_id=scan.project_id,
        scan_id=scan.id,
        scanner=Scanner.SEMGREP,
        category=Category.CODE,
        title="Test finding",
        description="Synthetic test fixture",
        severity=Severity.HIGH,
        original_severity="ERROR",
        rule_id="test-rule",
        fingerprint="test-fingerprint",
        evidence="redacted fixture",
        status=FindingStatus.OPEN,
        extra={"test": True},
    )
    db.add(finding)
    db.flush()
    analysis = AIAnalysis(finding_id=finding.id, model="test-only", status="COMPLETED", explanation="fixture")
    db.add(analysis)
    db.flush()
    fix = Fix(finding_id=finding.id, analysis_id=analysis.id, description="fixture")
    next_scan = Scan(project_id=scan.project_id, repository_id=scan.repository_id)
    db.add_all([fix, next_scan])
    db.flush()
    db.add(Rescan(project_id=scan.project_id, original_scan_id=scan.id, verification_scan_id=next_scan.id, finding_id=finding.id))
    db.commit()
    result = client.get("/api/findings?severity=HIGH&scanner=semgrep&status=OPEN")
    assert result.status_code == 200
    assert result.json()[0]["metadata"] == {"test": True}
    assert result.json()[0]["original_severity"] == "ERROR"
    assert client.get("/api/findings?severity=LOW").json() == []
    assert client.get(f"/api/findings/{finding.id}").json()["scan_id"] == str(scan.id)
    assert len(client.get(f"/api/ai-analyses?finding_id={finding.id}").json()) == 1
    assert len(client.get(f"/api/fixes?finding_id={finding.id}").json()) == 1
    assert len(client.get(f"/api/rescans?project_id={project['id']}").json()) == 1


def test_database_rejects_cross_project_scan_reference(client, db):
    first = make_project(client, "First")
    second = make_project(client, "Second")
    db.add(Scan(project_id=uuid.UUID(first["id"]), repository_id=uuid.UUID(second["repositories"][0]["id"])))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_database_enforces_finding_severity_and_status(client, db):
    project = make_project(client)
    scan = Scan(project_id=uuid.UUID(project["id"]), repository_id=uuid.UUID(project["repositories"][0]["id"]))
    db.add(scan)
    db.flush()
    db.add(
        Finding(
            project_id=scan.project_id,
            scan_id=scan.id,
            scanner=Scanner.TRIVY,
            category=Category.DEPENDENCY,
            title="Fixture",
            severity="INVALID",
            rule_id="test",
            fingerprint="test",
        )
    )
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_openapi_and_security_headers(client):
    result = client.get("/api/openapi.json")
    assert result.status_code == 200
    assert result.json()["info"]["version"] == "0.7.0"
    assert result.headers["x-content-type-options"] == "nosniff"
    assert result.headers["cache-control"] == "no-store"
    assert "/api/projects" in result.json()["paths"]
