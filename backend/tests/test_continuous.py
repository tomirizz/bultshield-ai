from app.continuous import compare
from app.models import Category, Finding, Scanner


def f(line=1, version='1.0', rule='CVE-2025-0001'):
    return Finding(scanner=Scanner.TRIVY, category=Category.DEPENDENCY, file='requirements.txt', rule_id=rule,
        cve=rule, line_start=line, extra={'package': 'example', 'ecosystem': 'pip', 'installed_version': version})


def test_comparison_ignores_line_and_version_but_preserves_occurrence_counts():
    result = compare([f(), f()], [f(line=40, version='1.1')])
    assert result == {'new': 0, 'fixed': 1, 'unchanged': 1}
    assert compare([f()], [f(rule='CVE-2025-0002')]) == {'new': 1, 'fixed': 1, 'unchanged': 0}


def test_poll_queues_exact_commit_and_does_not_repeat(client, db, monkeypatch):
    from app import continuous
    from app.models import Repository, Scan, ScanJob
    from sqlalchemy import select
    project = client.post('/api/projects', json={'name': 'poll', 'repository': {'url': 'https://github.com/example/demo', 'default_branch': 'main'}}).json()
    repo_id = project['repositories'][0]['id']
    import uuid
    repo = db.get(Repository, uuid.UUID(repo_id))
    repo.continuous_enabled = True
    db.commit()
    monkeypatch.setattr(continuous, 'github_request', lambda path: {'sha': 'a' * 40})
    continuous.poll_once()
    scan = db.scalar(select(Scan))
    assert scan.scanner_config['requested_commit'] == 'a' * 40
    assert db.scalar(select(ScanJob)).status == 'QUEUED'
    continuous.poll_once()
    assert len(db.scalars(select(Scan)).all()) == 1
