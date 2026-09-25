import uuid
from datetime import UTC, datetime, timedelta

from app.models import Category, Finding, FindingStatus, Scan, Scanner, ScanStatus, Severity


def project(client, name='Dashboard'):
    result = client.post('/api/projects', json={'name': name, 'repository': {'url': 'https://github.com/example/demo'}})
    assert result.status_code == 201
    return result.json()


def scan(db, p, day=0, status=ScanStatus.COMPLETED):
    item = Scan(project_id=uuid.UUID(p['id']), repository_id=uuid.UUID(p['repositories'][0]['id']),
                status=status, created_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=day))
    db.add(item)
    db.commit()
    return item


def finding(db, s, **values):
    fields = dict(project_id=s.project_id, scan_id=s.id, scanner=Scanner.TRIVY,
                  category=Category.DEPENDENCY, severity=Severity.HIGH, title='Example dependency',
                  rule_id='CVE-2026-0001', cve='CVE-2026-0001', cwe='CWE-79', file='requirements.txt',
                  fingerprint=str(uuid.uuid4()), extra={'package': 'example-package', 'installed_version': '1.0', 'fixed_version': '2.0'})
    fields.update(values)
    item = Finding(**fields)
    db.add(item)
    db.flush()
    return item


def test_summary_and_pages_use_latest_success_per_repository(client, db):
    p = project(client)
    old = scan(db, p)
    finding(db, old)
    current = scan(db, p, 1)
    newest = finding(db, current, scanner=Scanner.SEMGREP, category=Category.CODE, severity=Severity.CRITICAL)
    failed = scan(db, p, 2, ScanStatus.FAILED)
    finding(db, failed)
    db.commit()
    summary = client.get('/api/security-summary', params={'project_id': p['id']}).json()
    assert summary['total'] == 1
    assert summary['severity']['CRITICAL'] == summary['scanners']['semgrep'] == 1
    assert summary['scanners']['trivy'] == summary['severity']['HIGH'] == 0
    assert summary['scanned_repositories'] == summary['repository_count'] == 1
    assert summary['scan_count'] == 3
    assert summary['latest_runs'][0]['status'] == 'FAILED'
    assert summary['snapshots'][0]['id'] == str(current.id)
    page = client.get('/api/findings-page').json()
    assert [f['id'] for f in page['items']] == [str(newest.id)]
    assert client.get('/api/findings-page?scope=all').json()['total'] == 3
    assert client.get(f'/api/findings-page?scan_id={old.id}').json()['total'] == 1
    assert isinstance(client.get('/api/findings').json(), list)
    scan(db, p, 3)
    assert client.get('/api/security-summary').json()['total'] == 0
    assert client.get('/api/findings-page').json()['total'] == 0


def test_exact_counts_and_pagination_beyond_100(client, db):
    p = project(client)
    s = scan(db, p)
    for _ in range(106):
        finding(db, s)
    db.commit()
    assert client.get('/api/security-summary').json()['total'] == 106
    assert client.get('/api/security-summary').json()['severity']['HIGH'] == 106
    first = client.get('/api/findings-page?limit=100').json()
    second = client.get('/api/findings-page?limit=100&offset=100').json()
    assert first['total'] == second['total'] == 106
    assert len(first['items']) == 100 and len(second['items']) == 6
    assert not ({f['id'] for f in first['items']} & {f['id'] for f in second['items']})


def test_project_isolation_and_search_filters(client, db):
    p = project(client)
    other = project(client, 'Other')
    s = scan(db, p)
    other_scan = scan(db, other)
    matching = finding(db, s, title='Literal 50% under_score', status=FindingStatus.VERIFIED_FIXED,
                       line_start=2, line_end=4, evidence='[redacted]')
    finding(db, s, title='Literal 500 underXscore')
    finding(db, other_scan)
    db.commit()
    filters = {'project_id': p['id'], 'q': 'EXAMPLE-PACKAGE', 'scanner': 'trivy', 'category': 'dependency',
               'severity': 'HIGH', 'status': 'VERIFIED_FIXED'}
    response = client.get('/api/findings-page', params=filters)
    assert response.status_code == 200, response.text
    assert response.json()['total'] == 1
    for term in ['50%', 'under_', 'CVE-2026-0001', 'CWE-79', 'requirements.txt']:
        page = client.get('/api/findings-page', params={**filters, 'q': term}).json()
        assert page['total'] == 1
        assert page['items'][0]['id'] == str(matching.id)
    for term in ['50%', 'under_']:
        assert client.get('/api/findings-page', params={'q': term}).json()['total'] == 1
    detail = client.get(f'/api/findings/{matching.id}').json()
    assert detail['line_end'] == 4 and detail['evidence'] == '[redacted]'
    assert detail['metadata']['fixed_version'] == '2.0'
    assert client.get('/api/security-summary', params={'project_id': other['id']}).json()['total'] == 1
    assert client.get('/api/findings-page', params={'project_id': other['id'], 'scan_id': str(s.id)}).status_code == 404


def test_empty_and_invalid_scopes(client):
    p = project(client)
    summary = client.get('/api/security-summary', params={'project_id': p['id']}).json()
    assert summary['scanned_repositories'] == summary['total'] == 0
    assert summary['repository_count'] == 1
    for endpoint in ['security-summary', 'findings-page']:
        assert client.get(f'/api/{endpoint}?project_id={uuid.uuid4()}').status_code == 404
    for query in ['scope=wrong', 'limit=101', 'offset=-1', 'scanner=invalid', 'q=' + 'x' * 201]:
        assert client.get('/api/findings-page?' + query).status_code == 422


def test_scan_history_pagination(client, db):
    p = project(client)
    ids = [str(scan(db, p, day).id) for day in range(4)]
    first = client.get('/api/scans?limit=2').json()
    second = client.get('/api/scans?limit=2&offset=2').json()
    assert [s['id'] for s in first + second] == list(reversed(ids))
    assert client.get('/api/scans?offset=-1').status_code == 422
