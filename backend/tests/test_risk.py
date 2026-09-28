import uuid

from app.models import Category, Finding, Scanner, Severity
from app.risk import calculate, persist


def finding(**kw):
    return Finding(id=uuid.uuid4(), project_id=uuid.UUID(int=1), scan_id=uuid.UUID(int=2),
                   **{'severity': Severity.HIGH, 'scanner': Scanner.SEMGREP, 'category': Category.CODE,
                      'file': 'app.py', 'cwe': 'CWE-89', 'extra': {}, **kw})


def test_severity_is_preserved_and_secret_priority_explained():
    f = finding(scanner=Scanner.GITLEAKS, category=Category.SECRET, original_severity='high')
    persist([f])
    assert f.risk_score == 65 and f.priority == 'P1'
    assert f.severity == Severity.HIGH and f.original_severity == 'high'
    assert {r['factor'] for r in f.risk_details['reasons']} == {'severity', 'secret'}


def test_confirmation_requires_same_scan_file_and_cwe():
    f = finding()
    other = finding(scanner=Scanner.TRIVY)
    assert calculate(f, [f, other])['score'] == 60
    other.scan_id = uuid.uuid4()
    assert calculate(f, [f, other])['score'] == 50
    other.scan_id = f.scan_id
    other.cwe = None
    assert calculate(f, [f, other])['score'] == 50


def test_untrusted_cvss_values_never_change_score():
    for value in (True, '9.8', -1, 11, float('nan'), float('inf')):
        assert calculate(finding(extra={'cvss_score': value}))['score'] == 50
    assert calculate(finding(extra={'cvss_score': 10}))['score'] == 65


def test_ai_has_small_explicit_weight_and_score_is_capped():
    f = finding(severity=Severity.CRITICAL, category=Category.SECRET, extra={'cvss_score': 10})
    result = calculate(f, ai_related=True)
    assert result['score'] == 97 and result['priority'] == 'P0'
    assert result['reasons'][-1]['points'] == 2


def test_review_distinguishes_no_scan_clean_scan_and_failed_attempt(client, db):
    from app.models import Scan, ScanStatus
    project = client.post('/api/projects', json={'name': 'review-empty', 'repository': {'url': 'https://github.com/example/demo'}}).json()
    path = '/api/projects/' + project['id'] + '/security-review'
    assert client.get(path).json()['has_successful_scan'] is False
    repo_id = uuid.UUID(project['repositories'][0]['id'])
    db.add(Scan(project_id=uuid.UUID(project['id']), repository_id=repo_id, status=ScanStatus.COMPLETED))
    db.commit()
    clean = client.get(path).json()
    assert clean['has_successful_scan'] is True and clean['total'] == 0
    db.add(Scan(project_id=uuid.UUID(project['id']), repository_id=repo_id, status=ScanStatus.FAILED))
    db.commit()
    assert client.get(path).json()['previous_results'] is True
