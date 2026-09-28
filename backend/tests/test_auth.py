import uuid
from datetime import timedelta

import pytest
from app.auth import COOKIE, digest, now
from app.config import get_settings
from app.main import create_app
from app.models import AIAnalysis, Category, Finding, LoginSession, Project, Repository, Scan, Scanner, Severity, User
from app.tenant import isolate
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session


@pytest.fixture
def accounts(db):
    users = [User(display_name='one'), User(display_name='two')]
    db.add_all(users)
    db.flush()
    projects = [Project(owner_id=u.id, name='private project') for u in users]
    db.add_all(projects)
    db.flush()
    repositories = [Repository(project_id=p.id, url='https://github.com/example/demo', default_branch='main') for p in projects]
    db.add_all(repositories)
    db.flush()
    scans = [Scan(project_id=p.id, repository_id=r.id) for p, r in zip(projects, repositories)]
    db.add_all(scans)
    db.flush()
    findings = [Finding(project_id=p.id, scan_id=s.id, scanner=Scanner.SEMGREP, category=Category.CODE,
        title='private finding', severity=Severity.HIGH, rule_id='r', fingerprint='f') for p, s in zip(projects, scans)]
    db.add_all(findings)
    db.flush()
    db.add_all([AIAnalysis(finding_id=f.id, model='private') for f in findings])
    db.add(LoginSession(user_id=users[0].id, token_hash=digest('test-session'), expires_at=now() + timedelta(hours=1)))
    db.commit()
    return users, projects, repositories, scans, findings


def test_tenant_filters_aggregates_nested_queries_and_children(engine, accounts):
    users, projects, _, _, findings = accounts
    with Session(engine) as scoped:
        isolate(scoped, users[0].id)
        assert scoped.scalar(select(func.count()).select_from(Project)) == 1
        assert scoped.get(Project, projects[1].id) is None
        assert scoped.get(Finding, findings[1].id) is None
        assert len(scoped.scalars(select(AIAnalysis)).all()) == 1
        nested = select(Finding.id).subquery()
        assert scoped.scalar(select(func.count()).select_from(nested)) == 1


def test_auth_and_cross_tenant_endpoints(monkeypatch, accounts):
    users, projects, repos, scans, findings = accounts
    monkeypatch.setattr(get_settings(), 'auth_enabled', True)
    with TestClient(create_app(), base_url=get_settings().public_url) as client:
        assert client.get('/api/projects').status_code == 401
        assert client.get('/health/live').status_code == 200
        client.cookies.set(COOKIE, 'test-session')
        assert len(client.get('/api/projects').json()) == 1
        assert len(client.get('/api/ai-analyses').json()) == 1
        assert client.get('/api/overview').json()['findings'] == 1
        for path in (f'/projects/{projects[1].id}', f'/findings/{findings[1].id}',
                     f'/projects/{projects[1].id}/security-review', f'/findings/{findings[1].id}/fix',
                     f'/projects/{projects[1].id}/targets'):
            assert client.get('/api' + path).status_code == 404, path
        assert client.get(f'/api/findings?scan_id={scans[1].id}').json() == []
        assert client.post('/api/scans', json={'repository_id': str(repos[0].id)}).status_code == 403
        assert client.post('/api/scans', headers={'Origin': get_settings().public_url}, json={'repository_id': str(repos[1].id)}).status_code == 404
        created = client.post('/api/projects', headers={'Origin': get_settings().public_url}, json={'name': 'mine'})
        assert created.status_code == 201
        with Session(get_settings_engine()) as session:
            assert session.get(Project, uuid.UUID(created.json()['id'])).owner_id == users[0].id


def get_settings_engine():
    from app.database import get_engine
    return get_engine()


def test_oauth_callback_rejects_unbound_state(client):
    assert client.get('/api/auth/callback?state=attacker&code=code').status_code == 400


@pytest.mark.parametrize("separate_key", [True, False])
def test_oauth_pkce_callback_encrypts_token_and_consumes_state(monkeypatch, db, separate_key):
    from urllib.parse import parse_qs, urlsplit

    from app import auth
    from app.models import GithubIdentity, OAuthState
    from cryptography.fernet import Fernet
    settings = get_settings()
    key = Fernet.generate_key()
    for name, value in {'auth_enabled': True, 'github_client_id': 'test-client', 'github_client_secret': 'test-secret',
                        'github_token_key': key.decode() if separate_key else '', 'legacy_owner_github_id': '12345'}.items():
        monkeypatch.setattr(settings, name, value)
    def github(path, token=None, data=None):
        if path == '/login/oauth/access_token':
            assert data['code_verifier'] and data['redirect_uri'] == settings.public_url + '/api/auth/callback'
            return {'access_token': 'synthetic-oauth-value', 'expires_in': 3600}
        assert token == 'synthetic-oauth-value'
        return {'id': 12345, 'login': 'demo'}
    monkeypatch.setattr(auth, 'github_request', github)
    with TestClient(create_app(), base_url=settings.public_url) as client:
        start = client.get('/api/auth/github', follow_redirects=False)
        params = parse_qs(urlsplit(start.headers['location']).query)
        assert params['code_challenge_method'] == ['S256']
        assert params['scope'] == ['read:user public_repo']
        state = params['state'][0]
        done = client.get('/api/auth/callback', params={'state': state, 'code': 'synthetic-code'}, follow_redirects=False)
        assert done.status_code == 303
        assert 'HttpOnly' in done.headers['set-cookie'] and 'Secure' in done.headers['set-cookie']
        assert client.get('/api/auth/status').json()['authenticated'] is True
        assert client.get('/api/auth/callback', params={'state': state, 'code': 'synthetic-code'}).status_code == 400
        identity = db.scalar(select(GithubIdentity))
        assert identity.user_id == auth.LEGACY_OWNER
        assert identity.encrypted_token != 'synthetic-oauth-value'
        assert auth.token_cipher().decrypt(identity.encrypted_token.encode()) == b'synthetic-oauth-value'
        assert db.scalar(select(OAuthState)) is None
        client.post('/api/auth/logout', headers={'Origin': settings.public_url}, follow_redirects=False)
        assert client.get('/api/projects').status_code == 401


def test_production_cannot_disable_auth(monkeypatch):
    monkeypatch.setattr(get_settings(), 'app_env', 'production')
    monkeypatch.setattr(get_settings(), 'auth_enabled', False)
    with TestClient(create_app()) as client:
        assert client.get('/api/projects').status_code == 401
        assert client.get('/api/auth/status').json()['enabled'] is True
