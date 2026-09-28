"""GitHub OAuth with PKCE, one-use state and server-side expiring sessions."""
import base64
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, build_opener
from urllib.request import Request as URLRequest

from cryptography.fernet import Fernet
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_engine
from .models import AuditEvent, GithubIdentity, LoginSession, OAuthState, User

router = APIRouter(prefix='/api/auth')
COOKIE = '__Host-bultshield'
STATE_COOKIE = '__Host-bultshield-oauth'
LEGACY_OWNER = uuid.UUID('00000000-0000-4000-8000-000000000001')


def now():
    return datetime.now(timezone.utc)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def configured():
    s = get_settings()
    return bool(s.github_client_id and s.github_client_secret)


def token_cipher():
    s = get_settings()
    key = s.github_token_key.encode() if s.github_token_key else base64.urlsafe_b64encode(
        hashlib.sha256(b'BultShield OAuth storage v1\0' + s.github_client_secret.encode()).digest())
    if not s.github_client_secret:
        raise ValueError('OAuth is not configured')
    return Fernet(key)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def github_request(path, token=None, data=None, method=None, missing_ok=False):
    url = 'https://api.github.com' + path
    if path == '/login/oauth/access_token':
        url = 'https://github.com' + path
    headers = {'Accept': 'application/json', 'User-Agent': 'BultShield', 'X-GitHub-Api-Version': '2022-11-28'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    body = json.dumps(data).encode() if data is not None else None
    if body:
        headers['Content-Type'] = 'application/json'
    try:
        with build_opener(NoRedirect).open(URLRequest(url, data=body, headers=headers, method=method), timeout=20) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError('response size')
        return json.loads(raw)
    except HTTPError as exc:
        if missing_ok and exc.code == 404:
            return None
        raise HTTPException(502, 'GitHub отклонил запрос. Проверьте доступ и повторите подключение.') from None
    except (URLError, TimeoutError, ValueError):
        raise HTTPException(502, 'GitHub временно недоступен или отклонил запрос. Повторите подключение.') from None


def session_user(request):
    value = request.cookies.get(COOKIE, '')
    if not value or len(value) > 128:
        return None
    with Session(get_engine()) as db:
        return db.scalar(select(LoginSession.user_id).where(LoginSession.token_hash == digest(value), LoginSession.expires_at > now()))


@router.get('/status')
def status(request: Request):
    enabled = get_settings().authentication_required
    return {'enabled': enabled, 'configured': configured(), 'authenticated': bool(session_user(request)) if enabled else True}


@router.get('/github')
def login():
    if not configured():
        raise HTTPException(503, 'GitHub OAuth ещё не настроен администратором.')
    s = get_settings()
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    with Session(get_engine()) as db, db.begin():
        db.execute(delete(OAuthState).where(OAuthState.expires_at < now()))
        db.add(OAuthState(token_hash=digest(state), verifier=verifier, expires_at=now() + timedelta(minutes=10)))
    response = RedirectResponse('https://github.com/login/oauth/authorize?' + urlencode({
        'client_id': s.github_client_id, 'redirect_uri': s.public_url + '/api/auth/callback',
        'scope': 'read:user public_repo', 'state': state, 'code_challenge': challenge, 'code_challenge_method': 'S256'}))
    response.set_cookie(STATE_COOKIE, state, secure=True, httponly=True, samesite='lax', max_age=600, path='/')
    return response


@router.get('/callback')
def callback(request: Request, state: str = '', code: str = ''):
    cookie = request.cookies.get(STATE_COOKIE, '')
    if not state or len(state) > 128 or not secrets.compare_digest(state, cookie) or not code or len(code) > 512:
        raise HTTPException(400, 'Недействительный запрос входа. Начните вход заново.')
    with Session(get_engine()) as db, db.begin():
        pending = db.scalar(select(OAuthState).where(OAuthState.token_hash == digest(state), OAuthState.expires_at > now()).with_for_update())
        if pending is None:
            raise HTTPException(400, 'Время входа истекло. Начните заново.')
        verifier = pending.verifier
        db.delete(pending)
    s = get_settings()
    result = github_request('/login/oauth/access_token', data={'client_id': s.github_client_id,
        'client_secret': s.github_client_secret, 'code': code, 'code_verifier': verifier,
        'redirect_uri': s.public_url + '/api/auth/callback'})
    token = result.get('access_token')
    if not isinstance(token, str) or not token or len(token) > 1024:
        raise HTTPException(400, 'GitHub не подтвердил вход.')
    profile = github_request('/user', token)
    github_id = str(profile.get('id', ''))
    if not github_id.isdigit() or not isinstance(profile.get('login'), str):
        raise HTTPException(502, 'Некорректный профиль GitHub.')
    raw_session = secrets.token_urlsafe(48)
    expires_in = result.get('expires_in', 43200)
    lifetime = min(43200, max(60, expires_in)) if type(expires_in) is int else 43200
    with Session(get_engine()) as db, db.begin():
        identity = db.scalar(select(GithubIdentity).where(GithubIdentity.github_id == github_id))
        encrypted = token_cipher().encrypt(token.encode()).decode()
        if identity is None:
            user_id = LEGACY_OWNER if s.legacy_owner_github_id == github_id else uuid.uuid4()
            user = db.get(User, user_id)
            if user is None:
                db.add(User(id=user_id, display_name=profile['login'][:100]))
                db.flush()
            identity = GithubIdentity(user_id=user_id, github_id=github_id, login=profile['login'][:100], encrypted_token=encrypted)
            db.add(identity)
        else:
            identity.encrypted_token = encrypted
        db.execute(delete(LoginSession).where(LoginSession.expires_at < now()))
        db.add(LoginSession(user_id=identity.user_id, token_hash=digest(raw_session), expires_at=now() + timedelta(seconds=lifetime)))
        db.add(AuditEvent(user_id=identity.user_id, action='login', outcome='success'))
    response = RedirectResponse('/#/projects', status_code=303)
    response.delete_cookie(STATE_COOKIE, secure=True, httponly=True, path='/')
    response.set_cookie(COOKIE, raw_session, secure=True, httponly=True, samesite='lax', max_age=lifetime, path='/')
    return response


@router.post('/logout')
def logout(request: Request):
    if request.headers.get('origin') != get_settings().public_url:
        raise HTTPException(403, 'Недопустимый источник запроса.')
    with Session(get_engine()) as db, db.begin():
        db.execute(delete(LoginSession).where(LoginSession.token_hash == digest(request.cookies.get(COOKIE, ''))))
    response = RedirectResponse('/', status_code=303)
    response.delete_cookie(COOKIE, secure=True, httponly=True, path='/')
    return response
