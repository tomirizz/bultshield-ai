"""Public-repository picker and explicit creation of a reviewed fix branch."""
import base64
import uuid
from typing import Annotated
from urllib.parse import quote, urlsplit

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import github_request, token_cipher
from .database import get_session
from .models import AuditEvent, Finding, Fix, GithubIdentity, Repository, Scan

router = APIRouter(prefix='/api/github')
DB = Annotated[Session, Depends(get_session)]


def credential(db):
    owner = db.info.get('owner_id')
    if owner is None:
        raise HTTPException(401, 'Для GitHub integration включите вход через GitHub.')
    identity = db.scalar(select(GithubIdentity).where(GithubIdentity.user_id == owner))
    if identity is None:
        raise HTTPException(401, 'Подключите GitHub заново.')
    try:
        return token_cipher().decrypt(identity.encrypted_token.encode()).decode()
    except (InvalidToken, ValueError):
        raise HTTPException(503, 'Не удалось открыть подключение GitHub. Обратитесь к администратору.') from None


@router.get('/repositories')
def repositories(db: DB, page: int = 1):
    if not 1 <= page <= 100:
        raise HTTPException(422, 'Некорректная страница.')
    data = github_request(f'/user/repos?visibility=public&affiliation=owner,collaborator&sort=updated&per_page=30&page={page}', credential(db))
    return {'items': [{'name': r['full_name'], 'url': r['html_url'], 'branch': r['default_branch'],
                       'can_push': bool(r.get('permissions', {}).get('push'))} for r in data if not r.get('private')],
            'page': page, 'has_more': len(data) == 30}


@router.post('/fixes/{fix_id}/branch')
def fix_branch(fix_id: uuid.UUID, db: DB):
    token = credential(db)
    fix = db.scalar(select(Fix).where(Fix.id == fix_id).with_for_update())
    if fix is None:
        raise HTTPException(404, 'Исправление не найдено.')
    if not fix.approved_at or fix.status not in ('VERIFIED_FIXED', 'STILL_DETECTED') or not fix.proposed or not fix.file:
        raise HTTPException(409, 'Сначала одобрите исправление и дождитесь повторной проверки.')
    f = db.get(Finding, fix.finding_id)
    scan = db.get(Scan, f.scan_id)
    repo = db.get(Repository, scan.repository_id)
    slug = urlsplit(repo.url).path.strip('/').removesuffix('.git')
    branch = 'bultshield/fix-' + fix.id.hex
    api_path = '/repos/' + slug
    remote = github_request(api_path, token)
    if remote.get('private') or not remote.get('permissions', {}).get('push'):
        raise HTTPException(403, 'Нужен доступ на запись к публичному репозиторию.')
    source = github_request(api_path + '/contents/' + quote(fix.file, safe='/') + '?ref=' + quote(fix.base_sha, safe=''), token)
    if source.get('type') != 'file':
        raise HTTPException(409, 'Исходный файл недоступен.')
    import hashlib
    try:
        original = base64.b64decode(source.get('content', ''), validate=False)
    except ValueError:
        raise HTTPException(409, 'Исходный файл недоступен.') from None
    if hashlib.sha256(original).hexdigest() != fix.original_hash:
        raise HTTPException(409, 'Исходный файл изменился; создайте новое исправление.')
    existing = github_request(api_path + '/git/ref/heads/' + quote(branch, safe='/'), token, missing_ok=True)
    if existing:
        current = github_request(api_path + '/contents/' + quote(fix.file, safe='/') + '?ref=' + quote(branch, safe=''), token)
        if base64.b64decode(current.get('content', '')).decode('utf-8') == fix.proposed:
            return {'branch': branch, 'commit_sha': existing['object']['sha'], 'url': repo.url.removesuffix('.git') + '/tree/' + branch}
        if existing.get('object', {}).get('sha') != fix.base_sha:
            raise HTTPException(409, 'Fix branch уже изменена. Откройте её в GitHub для ручной проверки.')
    else:
        github_request(api_path + '/git/refs', token, {'ref': 'refs/heads/' + branch, 'sha': fix.base_sha})
    # If GitHub rejects the commit, the isolated empty branch remains visible for review.
    result = github_request(api_path + '/contents/' + quote(fix.file, safe='/'), token, {
        'message': 'Apply reviewed BultShield fix', 'content': base64.b64encode(fix.proposed.encode()).decode(),
        'sha': source['sha'], 'branch': branch}, method='PUT')
    db.add(AuditEvent(user_id=db.info['owner_id'], action='fix_branch_created', object_id=str(fix.id), outcome='success'))
    db.commit()
    return {'branch': branch, 'commit_sha': result['commit']['sha'], 'url': repo.url.removesuffix('.git') + '/tree/' + quote(branch, safe='/')}
