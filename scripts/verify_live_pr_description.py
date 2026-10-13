"""Real-model PR-description acceptance on a separate, non-destructive *_test database.

Run with the existing private Bult model settings. Input is a saved FIX_VERIFIED
agent result; this script does not rerun the sandbox, publish a PR or change GitHub.
Database credentials are read in memory only. No tables/databases are dropped.
"""
import argparse
import hashlib
import json
import re
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from app.config import get_settings  # noqa: E402
from app.github_pr import FixSet, build_pr_body  # noqa: E402
from app.llm_change import change_request, draft_change_note  # noqa: E402
from app.models import Base, LLMCall, Project, Repository, Scan, ScanStatus, User  # noqa: E402
from sqlalchemy import create_engine, select, text  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402


def verified_set(data):
    combined = data.get('combined') or {}
    required = {'install', 'tests', 'build', 'start', 'health', 'rescan'}
    passed = {s['name'] for s in combined.get('steps', []) if s['status'] == 'passed'}
    if combined.get('outcome') != 'FIX_VERIFIED' or not required.issubset(passed):
        raise ValueError('Нужен сохранённый результат полной успешной проверки исправления.')
    names = set(combined['packages'])
    methods = {c['package']: c['method'] for c in combined['candidates']}
    packages = [{'package': p['package'], 'from': p['installed'], 'to': p['target'],
                 'method': methods[p['package']], 'resolves': p['plan']['resolves']}
                for p in data['packages'] if p['package'] in names]
    if len(packages) != len(names) or not names:
        raise ValueError('Проверенный набор обновлений неполный.')
    manual = [{'package': p['package'], 'reason': p['reason']} for p in data['packages'] if p['package'] not in names]
    # Only metadata reaches the model; file contents are unnecessary for this check.
    return FixSet(packages, {}, {}, manual, combined.get('scan_db_updated_at'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--database-name', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z][a-z0-9_]{0,48}_test', args.database_name):
        parser.error('Нужна отдельная база с именем, оканчивающимся на _test.')
    raw = args.evidence.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.sha256:
        parser.error('Контрольная сумма исходного результата не совпадает.')
    fix = verified_set(json.loads(raw))
    settings = get_settings()
    if settings.llm_provider != 'bult':
        parser.error('Эта приёмка требует настоящего LLM_PROVIDER=bult.')
    url = make_url(settings.database_url)
    if url.database == args.database_name:
        parser.error('Тестовая база должна отличаться от основной базы приложения.')
    with create_engine(url.set(database='postgres'), isolation_level='AUTOCOMMIT').connect() as admin:
        if not admin.scalar(text('SELECT 1 FROM pg_database WHERE datname=:name'), {'name': args.database_name}):
            parser.error('Сначала создайте отдельную базу администратором PostgreSQL и назначьте владельцем роль приложения. Права роли приложения расширять не нужно.')
    engine = create_engine(url.set(database=args.database_name))
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        user = User(display_name='LLM acceptance fixture')
        db.add(user)
        db.flush()
        project = Project(owner_id=user.id, name=f'Imported verified fixture {uuid.uuid4()}')
        db.add(project)
        db.flush()
        repo = Repository(project_id=project.id, url='https://github.com/tomirizz/bultshield-training-app')
        db.add(repo)
        db.flush()
        scan = Scan(project_id=project.id, repository_id=repo.id, status=ScanStatus.COMPLETED,
                    scanner_config={'imported_local_evidence_sha256': args.sha256, 'acceptance_fixture': True})
        db.add(scan)
        db.commit()
        run = uuid.uuid4()
        note = draft_change_note(db, scan.id, run, fix, settings=settings)
        again = draft_change_note(db, scan.id, run, fix, settings=settings) if note['status'] == 'COMPLETED' else None
        calls = db.scalars(select(LLMCall).where(LLMCall.scan_id == scan.id)).all()
        fix.note = note
        result = {'source': 'real Bult model, imported locally verified fix, separate test database',
                  'evidence_sha256': args.sha256, 'request': json.loads(change_request(fix)),
                  'note': note, 'repeat': again, 'stored_call_count': len(calls),
                  'calls': [{'id': str(c.id), 'status': c.status, 'model': c.model, 'prompt_version': c.prompt_version,
                             'input_tokens': c.input_tokens, 'output_tokens': c.output_tokens} for c in calls],
                  'pr_body': build_pr_body(fix), 'github_modified': False}
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({'note': note, 'repeat': again, 'stored_call_count': len(calls)}, ensure_ascii=False, indent=2))
        print('OUTPUT_SHA256', hashlib.sha256(args.output.read_bytes()).hexdigest())
        if not (note['status'] == 'COMPLETED' and again and again['reused'] and len(calls) == 1):
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
