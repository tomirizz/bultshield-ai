"""Описание изменения для PR от модели: что отправляется, как проверяется ответ, что попадает в текст PR."""
import json
import uuid

import pytest
from app import llm_change
from app.github_pr import FixSet, build_pr_body
from app.llm import FakeProvider
from app.llm_change import change_request, draft_change_note
from app.models import LLMCall, Scan
from sqlalchemy import select
from test_fix_runs import allow_local_registry as allow_local_registry
from test_fix_runs import check as check
from test_gitleaks import worker_db as worker_db  # noqa: F401
from test_llm import SECRET, Counting, cfg
from test_llm import report_of as report_of

SECTION = '### Описание от модели (предположение)'


def fix_set(**changes):
    values = dict(
        packages=[{'package': 'lodash', 'from': '4.17.15', 'to': '4.18.1', 'method': 'direct', 'resolves': ['CVE-2021-23337', 'CVE-2020-8203']},
                  {'package': 'qs', 'from': '6.5.5', 'to': '6.16.0', 'method': 'override', 'resolves': ['CVE-2026-82417']}],
        files={'package.json': '{"name": "app", "secret": "' + SECRET + '"}', 'package-lock.json': '{}'},
        original={'package.json': '{}', 'package-lock.json': '{}'},
        manual=[{'package': 'request', 'reason': 'исправленной версии нет'}],
        db_updated_at='2026-10-13T06:00:00Z')
    values.update(changes)
    return FixSet(**values)


def stored(db):
    db.expire_all()
    return db.scalars(select(LLMCall).where(LLMCall.subject_key.like('change:%'))).all()


def draft(db, check, fix=None, provider=None, settings=None, run=None):
    return draft_change_note(db, check, run or uuid.uuid4(), fix or fix_set(), provider=provider or FakeProvider(), settings=settings or cfg())


# ---- что отправляется модели ----

def test_request_has_only_packages_versions_and_cves():
    text = change_request(fix_set())
    data = json.loads(text)
    assert data['kind'] == 'change' and [p['package'] for p in data['packages']] == ['lodash', 'qs']
    assert data['packages'][0]['resolves'] == ['CVE-2021-23337', 'CVE-2020-8203']
    assert data['not_included'] == [{'package': 'request', 'reason': 'исправленной версии нет'}]
    assert SECRET not in text and 'package-lock' not in text and '"name": "app"' not in text   # содержимое файлов не уходит


def test_links_and_markup_in_reasons_are_removed_before_sending():
    text = change_request(fix_set(manual=[{'package': 'x', 'reason': 'см. https://evil.example/a и <script>alert(1)</script> **жирный**'}]))
    assert 'evil.example' not in text and '<script>' not in text


# ---- ответ модели ----

def test_note_is_received_validated_and_stored(db, check):
    provider = Counting(FakeProvider())
    note = draft(db, check, provider=provider)
    assert note['status'] == 'COMPLETED' and note['model'] == 'fake-explainer-1' and note['reused'] is False
    assert 'lodash с 4.17.15 на 4.18.1' in note['summary'] and 'qs с 6.5.5 на 6.16.0' in note['summary']
    assert 'request' in note['recommendation']   # не вошло в изменение: названо, а не объявлено исправленным
    rows = stored(db)
    assert len(rows) == 1 and rows[0].status == 'COMPLETED' and rows[0].subject_key.startswith('change:') and rows[0].finding_ids == []
    assert rows[0].request['kind'] == 'change' and SECRET not in json.dumps(rows[0].request)


def test_same_change_is_not_paid_for_twice(db, check):
    provider = Counting(FakeProvider())
    first = draft(db, check, provider=provider, run=uuid.UUID(int=1))
    second = draft(db, check, provider=provider, run=uuid.UUID(int=2))
    assert provider.calls == 1 and second['reused'] is True and second['summary'] == first['summary'] and len(stored(db)) == 1


def test_a_different_change_asks_again(db, check):
    provider = Counting(FakeProvider())
    draft(db, check, provider=provider)
    draft(db, check, fix=fix_set(manual=[]), provider=provider)
    assert provider.calls == 2


def test_model_not_connected_asks_nothing(db, check):
    note = draft_change_note(db, check, uuid.uuid4(), fix_set(), settings=cfg(llm_provider='disabled'))
    assert note['status'] == 'NOT_CONFIGURED' and note['summary'] is None and stored(db) == []


@pytest.mark.parametrize('mode, status, code', [
    ('unavailable', 'UNAVAILABLE', 'network'), ('garbage', 'INVALID_RESPONSE', 'not_json'),
    ('invented_version', 'INVALID_RESPONSE', 'invented_version'), ('leak', 'INVALID_RESPONSE', 'secret_in_response'),
    ('english', 'INVALID_RESPONSE', 'wrong_language'), ('link', 'INVALID_RESPONSE', 'contains_link'),
])
def test_bad_model_behaviour_gives_no_note_and_is_recorded(db, check, mode, status, code):
    note = draft(db, check, provider=FakeProvider(mode))
    assert note['status'] == status and note['summary'] is None
    rows = stored(db)
    assert len(rows) == 1 and rows[0].status == status and rows[0].error_code == code and rows[0].result is None
    body = build_pr_body(fix_set(note=note))
    assert SECTION in body and 'Модель описание не подготовила' in body and 'ghp_' not in body and 'example.org' not in body


def test_daily_limit_stops_requests(db, check):
    provider = Counting(FakeProvider())
    note = draft(db, check, provider=provider, settings=cfg(llm_daily_call_limit=1))
    assert note['status'] == 'COMPLETED'
    other = draft(db, check, fix=fix_set(manual=[]), provider=provider, settings=cfg(llm_daily_call_limit=1))
    assert other['status'] == 'LIMIT_EXCEEDED' and 'суточный лимит' in other['message'] and provider.calls == 1


def test_unknown_check_is_an_error(db):
    with pytest.raises(LookupError):
        draft_change_note(db, uuid.uuid4(), uuid.uuid4(), fix_set(), provider=FakeProvider(), settings=cfg())


# ---- текст PR ----

def test_pr_body_gets_a_labelled_model_section_and_nothing_else_changes(db, check):
    plain = build_pr_body(fix_set(), 'a' * 40)
    note = draft(db, check)
    with_note = build_pr_body(fix_set(note=note), 'a' * 40)
    assert SECTION in with_note and 'Это текст языковой модели' in with_note and 'не заменяет просмотр' in with_note
    assert 'lodash с 4.17.15 на 4.18.1' in with_note
    # Всё, что собрано кодом, остаётся прежним: добавляется только раздел модели.
    assert with_note.replace(with_note[with_note.index('\n' + SECTION):with_note.index('\n---')], '') == plain
    assert SECTION not in plain and build_pr_body(fix_set(note=None), 'a' * 40) == plain


def test_hostile_model_text_cannot_inject_links_or_markup_into_the_pr():
    note = {'status': 'COMPLETED', 'message': None, 'summary': 'См. https://evil.example/x и ![a](http://evil.example/p.png) <b>тест</b>',
            'risk': 'Риск `rm -rf /` ```код```', 'recommendation': 'Смотрите [сюда](https://evil.example)'}
    body = build_pr_body(fix_set(note=note))
    assert 'evil.example' not in body and '<b>' not in body and '`rm -rf' not in body and '```' not in body and '![' not in body


def test_note_does_not_change_files_branch_or_package_set(db, check):
    from app.github_pr import _branch_name
    fix = fix_set()
    before = (dict(fix.files), list(fix.packages), _branch_name('a' * 40, fix.files))
    fix.note = draft(db, check)
    assert (fix.files, fix.packages, _branch_name('a' * 40, fix.files)) == before   # модель описывает изменение, но не меняет его


# ---- учёт и отчёт проверки ----

def test_change_notes_do_not_pose_as_finding_explanations_but_are_counted(db, check):
    before = report_of(db, check)['llm']
    assert before['status'] == 'NOT_RUN'
    draft(db, check)
    after = report_of(db, check)['llm']
    assert after['explained'] == 0 and after['failed'] == 0 and after['input_tokens'] > 0   # в расходах есть, в пояснениях находок нет
    assert not [a for a in report_of(db, check)['assumptions'] if a['source'] == 'llm_explanation']


def test_service_scan_row_is_untouched(db, check):
    draft(db, check)
    assert db.get(Scan, check).kind == 'image'
    assert llm_change.SUBJECT_PREFIX == 'change:'
