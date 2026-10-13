import hashlib
import io
import json
import os
import subprocess
import sys
import threading
import urllib.error
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from app import llm
from app.check_report import LIMITATIONS, load_report
from app.config import Settings, get_settings
from app.llm import (
    AnthropicProvider,
    FakeProvider,
    LLMBadResponse,
    LLMError,
    LLMNotConfigured,
    LLMResult,
    LLMUnavailable,
    OpenAICompatible,
    build_provider,
    cost_usd,
    estimate_tokens,
    redact,
    validate_base_url,
)
from app.llm_explain import PROMPT_VERSION, SYSTEM_PROMPT, InvalidResponse, build_groups, explain_check, parse_explanation
from app.models import LLMCall, Scan
from app.tenant import isolate
from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from test_fix_runs import allow_local_registry as allow_local_registry
from test_fix_runs import check as check
from test_gitleaks import worker_db as worker_db  # noqa: F401

SECRET = 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2'
KEY = 'sk-test-' + 'k' * 24
BACKEND = Path(__file__).resolve().parents[1]
REQUEST = json.dumps({'package': 'lodash', 'installed_version': '4.17.15', 'fixed_versions': ['4.17.21'],
                      'findings': [{'id': 'CVE-2021-23337', 'cve': 'CVE-2021-23337'}]}, ensure_ascii=False)
GOOD = {'summary': 'В пакете lodash версии 4.17.15 есть известные уязвимости.',
        'risk': 'Опасность зависит от того, попадают ли внешние данные в уязвимые функции.',
        'recommendation': 'Обновить lodash до версии 4.17.21 и запустить тесты.'}


def cfg(**changes):
    return get_settings().model_copy(update={'llm_provider': 'fake', **changes})


class Counting:
    """Обёртка, считающая обращения к провайдеру."""
    def __init__(self, inner):
        self.inner, self.calls, self.requests = inner, 0, []
        self.name, self.model = inner.name, inner.model

    def complete(self, system, user, max_tokens):
        self.calls += 1
        self.requests.append((system, user, max_tokens))
        return self.inner.complete(system, user, max_tokens)


def counting(mode='ok'):
    return Counting(FakeProvider(mode))


def rows(db):
    return db.scalars(select(LLMCall).order_by(LLMCall.created_at, LLMCall.id)).all()


def report_of(db, scan_id):
    return load_report(db, db.get(Scan, scan_id), limit=500)


def facts(report):
    """Всё, что не зависит от модели: если модель недоступна, это не должно меняться."""
    return {k: v for k, v in report.items() if k not in ('llm', 'assumptions', 'limitations')}


# ---- скрытие секретов ----

@pytest.mark.parametrize('raw', [
    SECRET, 'github_pat_' + 'A1b2C3d4E5' * 3, 'sk-ant-api03-' + 'x' * 30, 'AKIA' + 'ABCDEFGHIJKLMNOP',
    'xoxb-1234567890-abcdefghij', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk',
    'Authorization: Bearer abcdefghijklmnop12345', '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n-----END RSA PRIVATE KEY-----',
    '-----BEGIN PRIVATE KEY-----\nMIIBOgIBAAJBobrezano', 'postgresql://user:hunter2pass@db.local:5432/app',
    'password = "SuperSecret123"', 'DB_PASSWORD=abc12345', 'api_key: 9f8e7d6c5b4a',
])
def test_redact_hides_secrets(raw):
    cleaned, count = redact(f'до {raw} после')
    assert count >= 1 and 'до ' in cleaned and ' после' in cleaned or cleaned.startswith('до')
    for part in ('hunter2pass', 'SuperSecret123', 'abc12345', 'a1B2c3D4e5F6g7H8i9J0k1L2', 'MIIBOgIBAAJB', 'abcdefghijklmnop12345',
                 '9f8e7d6c5b4a', 'x' * 30, 'ABCDEFGHIJKLMNOP', '1234567890-abcdefghij'):
        assert part not in cleaned


def test_redact_hides_exact_values_and_keeps_ordinary_text():
    assert redact('ключ my-private-value-77 тут', extra=('my-private-value-77',)) == ('ключ [скрыто] тут', 1)
    ordinary = 'CVE-2021-23337: lodash 4.17.15 -> 4.17.21, sha256:' + 'ab12' * 16 + ', перл 1:2.38.1-5+deb12u3'
    assert redact(ordinary) == (ordinary, 0)
    assert redact('короткий', extra=('abc',)) == ('короткий', 0)  # слишком короткие значения не подставляются


def test_redact_url_credentials_keep_the_host():
    cleaned, _ = redact('git clone https://deploy:tok3nvalue@github.com/org/repo.git')
    assert 'tok3nvalue' not in cleaned and 'github.com/org/repo.git' in cleaned


# ---- оценка, цена, адрес ----

def test_estimate_and_cost():
    assert estimate_tokens('') == 0 and estimate_tokens('a' * 31) == 11
    assert cost_usd(1000, 500, cfg(llm_price_input_per_mtok=3, llm_price_output_per_mtok=15)) == pytest.approx(0.0105)
    assert cost_usd(1000, 500, cfg()) == 0


@pytest.mark.parametrize('url', ['https://api.openai.com/v1', 'https://llm.internal.example/v1/', 'http://localhost:8080/v1', 'http://127.0.0.1:9/v1'])
def test_base_url_accepted(url):
    assert validate_base_url(url) == url.rstrip('/')


@pytest.mark.parametrize('url', ['http://api.example.com/v1', 'ftp://x.example/v1', 'https://user:pw@api.example.com/v1',
                                 'https://api.example.com/v1?key=1', 'https://api.example.com/v1#x', '/v1', 'https://'])
def test_base_url_rejected(url):
    with pytest.raises(LLMNotConfigured):
        validate_base_url(url)


# ---- настройки и выбор провайдера ----

def test_provider_selection_follows_settings():
    with pytest.raises(LLMNotConfigured) as excinfo:
        build_provider(cfg(llm_provider='disabled'))
    assert excinfo.value.code == 'disabled'
    assert isinstance(build_provider(cfg()), FakeProvider)
    key = SecretStr(KEY)
    assert isinstance(build_provider(cfg(llm_provider='openai', llm_api_key=key, llm_model='m')), OpenAICompatible)
    assert isinstance(build_provider(cfg(llm_provider='anthropic', llm_api_key=key, llm_model='m')), AnthropicProvider)


def test_real_providers_need_key_and_model():
    key = SecretStr(KEY)
    for name in ('openai', 'anthropic'):
        with pytest.raises(LLMNotConfigured):
            build_provider(cfg(llm_provider=name, llm_model='m'))
        with pytest.raises(LLMNotConfigured):
            build_provider(cfg(llm_provider=name, llm_api_key=key))


def test_default_endpoints_and_custom_base_url():
    key = SecretStr(KEY)
    assert build_provider(cfg(llm_provider='openai', llm_api_key=key, llm_model='m'))._base == 'https://api.openai.com/v1'
    assert build_provider(cfg(llm_provider='anthropic', llm_api_key=key, llm_model='m'))._base == 'https://api.anthropic.com'
    assert build_provider(cfg(llm_provider='openai', llm_api_key=key, llm_model='m', llm_base_url='http://localhost:8000/v1/'))._base == 'http://localhost:8000/v1'
    with pytest.raises(LLMNotConfigured):
        build_provider(cfg(llm_provider='openai', llm_api_key=key, llm_model='m', llm_base_url='http://evil.example.com/v1'))


def test_settings_validate_provider_and_hide_the_key(monkeypatch):
    # Проверяем значение по умолчанию независимо от модели запущенного демо.
    monkeypatch.delenv('LLM_PROVIDER', raising=False)
    with pytest.raises(ValueError):
        Settings(database_url='postgresql://u:p@localhost/db', llm_provider='gpt-lan')
    settings = Settings(database_url='postgresql://u:p@localhost/db', llm_provider=' OpenAI ', llm_api_key=KEY)
    assert settings.llm_provider == 'openai'
    assert KEY not in repr(settings) and KEY not in str(settings) and KEY not in settings.model_dump_json()
    assert Settings(database_url='postgresql://u:p@localhost/db').llm_provider == 'disabled'


def test_unknown_fake_mode_is_refused():
    with pytest.raises(LLMNotConfigured):
        FakeProvider('chaos')


# ---- OpenAI-совместимый и Anthropic провайдеры (подставной opener) ----

class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def respond(payload, calls=None):
    def opener(request, timeout):
        if calls is not None:
            calls.append((request, timeout))
        return FakeResponse(payload if isinstance(payload, bytes) else json.dumps(payload).encode())
    return opener


def failing(exc):
    def opener(request, timeout):
        raise exc
    return opener


def http_error(code):
    return urllib.error.HTTPError('https://api.example.com', code, 'x', {}, io.BytesIO(b'{"error": "%s"}' % KEY.encode()))


def openai(opener, **kw):
    return OpenAICompatible(api_key=KEY, model='gpt-test', base_url='https://api.example.com/v1', timeout=7, opener=opener, **kw)


def anthropic(opener):
    return AnthropicProvider(api_key=KEY, model='claude-test', base_url='https://api.example.com', timeout=7, opener=opener)


OPENAI_OK = {'model': 'gpt-test-2025', 'choices': [{'message': {'content': 'ответ'}, 'finish_reason': 'stop'}],
             'usage': {'prompt_tokens': 120, 'completion_tokens': 30}}
ANTHROPIC_OK = {'model': 'claude-test-1', 'content': [{'type': 'text', 'text': 'отв'}, {'type': 'text', 'text': 'ет'}],
                'stop_reason': 'end_turn', 'usage': {'input_tokens': 90, 'output_tokens': 20}}


def test_openai_request_and_response():
    calls = []
    result = openai(respond(OPENAI_OK, calls)).complete('система', 'запрос', 321)
    assert result == LLMResult('ответ', 'gpt-test-2025', 120, 30)
    request, timeout = calls[0]
    body = json.loads(request.data)
    assert request.full_url == 'https://api.example.com/v1/chat/completions' and timeout == 7 and request.get_method() == 'POST'
    assert request.get_header('Authorization') == f'Bearer {KEY}'
    assert body['model'] == 'gpt-test' and body['max_tokens'] == 321 and body['temperature'] == 0
    assert body['messages'] == [{'role': 'system', 'content': 'система'}, {'role': 'user', 'content': 'запрос'}]
    assert KEY not in request.data.decode()


def test_anthropic_request_and_response():
    calls = []
    result = anthropic(respond(ANTHROPIC_OK, calls)).complete('система', 'запрос', 200)
    assert result == LLMResult('ответ', 'claude-test-1', 90, 20)
    request, _ = calls[0]
    body = json.loads(request.data)
    assert request.full_url == 'https://api.example.com/v1/messages'
    assert request.get_header('X-api-key') == KEY and request.get_header('Anthropic-version') == '2023-06-01'
    assert body['system'] == 'система' and body['messages'] == [{'role': 'user', 'content': 'запрос'}] and body['max_tokens'] == 200


@pytest.mark.parametrize('make', [lambda o: openai(o), anthropic])
@pytest.mark.parametrize('code, expected', [(401, LLMNotConfigured), (403, LLMNotConfigured), (429, LLMUnavailable), (408, LLMUnavailable),
                                            (500, LLMUnavailable), (503, LLMUnavailable), (400, LLMError), (404, LLMError)])
def test_http_errors_are_classified_without_leaking_the_key(make, code, expected):
    with pytest.raises(expected) as excinfo:
        make(failing(http_error(code))).complete('s', 'u', 100)
    assert type(excinfo.value) is expected and KEY not in str(excinfo.value) and str(code) in str(excinfo.value)
    assert not isinstance(excinfo.value, LLMUnavailable) or expected is LLMUnavailable


@pytest.mark.parametrize('error', [urllib.error.URLError(ConnectionRefusedError()), TimeoutError(), ConnectionResetError(), OSError('нет сети')])
def test_network_failures_mean_unavailable(error):
    with pytest.raises(LLMUnavailable) as excinfo:
        openai(failing(error)).complete('s', 'u', 100)
    assert excinfo.value.code == 'network' and KEY not in str(excinfo.value)


@pytest.mark.parametrize('payload, code', [
    (b'<html>502</html>', 'bad_envelope'), (b'[1, 2]', 'bad_envelope'), ({}, 'bad_envelope'), ({'choices': []}, 'bad_envelope'),
    ({'choices': [{'message': {}}]}, 'bad_envelope'), ({'choices': [{'message': {'content': '  '}}]}, 'empty'),
    ({'choices': [{'message': {'content': None}}]}, 'empty'),
    ({'choices': [{'message': {'content': '{"a"'}, 'finish_reason': 'length'}]}, 'truncated'),
    (b'x' * 200_001, 'too_large'),
])
def test_malformed_openai_responses_are_rejected(payload, code):
    with pytest.raises(LLMBadResponse) as excinfo:
        openai(respond(payload)).complete('s', 'u', 100)
    assert excinfo.value.code == code


@pytest.mark.parametrize('payload, code', [
    ({}, 'bad_envelope'), ({'content': 'text'}, 'bad_envelope'), ({'content': []}, 'empty'),
    ({'content': [{'type': 'tool_use', 'name': 'x'}]}, 'empty'),
    ({'content': [{'type': 'text', 'text': 'обрыв'}], 'stop_reason': 'max_tokens'}, 'truncated'),
])
def test_malformed_anthropic_responses_are_rejected(payload, code):
    with pytest.raises(LLMBadResponse) as excinfo:
        anthropic(respond(payload)).complete('s', 'u', 100)
    assert excinfo.value.code == code


def test_missing_or_odd_usage_becomes_zero_not_a_crash():
    payload = {'choices': [{'message': {'content': 'ответ'}}], 'usage': {'prompt_tokens': -5, 'completion_tokens': True}}
    result = openai(respond(payload)).complete('s', 'u', 100)
    assert (result.input_tokens, result.output_tokens, result.model) == (0, 0, 'gpt-test')
    assert openai(respond({'choices': [{'message': {'content': 'ответ'}}], 'usage': 'many'})).complete('s', 'u', 1).input_tokens == 0


def test_redirects_are_not_followed():
    handler = llm._NoRedirect()
    assert handler.redirect_request(None, None, 302, 'Found', {}, 'https://other.example.com') is None


# ---- настоящий HTTP: локальный подставной сервер ----

class MockModel(BaseHTTPRequestHandler):
    mode = 'ok'
    seen = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        MockModel.seen.append((self.path, dict(self.headers), json.loads(body)))
        if MockModel.mode == 'redirect':
            self.send_response(302)
            self.send_header('Location', 'http://127.0.0.1:1/steal')
            self.end_headers()
            return
        if MockModel.mode == 'slow':
            import time
            time.sleep(1.5)
        if MockModel.mode == 'error':
            self.send_response(503)
            self.end_headers()
            return
        reply = json.dumps({'model': 'mock-1', 'choices': [{'message': {'content': json.dumps(GOOD, ensure_ascii=False)}, 'finish_reason': 'stop'}],
                            'usage': {'prompt_tokens': 50, 'completion_tokens': 40}}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args):
        pass


@pytest.fixture
def mock_model():
    MockModel.mode, MockModel.seen = 'ok', []
    server = HTTPServer(('127.0.0.1', 0), MockModel)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{server.server_address[1]}/v1'
    server.shutdown()
    server.server_close()


def test_real_http_round_trip(mock_model):
    provider = OpenAICompatible(api_key=KEY, model='mock', base_url=mock_model, timeout=5)
    result = provider.complete('система', REQUEST, 100)
    assert json.loads(result.text) == GOOD and result.model == 'mock-1' and (result.input_tokens, result.output_tokens) == (50, 40)
    path, headers, body = MockModel.seen[0]
    assert path == '/v1/chat/completions' and headers['Authorization'] == f'Bearer {KEY}' and body['messages'][1]['content'] == REQUEST


def test_real_http_timeout_and_server_errors_mean_unavailable(mock_model):
    MockModel.mode = 'slow'
    with pytest.raises(LLMUnavailable):
        OpenAICompatible(api_key=KEY, model='mock', base_url=mock_model, timeout=0.3).complete('s', 'u', 10)
    MockModel.mode = 'error'
    with pytest.raises(LLMUnavailable) as excinfo:
        OpenAICompatible(api_key=KEY, model='mock', base_url=mock_model, timeout=5).complete('s', 'u', 10)
    assert excinfo.value.code == 'http_503'


def test_real_http_redirect_is_not_followed(mock_model):
    MockModel.mode = 'redirect'
    with pytest.raises(LLMError) as excinfo:
        OpenAICompatible(api_key=KEY, model='mock', base_url=mock_model, timeout=5).complete('s', 'u', 10)
    assert excinfo.value.code == 'http_302' and len(MockModel.seen) == 1


def test_connection_refused_means_unavailable():
    with pytest.raises(LLMUnavailable):
        OpenAICompatible(api_key=KEY, model='mock', base_url='http://127.0.0.1:9/v1', timeout=2).complete('s', 'u', 10)


# ---- тестовый провайдер ----

def test_fake_provider_builds_the_answer_from_the_request():
    result = FakeProvider().complete(SYSTEM_PROMPT, REQUEST, 500)
    data = json.loads(result.text)
    assert set(data) == {'summary', 'risk', 'recommendation'} and 'lodash' in data['summary'] and '4.17.21' in data['recommendation']
    assert result.input_tokens > 0 and result.output_tokens > 0
    assert parse_explanation(result.text, REQUEST) == data


@pytest.mark.parametrize('fixed, expected', [(['5.36.0-7+deb12u4'], '5.36.0-7+deb12u4'), (['>=4.17.19'], '4.17.19'),
                                             (['5.0.10, 3.0.7, 2.1.5'], '5.0.10'), (['^2.0.1'], '2.0.1')])
def test_fake_provider_recommends_the_whole_fixed_version(fixed, expected):
    request = json.dumps({'package': 'pkg', 'installed_version': '1.0.0', 'fixed_versions': fixed, 'findings': []})
    text = FakeProvider().complete('s', request, 1).text
    assert f'до версии {expected},' in json.loads(text)['recommendation']
    assert parse_explanation(text, request)  # такой ответ проходит нашу же проверку версий


def fake_text(**fields):
    request = json.dumps({'package': 'pkg', 'installed_version': '5.0.7', 'fixed_versions': ['1.1.18, 2.1.4, 5.0.9'], 'findings': [], **fields})
    return json.loads(FakeProvider().complete('s', request, 1).text), request


def test_fake_provider_picks_the_fix_on_the_same_major_version():
    answer_, _ = fake_text()
    assert 'до версии 5.0.9,' in answer_['recommendation'] and 'до версии 1.1.18' not in answer_['recommendation']
    other, _ = fake_text(installed_version='1:2.38.1-5+deb12u3', fixed_versions=['1:2.38.1-5+deb12u4', '3.0.0'])
    assert '1:2.38.1-5+deb12u4' in other['recommendation']


def test_fake_provider_respects_the_status_from_the_system():
    deployed, _ = fake_text(status='FIX_DEPLOYED')
    assert 'не нужно' in deployed['recommendation'] and 'уже применено' in deployed['summary'] and 'Обновить' not in deployed['recommendation']
    manual, _ = fake_text(status='MANUAL_REVIEW')
    assert 'нужен человек' in manual['recommendation'] and 'до версии 5.0.9' in manual['recommendation']
    proposed, _ = fake_text(status='FIX_VERIFIED')
    assert 'применяет человек' in proposed['recommendation']
    for status, reply in (('FIX_DEPLOYED', deployed), ('MANUAL_REVIEW', manual), ('FIX_VERIFIED', proposed)):
        _, req = fake_text(status=status)
        assert parse_explanation(json.dumps(reply, ensure_ascii=False), req)  # свои же ответы проходят нашу проверку


def test_prompt_explains_every_status():
    for status in ('FIX_DEPLOYED', 'FIX_VERIFIED', 'FIX_PROPOSED', 'MANUAL_REVIEW', 'FOUND'):
        assert status in SYSTEM_PROMPT


def test_image_digests_are_not_sent_in_status_reasons(db, check):
    report = report_of(db, check)
    digest = 'sha256:' + 'ab12' * 16
    for item in report['findings']['items']:
        item['status_reason'] = f'образ {digest} собран после слияния'
    sent = build_groups(report, 6000)[0]['text']
    assert digest not in sent and 'sha256:…' in sent


def test_fake_provider_without_a_fixed_version_asks_for_a_manual_decision():
    request = json.dumps({'package': 'pkg', 'installed_version': '1.0.0', 'fixed_versions': [], 'findings': []})
    assert 'вручную' in json.loads(FakeProvider().complete('s', request, 1).text)['recommendation']


def test_fake_provider_failure_modes():
    with pytest.raises(LLMUnavailable):
        FakeProvider('unavailable').complete('s', REQUEST, 1)
    with pytest.raises(LLMBadResponse):
        FakeProvider().complete('s', 'не json', 1)
    for mode, code in (('garbage', 'not_json'), ('invented_version', 'invented_version'), ('leak', 'secret_in_response'),
                       ('english', 'wrong_language'), ('link', 'contains_link')):
        with pytest.raises(InvalidResponse) as excinfo:
            parse_explanation(FakeProvider(mode).complete('s', REQUEST, 1).text, REQUEST)
        assert excinfo.value.code == code, mode


# ---- проверка ответа модели ----

def answer(**changes):
    return json.dumps({**GOOD, **changes}, ensure_ascii=False)


def rejected(raw, code):
    with pytest.raises(InvalidResponse) as excinfo:
        parse_explanation(raw, REQUEST)
    assert excinfo.value.code == code


def test_valid_answer_is_accepted_even_in_a_code_fence():
    assert parse_explanation(answer(), REQUEST) == GOOD
    assert parse_explanation('```json\n' + answer() + '\n```', REQUEST) == GOOD
    assert parse_explanation('  ' + answer() + '\n', REQUEST) == GOOD


@pytest.mark.parametrize('raw, code', [
    ('Конечно, вот объяснение', 'not_json'), ('', 'not_json'), ('[1, 2]', 'not_json'), ('"строка"', 'not_json'),
    (json.dumps({'summary': 'только это поле, довольно длинное'}), 'schema'),
    (json.dumps({**GOOD, 'extra': 'поле'}), 'schema'),
    (answer(summary='коротко'), 'schema'), (answer(risk='б' * 601), 'schema'),
    (json.dumps({**GOOD, 'risk': ['список', 'вместо', 'строки']}), 'schema'),
    (json.dumps({**GOOD, 'recommendation': None}), 'schema'),
])
def test_wrong_shape_is_rejected(raw, code):
    rejected(raw, code)


@pytest.mark.parametrize('changes, code', [
    ({'recommendation': 'Подробности на https://example.org/fix и дальше по тексту'}, 'contains_link'),
    ({'recommendation': 'Откройте www.example.org для подробностей и деталей'}, 'contains_link'),
    ({'recommendation': 'Выполнить так:\n```\nnpm install lodash@4.17.21\n```'}, 'contains_code'),
    ({'risk': 'Ключ доступа ' + SECRET + ' попал в данные, будьте осторожны'}, 'secret_in_response'),
    ({'risk': 'Файл содержит password = Secret12345 в открытом виде тут'}, 'secret_in_response'),
    ({'summary': 'The package lodash 4.17.15 has known vulnerabilities'}, 'wrong_language'),
    ({'recommendation': 'Обновить lodash до версии 4.17.22 и проверить тесты'}, 'invented_version'),
    ({'recommendation': 'Обновить lodash до 5.0 и проверить тесты приложения'}, 'invented_version'),
    ({'risk': 'Похожая проблема описана в CVE-2099-0001, она тоже опасна'}, 'invented_cve'),
    ({'risk': 'Опасность зависит от данных\x07 из внешних источников тут'}, 'bad_characters'),
])
def test_unsafe_or_invented_content_is_rejected(changes, code):
    rejected(answer(**changes), code)


def test_versions_and_cves_from_the_request_are_allowed():
    ok = answer(recommendation='Обновить lodash с 4.17.15 до 4.17.21 из-за CVE-2021-23337 и cve-2021-23337 в списке.')
    assert parse_explanation(ok, REQUEST)['recommendation'].startswith('Обновить lodash')


# ---- что отправляется модели ----

def test_groups_contain_only_safe_fields(db, check):
    groups = build_groups(report_of(db, check), 6000)
    assert [g['subject'] for g in groups][0] == 'package:lodash@4.17.15'
    assert [g['payload']['in_application'] for g in groups] == [True] + [False] * (len(groups) - 1)
    for group in groups:
        assert set(group['payload']) == {'package', 'installed_version', 'fixed_versions', 'in_application', 'status', 'status_reason',
                                         'findings_total', 'findings'}
        assert all(set(f) == {'id', 'cve', 'severity', 'title'} for f in group['payload']['findings'])
        assert json.loads(group['text']) == group['payload'] and len(group['finding_ids']) == group['payload']['findings_total']
    lodash = groups[0]['payload']
    assert lodash['findings_total'] == 7 and lodash['status'] == 'FOUND' and lodash['installed_version'] == '4.17.15'
    sent = ' '.join(g['text'] for g in groups)
    for private in ('localhost:5001', 'sha256:', '/app/', 'node_modules', 'password'):
        assert private not in sent


def test_secrets_in_scanner_text_are_removed_before_sending(db, check):
    report = report_of(db, check)
    report['findings']['items'][0]['title'] = f'Утечка {SECRET} в заголовке'
    report['findings']['items'][0]['status_reason'] = 'смотри postgresql://user:hunter2pass@db:5432/x'
    sent = ' '.join(g['text'] for g in build_groups(report, 6000))
    assert SECRET not in sent and 'hunter2pass' not in sent and '[скрыто]' in sent


def test_long_requests_are_trimmed_to_the_limit(db, check):
    report = report_of(db, check)
    full = build_groups(report, 6000)[0]
    short = build_groups(report, 700)[0]
    assert len(short['text']) <= 700 < len(full['text'])
    assert short['payload']['findings_total'] == 7 and len(short['payload']['findings']) < 7  # честно сообщает, сколько находок всего
    assert len(short['finding_ids']) == 7


def test_many_findings_are_capped(db, check):
    report = report_of(db, check)
    item = report['findings']['items'][0]
    report['findings']['items'] = [dict(item, rule_id=f'CVE-2024-{i:04d}', cve=f'CVE-2024-{i:04d}') for i in range(40)]
    payload = build_groups(report, 20000)[0]['payload']
    assert payload['findings_total'] == 40 and len(payload['findings']) == 15


# ---- запуск пояснений ----

def test_dry_run_sends_nothing_and_stores_nothing(db, check):
    provider = counting()
    summary = explain_check(db, check, provider=provider, settings=cfg(), dry_run=True)
    assert provider.calls == 0 and rows(db) == []
    assert summary['status'] == 'DRY_RUN' and summary['planned'] == 6 and len(summary['prompts']) == 6
    assert summary['estimated_input_tokens'] > 0 and summary['max_output_tokens'] == 600 * 6


def test_dry_run_works_without_a_configured_provider(db, check):
    summary = explain_check(db, check, settings=cfg(llm_provider='disabled'), dry_run=True)
    assert summary['status'] == 'DRY_RUN' and summary['planned'] == 6 and rows(db) == []


def test_dry_run_estimates_cost_from_prices(db, check):
    summary = explain_check(db, check, settings=cfg(llm_price_input_per_mtok=3, llm_price_output_per_mtok=15), dry_run=True)
    expected = (summary['estimated_input_tokens'] * 3 + summary['max_output_tokens'] * 15) / 1_000_000
    assert summary['estimated_cost_usd_max'] == pytest.approx(expected, abs=1e-6) and expected > 0


def test_not_configured_does_nothing(db, check):
    summary = explain_check(db, check, settings=cfg(llm_provider='disabled'))
    assert summary['status'] == 'NOT_CONFIGURED' and rows(db) == []
    assert report_of(db, check)['llm']['status'] == 'NOT_RUN'


def test_unknown_check_is_reported(db):
    with pytest.raises(LookupError):
        explain_check(db, uuid.uuid4(), settings=cfg())


def test_explanations_are_saved_and_shown_as_assumptions(db, check):
    before = report_of(db, check)
    provider = counting()
    settings = cfg(llm_price_input_per_mtok=3, llm_price_output_per_mtok=15)
    summary = explain_check(db, check, provider=provider, settings=settings)
    assert summary['status'] == 'COMPLETED' and summary['completed'] == 6 and provider.calls == 6 and summary['failed'] == 0
    saved = rows(db)
    assert len(saved) == 6 and {r.status for r in saved} == {'COMPLETED'}
    lodash = next(r for r in saved if r.subject_key == 'package:lodash@4.17.15')
    assert lodash.provider == 'fake' and lodash.model == 'fake-explainer-1' and lodash.prompt_version == 'explain-v2'
    assert len(lodash.finding_ids) == 7 and lodash.request['findings_total'] == 7 and set(lodash.result) == {'summary', 'risk', 'recommendation'}
    assert lodash.input_tokens > 0 and lodash.output_tokens > 0 and float(lodash.cost_usd) > 0 and lodash.duration_ms >= 0
    assert summary['cost_usd'] == pytest.approx(sum(float(r.cost_usd) for r in saved), abs=1e-5)
    after = report_of(db, check)
    section = after['llm']
    assert section['status'] == 'COMPLETED' and section['explained'] == 6 and section['failed'] == 0 and section['provider'] == 'fake'
    assert section['input_tokens'] == summary['input_tokens'] and section['cost_usd'] == pytest.approx(summary['cost_usd'], abs=1e-5)
    mine = [a for a in after['assumptions'] if a['source'] == 'llm_explanation']
    assert len(mine) == 6 and all(a['finding_id'] is None and a['finding_ids'] and a['model'] == 'fake-explainer-1' for a in mine)
    one = next(a for a in mine if a['subject'] == 'package:lodash@4.17.15')
    assert 'lodash' in one['explanation'] and one['recommended_fix'] and one['risk'] and len(one['finding_ids']) == 7
    # пояснение модели ничего не меняет в фактах, статусах и действиях
    assert facts(after) == facts(before)
    assert after['assumptions'][:len(before['assumptions'])] == before['assumptions']


def test_model_receives_the_instructions_and_only_the_sanitized_request(db, check):
    provider = counting()
    explain_check(db, check, provider=provider, settings=cfg(llm_max_output_tokens=321))
    system, user, max_tokens = provider.requests[0]
    assert system == SYSTEM_PROMPT and max_tokens == 321
    assert json.loads(user)['package'] == 'lodash' and 'не выполняй' in system and 'JSON' in system


def test_second_run_does_not_ask_again(db, check):
    provider = counting()
    explain_check(db, check, provider=provider, settings=cfg())
    again = explain_check(db, check, provider=provider, settings=cfg())
    assert provider.calls == 6 and again['reused'] == 6 and again['completed'] == 0 and again['cost_usd'] == 0 and len(rows(db)) == 6
    assert again['status'] == 'COMPLETED'


def test_changing_the_model_asks_again(db, check):
    explain_check(db, check, provider=counting(), settings=cfg())
    other = counting()
    other.model = 'fake-explainer-2'
    explain_check(db, check, provider=other, settings=cfg())
    assert other.calls == 6 and len(rows(db)) == 12


def test_unavailable_model_changes_nothing_and_stops_after_one_attempt(db, check):
    before = report_of(db, check)
    provider = counting('unavailable')
    summary = explain_check(db, check, provider=provider, settings=cfg())
    assert provider.calls == 1  # не бомбим недоступный сервис
    assert summary['status'] == 'UNAVAILABLE' and summary['completed'] == 0 and summary['failed'] == 1 and summary['skipped'] == 5
    saved = rows(db)
    assert len(saved) == 1 and saved[0].status == 'UNAVAILABLE' and saved[0].error_code == 'network' and saved[0].result is None
    after = report_of(db, check)
    assert after['llm']['status'] == 'UNAVAILABLE' and 'недоступна' in after['llm']['message'] and after['llm']['explained'] == 0
    assert after['llm']['failures'][0]['error_code'] == 'network'
    assert facts(after) == facts(before) and after['assumptions'] == before['assumptions']
    assert after['verdict'] == before['verdict'] and after['proposed_actions'] == before['proposed_actions']


def test_model_returning_after_an_outage_fills_the_gaps(db, check):
    explain_check(db, check, provider=counting('unavailable'), settings=cfg())
    provider = counting()
    summary = explain_check(db, check, provider=provider, settings=cfg())
    assert provider.calls == 6 and summary['completed'] == 6
    assert report_of(db, check)['llm']['status'] == 'COMPLETED'  # старая неудача не мешает: берётся последний результат по каждому пакету


@pytest.mark.parametrize('mode, code', [('garbage', 'not_json'), ('invented_version', 'invented_version'), ('leak', 'secret_in_response'),
                                        ('english', 'wrong_language'), ('link', 'contains_link')])
def test_invalid_answers_are_recorded_and_never_shown(db, check, mode, code):
    before = report_of(db, check)
    provider = counting(mode)
    summary = explain_check(db, check, provider=provider, settings=cfg())
    assert provider.calls == 6 and summary['failed'] == 6 and summary['completed'] == 0 and summary['status'] == 'FAILED'
    saved = rows(db)
    assert {r.status for r in saved} == {'INVALID_RESPONSE'} and {r.error_code for r in saved} == {code}
    assert all(r.result is None for r in saved)
    dump = json.dumps([[str(getattr(r, c.name)) for c in LLMCall.__table__.columns] for r in saved], ensure_ascii=False)
    assert SECRET not in dump and 'ghp_' not in dump and 'example.org' not in dump and '9.9.9' not in dump
    after = report_of(db, check)
    assert after['llm']['status'] == 'FAILED' and after['llm']['explained'] == 0 and after['llm']['failed'] == 6
    assert after['assumptions'] == before['assumptions'] and facts(after) == facts(before)


def test_wasted_tokens_of_rejected_answers_are_still_counted(db, check):
    summary = explain_check(db, check, provider=counting('garbage'), settings=cfg(llm_price_input_per_mtok=1000, llm_price_output_per_mtok=1000))
    assert summary['input_tokens'] > 0 and summary['cost_usd'] > 0
    assert report_of(db, check)['llm']['cost_usd'] == pytest.approx(summary['cost_usd'], abs=1e-5)


def test_partial_result_when_one_answer_is_bad(db, check):
    class Flaky(Counting):
        def complete(self, system, user, max_tokens):
            if json.loads(user)['package'] == 'apt':
                return LLMResult('это не JSON', 'fake-explainer-1', 10, 5)
            return super().complete(system, user, max_tokens)

    summary = explain_check(db, check, provider=Flaky(FakeProvider()), settings=cfg())
    assert summary['status'] == 'PARTIAL' and summary['completed'] == 5 and summary['failed'] == 1
    section = report_of(db, check)['llm']
    assert section['status'] == 'PARTIAL' and section['explained'] == 5 and section['failed'] == 1
    assert section['failures'][0]['subject'] == 'package:apt@2.6.1' and section['failures'][0]['error_code'] == 'not_json'


def test_rejected_key_stops_without_leaking_it(db, check):
    provider = openai(failing(http_error(401)))
    summary = explain_check(db, check, provider=provider, settings=cfg(llm_provider='openai'))
    saved = rows(db)
    assert len(saved) == 1 and saved[0].status == 'ERROR' and saved[0].error_code == 'auth' and summary['status'] == 'FAILED'
    assert summary['skipped'] == 5
    everything = json.dumps(summary, ensure_ascii=False) + json.dumps(report_of(db, check)['llm'], ensure_ascii=False) + str(saved[0].error_message)
    assert KEY not in everything


def test_bad_envelope_is_recorded_and_the_next_group_is_still_tried(db, check):
    provider = openai(respond({'choices': []}))
    summary = explain_check(db, check, provider=provider, settings=cfg(llm_provider='openai'))
    assert summary['failed'] == 6 and {r.error_code for r in rows(db)} == {'bad_envelope'} and {r.status for r in rows(db)} == {'ERROR'}


def test_per_check_limit_is_applied_and_reported(db, check):
    provider = counting()
    summary = explain_check(db, check, provider=provider, settings=cfg(llm_max_calls_per_check=2))
    assert provider.calls == 2 and summary['completed'] == 2 and summary['skipped'] == 4 and summary['status'] == 'PARTIAL'
    saved = rows(db)
    assert [r.subject_key for r in saved[:2]] == ['package:lodash@4.17.15', 'package:perl-base@5.36.0-7+deb12u3'] and saved[2].status == 'LIMIT_EXCEEDED'
    section = report_of(db, check)['llm']
    assert section['status'] == 'PARTIAL' and section['explained'] == 2 and 'Лимит запросов на одну проверку (2)' in section['failures'][-1]['message']
    # повтор с тем же лимитом не множит записи о лимите
    explain_check(db, check, provider=provider, settings=cfg(llm_max_calls_per_check=2))
    assert provider.calls == 2 and len(rows(db)) == 3
    # лимит снят: остальное дополняется, а запись о лимите перестаёт показываться
    explain_check(db, check, provider=provider, settings=cfg())
    assert provider.calls == 6
    assert report_of(db, check)['llm']['status'] == 'COMPLETED'


def test_max_calls_argument_cannot_exceed_the_configured_limit(db, check):
    provider = counting()
    explain_check(db, check, provider=provider, settings=cfg(llm_max_calls_per_check=3), max_calls=99)
    assert provider.calls == 3
    other = counting()
    again = explain_check(db, check, provider=other, settings=cfg(llm_max_calls_per_check=10), max_calls=1)
    assert other.calls == 0 and again['reused'] == 1 and again['planned'] == 1 and again['skipped'] == 5


def test_daily_limit_stops_requests(db, check):
    provider = counting()
    summary = explain_check(db, check, provider=provider, settings=cfg(llm_daily_call_limit=2))
    assert provider.calls == 2 and summary['status'] == 'LIMITED' and summary['completed'] == 2 and summary['skipped'] == 4
    section = report_of(db, check)['llm']
    assert section['status'] == 'PARTIAL' and any(f['error_code'] == 'limit' and 'суточный' in f['message'] for f in section['failures'])
    # лимит считает отправленные запросы, а не записи о лимите
    again = explain_check(db, check, provider=provider, settings=cfg(llm_daily_call_limit=2))
    assert provider.calls == 2 and again['reused'] == 2 and again['status'] == 'LIMITED'


def test_daily_limit_ignores_requests_older_than_a_day(db, check):
    explain_check(db, check, provider=counting(), settings=cfg(llm_max_calls_per_check=2))
    db.execute(text("UPDATE llm_calls SET created_at = now() - interval '25 hours'"))
    db.commit()
    provider = counting()
    summary = explain_check(db, check, provider=provider, settings=cfg(llm_daily_call_limit=2))
    assert provider.calls == 2 and summary['completed'] == 2


def test_concurrent_duplicate_is_treated_as_already_done(db, check, engine):
    class Racing(Counting):
        def complete(self, system, user, max_tokens):
            result = super().complete(system, user, max_tokens)
            if self.calls == 1:  # другой запуск успел сохранить тот же запрос
                with Session(engine) as other:
                    scan = other.get(Scan, check)
                    group = build_groups(load_report(other, scan, limit=500), 6000)[0]
                    raw = f'{PROMPT_VERSION}|fake|fake-explainer-1|{group["text"]}'
                    other.add(LLMCall(project_id=scan.project_id, scan_id=scan.id, subject_key=group['subject'], finding_ids=group['finding_ids'],
                                      provider='fake', model='fake-explainer-1', prompt_version=PROMPT_VERSION,
                                      input_hash=hashlib.sha256(raw.encode()).hexdigest(), status='COMPLETED', result=GOOD))
                    other.commit()
            return result

    summary = explain_check(db, check, provider=Racing(FakeProvider()), settings=cfg())
    assert summary['reused'] == 1 and summary['completed'] == 5 and len(rows(db)) == 6


# ---- база данных ----

def make_row(db, check, **kw):
    scan = db.get(Scan, check)
    values = dict(project_id=scan.project_id, scan_id=scan.id, subject_key='package:x@1', provider='fake', prompt_version='v1',
                  input_hash='h' * 8, status='COMPLETED')
    row = LLMCall(**{**values, **kw})
    db.add(row)
    return row


def test_database_refuses_unknown_status_and_duplicate_completed(db, check):
    make_row(db, check, status='SUCCESS')
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
    make_row(db, check)
    db.commit()
    make_row(db, check)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
    make_row(db, check, status='UNAVAILABLE')
    make_row(db, check, status='UNAVAILABLE')
    db.commit()  # неудачные попытки можно повторять


def test_calls_are_removed_with_the_check(db, check):
    make_row(db, check)
    db.commit()
    db.execute(text('DELETE FROM scans WHERE id = :id'), {'id': check})
    db.commit()
    assert rows(db) == []


def test_owner_isolation_covers_llm_calls(db, check):
    from app.api import WORKSPACE_USER_ID
    make_row(db, check)
    db.commit()
    with Session(db.get_bind()) as outsider:
        isolate(outsider, uuid.uuid4())
        assert outsider.scalars(select(LLMCall)).all() == []
    with Session(db.get_bind()) as owner:
        isolate(owner, WORKSPACE_USER_ID)
        assert len(owner.scalars(select(LLMCall)).all()) == 1


# ---- отчёт ----

def test_report_without_model_is_unchanged_and_says_so(db, check):
    report = report_of(db, check)
    assert report['llm']['status'] == 'NOT_RUN' and report['llm']['explained'] == 0 and report['llm']['failures'] == []
    assert not [a for a in report['assumptions'] if a['source'] == 'llm_explanation']
    assert any('Пояснения языковой модели' in item for item in report['limitations']) and 'Пояснения языковой модели' in LIMITATIONS[-1]


def test_report_api_exposes_the_llm_section(client, db, check):
    explain_check(db, check, provider=counting(), settings=cfg())
    body = client.get(f'/api/checks/{check}/report').json()
    assert body['llm']['status'] == 'COMPLETED' and any(a['source'] == 'llm_explanation' for a in body['assumptions'])
    assert KEY not in json.dumps(body)


def test_explanations_follow_the_report_page(db, check):
    explain_check(db, check, provider=counting(), settings=cfg())
    page = load_report(db, db.get(Scan, check), limit=1, offset=0)
    shown = page['findings']['items'][0]['id']
    mine = [a for a in page['assumptions'] if a['source'] == 'llm_explanation']
    assert len(mine) == 1 and shown in mine[0]['finding_ids']  # только пояснение к находке на этой странице
    assert page['llm']['explained'] == 6  # сводка относится ко всей проверке


# ---- скрипт ----

def run_script(check_id, *args, **env):
    environment = {**os.environ, 'LLM_PROVIDER': 'fake', **env}
    return subprocess.run([sys.executable, str(BACKEND.parent / 'scripts' / 'run_llm_explain.py'), str(check_id), *args],
                          capture_output=True, text=True, env=environment, cwd=BACKEND, timeout=120)


def test_script_dry_run(db, check):
    done = run_script(check, '--dry-run')
    assert done.returncode == 0, done.stderr
    assert 'РЕЖИМ ПРОВЕРКИ: ничего не отправлено' in done.stdout and 'package:lodash@4.17.15' in done.stdout
    assert rows(db) == []


def test_script_runs_with_the_fake_model(db, check):
    done = run_script(check)
    assert done.returncode == 0, done.stderr
    assert 'Итог: COMPLETED. Новых пояснений: 6' in done.stdout and 'предположение модели fake-explainer-1' in done.stdout
    assert 'Статусы находок не менялись' in done.stdout and len(rows(db)) == 6


def test_script_reports_an_unavailable_model(db, check):
    done = run_script(check, LLM_FAKE_MODE='unavailable')
    assert done.returncode == 0, done.stderr
    assert 'Итог: UNAVAILABLE' in done.stdout and 'Модель недоступна' in done.stdout and 'Статусы находок не менялись' in done.stdout


def test_script_without_a_provider_explains_what_to_do(db, check):
    done = run_script(check, LLM_PROVIDER='disabled')
    assert done.returncode != 0 and 'Модель не подключена' in done.stderr and 'LLM_PROVIDER=fake' in done.stderr


def test_script_unknown_check(db, check):
    done = run_script(uuid.uuid4())
    assert done.returncode != 0 and 'Проверка не найдена' in done.stderr
