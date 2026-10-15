import json
import re

import pytest
from app.config import Settings
from app.llm import LLMBadResponse, LLMUnavailable, build_provider


def settings():
    return Settings(database_url='postgresql+psycopg://localhost/bult_test', llm_provider='bult',
                    ai_endpoint='http://bultshield-model:8080')


def test_bult_uses_private_model_without_api_key(monkeypatch):
    import app.bult_llm as module
    seen = {}
    class Response:
        status = 200
        def read(self, limit):
            return json.dumps({'model': 'qwen2.5-1.5b-instruct', 'choices': [{'finish_reason': 'stop',
                'message': {'content': '{"summary":"Проверка"}'}}],
                'usage': {'prompt_tokens': 123, 'completion_tokens': 45}}).encode()
    class Connection:
        def __init__(self, host, port, timeout):
            seen.update(host=host, port=port, timeout=timeout)
        def request(self, method, path, body, headers):
            seen.update(path=path, body=json.loads(body), headers=headers)
        def getresponse(self):
            return Response()
        def close(self):
            seen['closed'] = True
    monkeypatch.setattr(module, 'private_endpoint', lambda url: ('10.0.0.7', 8080))
    monkeypatch.setattr(module, 'HTTPConnection', Connection)
    result = build_provider(settings()).complete('Правила', '{}', 600)
    assert (result.input_tokens, result.output_tokens) == (123, 45)
    assert seen['host'] == '10.0.0.7'
    assert seen['closed'] and 'Authorization' not in seen['headers']
    assert seen['body']['response_format']['schema']['additionalProperties'] is False


def test_bult_rejects_public_endpoint(monkeypatch):
    import app.bult_llm as module
    monkeypatch.setattr(module, 'private_endpoint', lambda url: (_ for _ in ()).throw(ValueError('unsafe')))
    with pytest.raises(LLMUnavailable):
        build_provider(settings()).complete('Правила', '{}', 600)


def test_live_language_and_no_fix_failures_are_constrained():
    from app.bult_llm import NO_FIX, response_schema
    schema = response_schema('{"package":"request","fixed_versions":[]}')
    pattern = schema['properties']['summary']['pattern']
    assert re.fullmatch(pattern, 'Проблема в проверенном пакете.')
    assert not re.fullmatch(pattern, 'SSRF漏洞被发现')
    assert re.fullmatch(pattern, 'Уязвимость в пакете tough-cookie требует проверки.')
    assert schema['properties']['recommendation'] == {'type': 'string', 'const': NO_FIX}
    assert 'const' not in response_schema('{"fixed_versions":["2.5.6"]}')['properties']['recommendation']


def test_pr_instruction_is_not_a_scanner_instruction():
    from app.bult_llm import CHANGE_REVIEW, response_schema, task_instruction
    payload = '{"kind":"change","packages":[{"package":"qs","from":"6.5.5","to":"6.16.0"}]}'
    assert 'точные версии до и после' in task_instruction(payload)
    assert 'не применено' in task_instruction(payload)
    assert response_schema(payload)['properties']['recommendation']['const'] == CHANGE_REVIEW


def test_live_pr_contradiction_is_rejected_even_if_model_ignores_schema():
    from app.bult_llm import CHANGE_REVIEW, CHANGE_RISKS
    from app.llm_explain import InvalidResponse, parse_explanation
    request = '{"kind":"change","packages":[{"package":"qs","from":"6.5.5","to":"6.16.0"}]}'
    good = {'summary': 'Обновление qs с 6.5.5 до 6.16.0.', 'risk': CHANGE_RISKS[0], 'recommendation': CHANGE_REVIEW}
    assert parse_explanation(json.dumps(good), request, grounded=True) == good
    bad = {**good, 'risk': 'Шаги тестов завершились с ошибками после обновления, тесты не запускались без сети'}
    with pytest.raises(InvalidResponse, match='противоречит'):
        parse_explanation(json.dumps(bad), request, grounded=True)
    with pytest.raises(InvalidResponse, match='противоречит'):
        parse_explanation(json.dumps({**good, 'summary': 'Обновлены некоторые зависимости.'}), request, grounded=True)


def test_cve_only_finding_does_not_invent_impact_or_recommend_blind_major_upgrade():
    from app.bult_llm import UNKNOWN_RISK, response_schema
    payload = {'package': 'uuid', 'status': 'FOUND', 'fixed_versions': ['11.1.1'],
               'findings': [{'cve': 'CVE-2026-41907', 'title': 'CVE-2026-41907: uuid'}]}
    schema = response_schema(json.dumps(payload))['properties']
    assert schema['risk']['const'] == UNKNOWN_RISK
    assert 'мажорной версии требует ручного' in schema['recommendation']['const']
    payload['status'] = 'FIX_DEPLOYED'
    payload['fixed_versions'] = []
    assert 'приложение использует именно этот образ' in response_schema(json.dumps(payload))['properties']['recommendation']['const']


def test_mixed_script_live_regression_keeps_exact_package_names():
    from app.llm_explain import InvalidResponse, parse_explanation
    good = {'summary': 'Уязвимость в tough-cookie требует проверки.',
            'risk': 'Применимость зависит от использования пакета.',
            'recommendation': 'Проверьте совместимость обновления перед применением.'}
    assert parse_explanation(json.dumps(good), '{"package":"tough-cookie"}') == good
    with pytest.raises(InvalidResponse, match='смешаны алфавиты'):
        parse_explanation(json.dumps({**good, 'summary': 'Вulnerability в пакете требует проверки.'}), '{}')


@pytest.mark.parametrize('value', [None, {}, {'choices': []}, {'choices': [{'finish_reason': 'length'}]}])
def test_bult_rejects_bad_or_truncated_reply(value):
    from app.bult_llm import parse_response
    with pytest.raises(LLMBadResponse):
        parse_response(value, 'qwen')


PLAN_REQUEST = json.dumps({'kind': 'plan', 'package': 'qs', 'installed_version': '6.5.5', 'default': '6.5.6',
                           'candidates': [{'version': '6.5.6', 'major_change': False}, {'version': '6.16.0', 'major_change': True}],
                           'findings': [{'id': 'CVE-2022-24999', 'severity': 'HIGH', 'fixed_in': '6.5.6'}]}, ensure_ascii=False)


def test_plan_schema_limits_the_choice_to_the_allowed_versions():
    from app.bult_llm import response_schema, task_instruction, validate_grounding
    schema = response_schema(PLAN_REQUEST)
    assert schema['properties']['target']['enum'] == ['6.5.6', '6.16.0'] and schema['additionalProperties'] is False
    assert set(schema['required']) == {'target', 'reason', 'risk', 'needs_review'} and schema['properties']['needs_review'] == {'type': 'boolean'}
    assert 'candidates' in task_instruction(PLAN_REQUEST)
    good = {'target': '6.5.6', 'reason': 'Версия остаётся в той же ветке.', 'risk': 'Совместимость нужно проверить тестами.', 'needs_review': False}
    assert validate_grounding(good, PLAN_REQUEST)
    assert not validate_grounding({**good, 'target': '7.0.0'}, PLAN_REQUEST)


def test_plan_retry_note_does_not_break_the_schema():
    from app.bult_llm import response_schema, task_instruction
    retry = PLAN_REQUEST + '\n\nПредыдущий ответ отклонён: версия не из набора. Ответь только JSON-объектом.'
    assert response_schema(retry) == response_schema(PLAN_REQUEST) and task_instruction(retry) == task_instruction(PLAN_REQUEST)


def test_plan_without_candidates_cannot_be_answered_with_any_version():
    from app.bult_llm import response_schema
    empty = json.dumps({'kind': 'plan', 'package': 'qs', 'installed_version': '1.0.0', 'candidates': []})
    assert response_schema(empty)['properties']['target']['enum'] == []
