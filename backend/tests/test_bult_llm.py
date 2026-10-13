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
    assert not re.fullmatch(pattern, 'Вulnerability in the request package')
    assert schema['properties']['recommendation'] == {'type': 'string', 'const': NO_FIX}
    assert 'const' not in response_schema('{"fixed_versions":["2.5.6"]}')['properties']['recommendation']


@pytest.mark.parametrize('value', [None, {}, {'choices': []}, {'choices': [{'finish_reason': 'length'}]}])
def test_bult_rejects_bad_or_truncated_reply(value):
    from app.bult_llm import parse_response
    with pytest.raises(LLMBadResponse):
        parse_response(value, 'qwen')
