"""Measured Function 1 explanations through the existing private Bult model."""
import json
from http.client import HTTPConnection, HTTPException

from .ai_service import private_endpoint
from .llm import MAX_RESPONSE_BYTES, LLMBadResponse, LLMResult, LLMUnavailable


def parse_response(data, model):
    try:
        choice = data['choices'][0]
        content = choice['message']['content']
        if choice.get('finish_reason') != 'stop' or not isinstance(content, str) or not content.strip():
            raise ValueError()
        usage = data.get('usage', {})
        counts = [usage.get(key) for key in ('prompt_tokens', 'completion_tokens')]
        if any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in counts):
            raise ValueError()
        return LLMResult(content, str(data.get('model') or model)[:200], *counts)
    except (KeyError, IndexError, TypeError, AttributeError, ValueError):
        raise LLMBadResponse('Ответ Bult-модели неполный или не содержит счётчиков токенов.') from None


class BultProvider:
    name = 'bult'

    def __init__(self, settings):
        self.settings = settings
        self.model = settings.ai_model

    def complete(self, system, user, max_tokens):
        # Reuse the same strict private-address policy as the deployed assistant.
        # Pin the resolved IP and never follow redirects or environment proxies.
        connection = None
        try:
            host, port = private_endpoint(self.settings.ai_endpoint)
            connection = HTTPConnection(host, port, timeout=self.settings.ai_timeout_seconds)
            schema = {'type': 'object', 'properties': {name: {'type': 'string', 'minLength': 20, 'maxLength': 600}
                      for name in ('summary', 'risk', 'recommendation')},
                      'required': ['summary', 'risk', 'recommendation'], 'additionalProperties': False}
            body = {'model': self.model, 'temperature': 0.1, 'max_tokens': max_tokens, 'stream': False,
                    'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}],
                    'response_format': {'type': 'json_object', 'schema': schema}}
            connection.request('POST', '/v1/chat/completions', body=json.dumps(body).encode(),
                               headers={'Content-Type': 'application/json'})
            response = connection.getresponse()
            if response.status != 200:
                raise LLMUnavailable(f'Bult-модель временно недоступна (HTTP {response.status}).', f'http_{response.status}')
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise LLMBadResponse('Ответ Bult-модели превышает допустимый размер.')
            try:
                data = json.loads(raw)
            except ValueError:
                raise LLMBadResponse('Bult-модель вернула некорректный JSON.') from None
            return parse_response(data, self.model)
        except (OSError, HTTPException, ValueError):
            raise LLMUnavailable('Нет связи с приватной моделью Bult.', 'network') from None
        finally:
            if connection:
                connection.close()
