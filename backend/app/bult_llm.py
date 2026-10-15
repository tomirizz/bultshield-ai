"""Measured Function 1 explanations through the existing private Bult model."""
import json
from http.client import HTTPConnection, HTTPException

from .ai_service import private_endpoint
from .llm import MAX_RESPONSE_BYTES, LLMBadResponse, LLMResult, LLMUnavailable

RUSSIAN_TEXT = '^[А-Яа-яЁё][А-Яа-яЁёA-Za-z0-9 .,;:()!?/+_@-]*$'
NO_FIX = ('Сканер не указал исправленную версию. Нужен ручной разбор применимости уязвимости '
          'и вариантов замены или ограничения использования компонента. Автоматическое исправление не подготовлено.')
CHANGE_RISKS = [
    'Проверка прошла на копии проекта. Тесты покрывают ограниченный набор сценариев, поэтому риск несовместимости сохраняется.',
    'Сборка, тесты, запуск и повторное сканирование прошли на копии проекта. Совместимость во всех сценариях не гарантирована.',
]
CHANGE_REVIEW = ('Просмотрите изменение перед слиянием. Проверенный патч ещё не применён к работающему приложению; '
                 'после подтверждения нужны сборка и отдельная проверка опубликованного образа.')
UNKNOWN_RISK = ('В данных есть идентификатор уязвимости, но нет описания механизма атаки. '
                'Влияние на приложение зависит от использования компонента и требует ручной проверки.')


def _payload(user):
    """Данные запроса без добавленного при повторе замечания об отклонённом ответе."""
    try:
        data = json.loads(user.split('\n\nПредыдущий ответ отклонён', 1)[0])
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def task_instruction(user):
    kind = _payload(user).get('kind')
    change = kind == 'change'
    if kind == 'plan':
        return ('Выбери одну версию из candidates: target должен точно совпадать с одной из них. Предпочитай ту же мажорную версию, '
                'что у installed_version. Пиши по-русски: по одному-два полных предложения в reason и risk. '
                'Названия пакетов и версии копируй точно из данных. Не смешивай русский и латинский алфавиты внутри одного слова.')
    common = ('Пиши по-русски: по одному-два полных предложения в каждом поле. '
              'Названия пакетов копируй точно латиницей из данных: не переводи и не транслитерируй. '
              'Не смешивай русский и латинский алфавиты внутри одного слова. ')
    if change:
        return common + ('Это описание уже проверенного изменения для PR. В summary перечисли только обновлённые пакеты '
                         'и точные версии до и после. В risk укажи ограничения тестов и риск совместимости. '
                         'В recommendation напомни о проверке человеком и что изменение ещё не применено к работающему приложению. '
                         'Пакеты из not_included не исправлены этим изменением. Их ошибки не относятся к проверенному набору. '
                         'Не утверждай, что успешные тесты завершились с ошибкой.')
    return common + ('Это находка сканера, не доказательство эксплуатации. Если описание содержит только номер уязвимости, '
                     'не выдумывай механизм атаки: скажи, что применимость требует проверки. '
                     'Если исправленной версии нет, нужен ручной разбор. Обновление мажорной версии требует проверки совместимости. '
                     'Не утверждай, что обновление уже выполнено или проверено, когда status=FOUND.')


def response_schema(user):
    payload = _payload(user)
    if payload.get('kind') == 'plan':
        text = {'type': 'string', 'minLength': 20, 'maxLength': 500, 'pattern': RUSSIAN_TEXT}
        return {'type': 'object', 'properties': {'target': {'type': 'string', 'enum': [c['version'] for c in payload.get('candidates', [])]},
                                                'reason': text, 'risk': text, 'needs_review': {'type': 'boolean'}},
                'required': ['target', 'reason', 'risk', 'needs_review'], 'additionalProperties': False}
    schema = {'type': 'object', 'properties': {
        name: {'type': 'string', 'minLength': 20, 'maxLength': 600, 'pattern': RUSSIAN_TEXT}
        for name in ('summary', 'risk', 'recommendation')},
        'required': ['summary', 'risk', 'recommendation'], 'additionalProperties': False}
    if not payload:
        return schema
    if payload.get('kind') == 'change':
        # Verification/approval facts are trusted application data, not model guesses.
        schema['properties']['risk'] = {'type': 'string', 'enum': CHANGE_RISKS}
        schema['properties']['recommendation'] = {'type': 'string', 'const': CHANGE_REVIEW}
        return schema
    findings = payload.get('findings') or []
    if findings and all(f.get('title', '').strip() in (f.get('cve'), f"{f.get('cve')}: {payload.get('package')}") for f in findings):
        schema['properties']['risk'] = {'type': 'string', 'const': UNKNOWN_RISK}
    status = payload.get('status')
    if status in ('FIX_VERIFIED', 'FIX_PROPOSED'):
        schema['properties']['recommendation'] = {'type': 'string', 'const':
            'Просмотрите предложенное изменение и результат его проверки. Применение требует подтверждения человеком; работающая версия ещё не подтверждена как исправленная.'}
    elif status == 'FIX_DEPLOYED':
        schema['properties']['recommendation'] = {'type': 'string', 'const':
            'Исправление подтверждено повторным сканированием опубликованного образа. Отдельно проверьте, что приложение использует именно этот образ.'}
    elif 'fixed_versions' in payload and not payload['fixed_versions']:
        # The live small model invented an update for an unmaintained package.
        # No-fix actions are scanner facts, so constrain them instead of trusting generation.
        schema['properties']['recommendation'] = {'type': 'string', 'const': NO_FIX}
    elif status in ('FOUND', 'MANUAL_REVIEW'):
        schema['properties']['recommendation'] = {'type': 'string', 'const':
            'Сверьте исправленные версии и причину статуса в отчёте. До применения обновления проверьте совместимость, сборку, тесты, запуск и повторное сканирование на изолированной копии; смена мажорной версии требует ручного разбора.'}
    return schema


def validate_grounding(result, user):
    """Recheck critical schema constraints server-side; model decoding alone is not validation."""
    for name, rule in response_schema(user)['properties'].items():
        if ('const' in rule and result[name] != rule['const']) or ('enum' in rule and result[name] not in rule['enum']):
            return False
    payload = _payload(user)
    if payload.get('kind') == 'plan':
        return True   # версия уже ограничена списком candidates (enum), пакета в тексте может не быть
    if payload.get('kind') == 'change':
        return all(all(str(p[k]) in result['summary'] for k in ('package', 'from', 'to')) for p in payload.get('packages', []))
    return not payload.get('package') or payload['package'] in result['summary']


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
            schema = response_schema(user)
            body = {'model': self.model, 'temperature': 0.1, 'max_tokens': max_tokens, 'stream': False,
                    'messages': [{'role': 'system', 'content': system + '\n' + task_instruction(user)},
                                 {'role': 'user', 'content': 'Подготовь ответ по этим данным: ' + user}],
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
