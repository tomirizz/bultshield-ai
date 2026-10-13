"""Адаптер языковой модели: один интерфейс, тестовый провайдер и подключение к внешним API.

Что делает: отправляет модели уже подготовленный запрос и возвращает текст ответа и число токенов.
Провайдер выбирается настройкой LLM_PROVIDER: disabled (по умолчанию), fake (тестовый, без сети),
openai (любой OpenAI-совместимый API, в том числе локальный) или anthropic. Остальной код про провайдера ничего не знает:
замена провайдера или модели не требует менять логику проверок.
Чего не делает: не решает, что отправлять, не проверяет смысл ответа и ничего не исполняет. Это в llm_explain.py.

Безопасность: ключ берётся только из настроек сервера, уходит только в заголовок запроса и не попадает в ошибки и логи;
адрес API должен быть HTTPS (http разрешён только для localhost); переходы по редиректам запрещены;
таймаут и размер ответа ограничены; любой сбой сети или сервера превращается в LLMUnavailable, а не в пустой «успех».
"""
import json
import math
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

from .config import get_settings

MAX_RESPONSE_BYTES = 200_000
REDACTED = '[скрыто]'
LOCAL_HOSTS = ('localhost', '127.0.0.1', '::1')

# Шаблоны секретов. Лучше скрыть лишнее, чем отправить внешней модели ключ.
SECRET_PATTERNS = (
    re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)', re.S),
    re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}'),
    re.compile(r'\bgithub_pat_[A-Za-z0-9_]{20,}'),
    re.compile(r'\bsk-[A-Za-z0-9_-]{16,}'),
    re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
    re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}'),
    re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'),
    re.compile(r'(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}'),
)
URL_CREDENTIALS = re.compile(r'(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@')
ASSIGNMENT = re.compile(r'(?i)\b([A-Za-z0-9_]*(?:password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|authorization)[A-Za-z0-9_]*)'
                        r'\s*[:=]\s*([\'"]?)[^\s\'",;]{4,}')


class LLMError(Exception):
    """Базовая ошибка адаптера. Текст безопасен для показа и сохранения: в нём нет ключа и тела ответа."""
    code = 'error'

    def __init__(self, message, code=None):
        super().__init__(message)
        if code:
            self.code = code


class LLMUnavailable(LLMError):
    """Модель не ответила: сеть, таймаут, 429, 5xx. Повторять сразу бессмысленно, проверки это не останавливает."""
    code = 'unavailable'


class LLMNotConfigured(LLMError):
    """Провайдер не настроен или отверг ключ."""
    code = 'not_configured'


class LLMBadResponse(LLMError):
    """Ответ провайдера не похож на ожидаемый."""
    code = 'bad_envelope'


@dataclass(frozen=True)
class LLMResult:
    text: str
    model: str
    input_tokens: int
    output_tokens: int


def redact(text, extra=()):
    """Скрывает секреты в тексте. Возвращает (текст, сколько мест скрыто). extra: точные значения, которые нельзя показывать."""
    count = 0
    text = str(text)
    for secret in extra:
        if secret and len(secret) >= 6 and secret in text:
            count += text.count(secret)
            text = text.replace(secret, REDACTED)
    for pattern in SECRET_PATTERNS:
        text, n = pattern.subn(REDACTED, text)
        count += n
    text, n = URL_CREDENTIALS.subn(lambda m: m.group(1) + REDACTED + '@', text)
    count += n
    text, n = ASSIGNMENT.subn(lambda m: f'{m.group(1)}={REDACTED}', text)
    return text, count + n


def estimate_tokens(text):
    """Грубая оценка числа токенов (для предварительного расчёта без отправки запроса). Реальное число даёт провайдер."""
    return math.ceil(len(text) / 3)


def cost_usd(input_tokens, output_tokens, settings=None):
    settings = settings or get_settings()
    return round((input_tokens * settings.llm_price_input_per_mtok + output_tokens * settings.llm_price_output_per_mtok) / 1_000_000, 6)


def validate_base_url(value):
    parsed = urlsplit(value)
    local = (parsed.hostname or '') in LOCAL_HOSTS
    if parsed.scheme not in ('https', 'http') or not parsed.hostname or (parsed.scheme == 'http' and not local):
        raise LLMNotConfigured('LLM_BASE_URL: нужен адрес https (http разрешён только для localhost).')
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise LLMNotConfigured('LLM_BASE_URL не должен содержать логин, пароль, параметры или якорь.')
    return value.rstrip('/')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _default_opener(request, timeout):
    return urllib.request.build_opener(_NoRedirect).open(request, timeout=timeout)


class HttpProvider:
    """Общая часть внешних провайдеров: POST JSON, ограниченный ответ, единообразные ошибки."""
    name = 'http'

    def __init__(self, *, api_key, model, base_url, timeout, opener=None):
        if not api_key:
            raise LLMNotConfigured('LLM_API_KEY не задан.')
        if not model:
            raise LLMNotConfigured('LLM_MODEL не задана.')
        self._key, self.model, self._timeout = api_key, model, timeout
        self._base = validate_base_url(base_url)
        self._opener = opener or _default_opener

    def _safe(self, text):
        return redact(text, extra=(self._key,))[0]

    def _post(self, url, headers, body):
        request = urllib.request.Request(url, data=json.dumps(body).encode(), method='POST',
                                         headers={'Content-Type': 'application/json', 'Accept': 'application/json', **headers})
        try:
            with self._opener(request, self._timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise LLMNotConfigured(f'Провайдер отклонил ключ (HTTP {exc.code}).', 'auth') from None
            if exc.code in (408, 429) or exc.code >= 500:
                raise LLMUnavailable(f'Модель временно недоступна (HTTP {exc.code}).', f'http_{exc.code}') from None
            raise LLMError(f'Провайдер отклонил запрос (HTTP {exc.code}).', f'http_{exc.code}') from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            # URLError.reason бывает исключением с адресом; в сообщение идёт только его тип.
            raise LLMUnavailable(f'Нет связи с моделью ({type(getattr(exc, "reason", exc)).__name__}).', 'network') from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LLMBadResponse('Ответ провайдера слишком большой.', 'too_large')
        try:
            data = json.loads(raw)
        except ValueError:
            raise LLMBadResponse('Ответ провайдера не JSON.') from None
        if not isinstance(data, dict):
            raise LLMBadResponse('Ответ провайдера имеет неожиданную форму.')
        return data

    @staticmethod
    def _count(value):
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


class OpenAICompatible(HttpProvider):
    """Chat Completions: OpenAI и совместимые API (в том числе локальные серверы моделей)."""
    name = 'openai'

    def complete(self, system, user, max_tokens):
        data = self._post(self._base + '/chat/completions', {'Authorization': f'Bearer {self._key}'}, {
            'model': self.model, 'max_tokens': max_tokens, 'temperature': 0,
            'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}]})
        try:
            choice = data['choices'][0]
            text = choice['message']['content']
        except (KeyError, IndexError, TypeError):
            raise LLMBadResponse('В ответе нет текста модели.') from None
        if not isinstance(text, str) or not text.strip():
            raise LLMBadResponse('Модель вернула пустой ответ.', 'empty')
        if choice.get('finish_reason') == 'length':
            raise LLMBadResponse('Ответ модели оборван по лимиту токенов.', 'truncated')
        usage = data.get('usage') if isinstance(data.get('usage'), dict) else {}
        return LLMResult(text, str(data.get('model') or self.model)[:200], self._count(usage.get('prompt_tokens')),
                         self._count(usage.get('completion_tokens')))


class AnthropicProvider(HttpProvider):
    """Messages API Anthropic."""
    name = 'anthropic'

    def complete(self, system, user, max_tokens):
        data = self._post(self._base + '/v1/messages', {'x-api-key': self._key, 'anthropic-version': '2023-06-01'}, {
            'model': self.model, 'max_tokens': max_tokens, 'temperature': 0, 'system': system,
            'messages': [{'role': 'user', 'content': user}]})
        blocks = data.get('content')
        if not isinstance(blocks, list):
            raise LLMBadResponse('В ответе нет текста модели.')
        text = ''.join(b.get('text', '') for b in blocks if isinstance(b, dict) and b.get('type') == 'text' and isinstance(b.get('text'), str))
        if not text.strip():
            raise LLMBadResponse('Модель вернула пустой ответ.', 'empty')
        if data.get('stop_reason') == 'max_tokens':
            raise LLMBadResponse('Ответ модели оборван по лимиту токенов.', 'truncated')
        usage = data.get('usage') if isinstance(data.get('usage'), dict) else {}
        return LLMResult(text, str(data.get('model') or self.model)[:200], self._count(usage.get('input_tokens')),
                         self._count(usage.get('output_tokens')))


def _closest_version(installed, candidates):
    """Из исправленных версий берёт ту, что на той же мажорной ветке, что и установленная (иначе первую)."""
    def major(value):
        m = re.match(r'(?:\d+:)?(\d+)', str(value or ''))
        return m.group(1) if m else None
    return next((c for c in candidates if major(c) == major(installed)), candidates[0] if candidates else None)


class FakeProvider:
    """Тестовый провайдер без сети. Строит ответ из переданных данных, поэтому его можно проверять детерминированно.

    Режимы (LLM_FAKE_MODE) повторяют реальные сбои: unavailable (модель недоступна), garbage (ответ не JSON),
    invented_version (модель выдумала версию), leak (в ответе секрет), english (ответ не по-русски), link (в ответе ссылка).
    """
    name = 'fake'
    model = 'fake-explainer-1'

    def __init__(self, mode='ok'):
        if mode not in ('ok', 'unavailable', 'garbage', 'invented_version', 'leak', 'english', 'link'):
            raise LLMNotConfigured('LLM_FAKE_MODE: ok, unavailable, garbage, invented_version, leak, english или link.')
        self.mode = mode

    def complete(self, system, user, max_tokens):
        if self.mode == 'unavailable':
            raise LLMUnavailable('Тестовая модель недоступна (имитация сбоя).', 'network')
        if self.mode == 'garbage':
            text = 'Конечно! Вот объяснение, но не в JSON.'
        else:
            try:
                data = json.loads(user)
                if data.get('kind') == 'change':
                    summary, risk, fix = self._change(data)
                    package = installed = None
                else:
                    package, installed = data['package'], data['installed_version']
                    total = data.get('findings_total', len(data.get('findings', [])))
            except (ValueError, KeyError, TypeError):
                raise LLMBadResponse('Тестовая модель получила непонятный запрос.') from None
            if package is None:
                text = self._finish(summary, risk, fix, 'пакет')
                return LLMResult(text, self.model, estimate_tokens(system + user), estimate_tokens(text))
            status = data.get('status')
            candidates = [c.strip().lstrip('>=^~ ') for v in data.get('fixed_versions') or [] for c in str(v).split(',') if c.strip()]
            target = _closest_version(installed, candidates)
            summary = f'В пакете {package} версии {installed} сканер нашёл уязвимостей: {total}.'
            if candidates:
                summary += ' Исправления есть в версиях: ' + ', '.join(candidates[:4]) + (' и других.' if len(candidates) > 4 else '.')
            risk = ('Это предположение, а не результат сканера: опасность зависит от того, попадают ли в уязвимые функции '
                    'данные из внешних источников. Сканер это не проверял.')
            if status == 'FIX_DEPLOYED':
                summary += ' Исправление подтверждено в опубликованном образе. Какая версия запущена в приложении, неизвестно.'
                fix = f'Повторно обновлять {package} не нужно. Убедитесь, что в эксплуатации запущен именно исправленный образ.'
            elif status == 'MANUAL_REVIEW':
                fix = (f'Автоматически проблема не исправлена, нужен человек. Возможное обновление: до версии {target}; '
                       'перед применением проверьте совместимость и тесты.' if target else
                       f'Для {package} исправленной версии нет: решение нужно принять вручную.')
            elif status in ('FIX_VERIFIED', 'FIX_PROPOSED') and target:
                fix = (f'Обновление {package} до версии {target} предложено и проверено в изолированной копии. '
                       'Его применяет человек после просмотра изменений.')
            else:
                fix = (f'Обновить {package} до версии {target}, затем запустить тесты и сборку и убедиться, что приложение работает.'
                       if target else f'Для {package} исправленной версии нет: решение нужно принять вручную.')
            text = self._finish(summary, risk, fix, package)
        return LLMResult(text, self.model, estimate_tokens(system + user), estimate_tokens(text))

    def _finish(self, summary, risk, fix, package):
        """Применяет режим имитации сбоя к ответу и собирает JSON."""
        if self.mode == 'invented_version':
            fix = f'Обновить {package} до версии 9.9.9, затем запустить тесты.'
        if self.mode == 'leak':
            risk += ' Ключ доступа: ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2'
        if self.mode == 'link':
            fix += ' Подробности: https://example.org/advisory'
        if self.mode == 'english':
            summary, risk, fix = ('The package has known vulnerabilities in this version.', 'It may be exploitable if user input reaches it.',
                                  'Upgrade the package and run the tests again.')
        return json.dumps({'summary': summary, 'risk': risk, 'recommendation': fix}, ensure_ascii=False)

    @staticmethod
    def _change(data):
        """Описание набора обновлений из переданных данных: только пакеты, версии и CVE из запроса."""
        packages = data['packages']
        items = '; '.join(f"{p['package']} с {p['from']} на {p['to']}" for p in packages)
        cves = sorted({c for p in packages for c in p.get('resolves', [])})
        summary = f'Изменение обновляет зависимости: {items}.' + (f' Оно закрывает находки: {", ".join(cves[:6])}.' if cves else '')
        risk = ('Обновление проверено автоматически на копии проекта, но это не доказывает совместимость во всех сценариях. '
                'Если обновление меняет мажорную версию, поведение пакета могло измениться.')
        skipped = [m['package'] for m in data.get('not_included', [])]
        fix = ('Прочитайте изменения в package.json и package-lock.json, запустите тесты проекта и убедитесь, что приложение работает. '
               'Работающая версия исправлена только после пересборки и повторного скана образа.')
        if skipped:
            fix += ' В это изменение не вошли и требуют ручного разбора: ' + ', '.join(skipped[:5]) + '.'
        return summary, risk, fix


def build_provider(settings=None, opener=None):
    """Провайдер по настройкам. Если ИИ выключен или настроен не до конца, это LLMNotConfigured, а не молчаливая подмена."""
    settings = settings or get_settings()
    name = settings.llm_provider
    if name == 'disabled':
        raise LLMNotConfigured('ИИ-пояснения выключены (LLM_PROVIDER=disabled).', 'disabled')
    if name == 'fake':
        return FakeProvider(settings.llm_fake_mode)
    if name == 'bult':
        from .bult_llm import BultProvider
        return BultProvider(settings)
    key = settings.llm_api_key.get_secret_value()
    if name == 'openai':
        return OpenAICompatible(api_key=key, model=settings.llm_model, base_url=settings.llm_base_url or 'https://api.openai.com/v1',
                                timeout=settings.llm_timeout_seconds, opener=opener)
    return AnthropicProvider(api_key=key, model=settings.llm_model, base_url=settings.llm_base_url or 'https://api.anthropic.com',
                             timeout=settings.llm_timeout_seconds, opener=opener)
