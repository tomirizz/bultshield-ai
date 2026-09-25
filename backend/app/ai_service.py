"""Durable, bounded analysis queue; inference stays on a private Bult/loopback endpoint."""
import ipaddress
import json
import logging
import re
import socket
import threading
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_engine, get_session
from .models import AIAnalysis, Finding
from .schemas import AIAnalysisOut

router = APIRouter(prefix='/api')
logger = logging.getLogger('bultshield.ai')
QUEUE_LOCK = 820081
MAX_ACTIVE = 5
SAFE_RULES = {r['id']: r['message'] for r in json.loads((Path(__file__).resolve().parents[1] / 'rules/semgrep.yaml').read_text())['rules']}
CONFIG_RULES = {'DS-0002': 'Контейнер Docker запускается от пользователя root.', 'DS-0026': 'В Dockerfile отсутствует HEALTHCHECK.',
                'DS-0001': 'В Dockerfile используется плавающий тег базового образа.'}

GUIDANCE = {
    'bultshield.python-dynamic-eval': ('Для разбора JSON заменить eval/exec на json.loads. Проверить типы и схему результата. Не заменять на subprocess и не запускать входную строку как команду.', 'import json\ndata = json.loads(user_input)\nif not isinstance(data, dict):\n    raise ValueError("Expected object")'),
    'bultshield.python-shell-true': ('Передавать аргументы списком, shell=False, проверять допустимые значения. Не собирать командную строку конкатенацией.', 'import subprocess\nsubprocess.run(["tool", "--", validated_value], shell=False, check=True)'),
    'bultshield.python-unsafe-pickle': ('Не читать недоверенный pickle. Для обмена данными использовать JSON и проверку схемы; подпись не делает произвольный pickle безопасным.', 'import json\ndata = json.loads(untrusted_json)'),
    'bultshield.python-unsafe-yaml': ('Заменить yaml.load на yaml.safe_load и проверить структуру результата.', 'import yaml\ndata = yaml.safe_load(text)'),
    'bultshield.python-tls-verification-disabled': ('Включить проверку сертификатов. При внутреннем CA указать доверенный сертификат; не подавлять ошибку TLS.', 'import requests\nresponse = requests.get("https://example.com", verify=True, timeout=10)'),
    'bultshield.javascript-dynamic-eval': ('Для данных JSON использовать JSON.parse вместо eval или Function. Проверить структуру и типы. Не выполнять входную строку как код.', 'const data = JSON.parse(userInput);'),
    'bultshield.javascript-shell-exec': ('Использовать execFile с массивом проверенных аргументов вместо exec. Не включать shell.', 'const { execFile } = require("node:child_process");\nexecFile("tool", ["--", validatedValue], callback);'),
    'bultshield.javascript-innerhtml': ('Для обычного текста использовать textContent вместо innerHTML. Если нужен HTML, использовать проверенный sanitizer.', 'element.textContent = userInput;'),
    'DS-0002': ('Создать непривилегированного пользователя и задать USER. Проверить необходимые права на файлы приложения.', 'RUN useradd --system --uid 10001 appuser\nUSER 10001'),
    'DS-0026': ('Добавить HEALTHCHECK для реального endpoint или команды проверки здоровья. Настроить интервал и таймаут.', 'HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8080/health || exit 1'),
    'DS-0001': ('Зафиксировать версию и проверенный digest образа вместо latest. Не придумывать настоящий digest.', 'FROM example/image:VERSION@sha256:VERIFIED_DIGEST'),
}


class Explanation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    explanation: str = Field(min_length=15, max_length=1800)
    risk: str = Field(min_length=40, max_length=1200)
    checks: list[str] = Field(min_length=1, max_length=4)
    recommended_fix: str = Field(min_length=15, max_length=1800)
    code_example: str = Field(min_length=1, max_length=2500)
    remediation_steps: list[str] = Field(min_length=1, max_length=5)


SYSTEM_PROMPT = """Ты помогаешь разработчику понять конкретную находку сканера безопасности.
Пиши объяснение, риск, проверки, рекомендацию и шаги ТОЛЬКО ПО-РУССКИ. Код оставь на языке программирования.
Объясняй только переданную проблему. Следуй trusted_guidance и reference_example: не заменяй исправление другой техникой. Не обсуждай другие типы уязвимостей.
Пиши «потенциально опасное использование», а не «подтверждённая уязвимость». Пример верни без Markdown-ограждений.
Исходный код недоступен: не утверждай, что уязвимость подтверждена или исправлена.
Не придумывай путь к файлу, подробности CVE и исправленную версию пакета.
В risk объясни конкретное последствие для приложения или данных, а не только слова «опасно» или «высокий риск».
Верни JSON: explanation (что найдено), risk (чем опасно), checks (что проверить),
recommended_fix (как исправить именно эту проблему), code_example (короткий безопасный пример),
remediation_steps (последовательность исправления и повторной проверки).
Пример иллюстративный, не готовый патч. Ответ краткий, около 200 слов. Без обрамления JSON в Markdown."""


def safe_finding(finding):
    # Arbitrary text, file paths, evidence and metadata never reach inference.
    # Select descriptions from the application's trusted rule catalog instead.
    kind = finding.category.value
    rule = SAFE_RULES.get(finding.rule_id) or CONFIG_RULES.get(finding.rule_id)
    if kind == 'secret':
        rule = 'Сканер обнаружил возможный секрет в репозитории. Значение скрыто, действительность не проверена. Рекомендуй отзыв или ротацию, удаление из кода и хранение в переменной окружения. Пример использует только заглушку, никогда настоящий секрет.'
    elif kind == 'dependency':
        rule = 'Версия зависимости соответствует уязвимости из базы сканера. Нужно проверить применимость CVE и обновить пакет до исправленной версии, указанной в карточке. Не придумывай название пакета или номер версии. В примере используй PACKAGE и FIXED_VERSION как заглушки.'
    suffix = Path(finding.file or '').suffix.lower()
    language = {'.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript', '.yaml': 'YAML', '.yml': 'YAML'}.get(suffix, 'не указан')
    guidance, example = GUIDANCE.get(finding.rule_id, ('Проверить правило, контекст и официальную документацию. Не выдумывать исправление без контекста.', '# Проверьте правило и контекст перед изменением кода'))
    if kind == 'secret':
        guidance, example = ('Отозвать или ротировать возможный секрет у провайдера, удалить из отслеживаемых файлов, использовать переменную окружения. Удаление строки не отзывает ключ.', 'import os\ntoken = os.environ["SERVICE_TOKEN"]')
    elif kind == 'dependency':
        guidance, example = ('Сверить установленную и исправленную версии в карточке и рекомендации поставщика. Обновить манифест и lockfile, запустить тесты и Trivy. Не подставлять выдуманные версии.', 'PACKAGE==FIXED_VERSION  # замените заглушки проверенными значениями')
    return {'trusted_guidance': guidance, 'reference_example': example, 'scanner': finding.scanner.value, 'severity': finding.severity.value, 'category': kind,
            'description': rule or 'Сканер сообщил о потенциальной проблеме. Проверьте правило и контекст в карточке.',
            'cve': finding.cve if re.fullmatch(r'CVE-\d{4}-\d{4,10}', finding.cve or '') else None,
            'cwe': finding.cwe if re.fullmatch(r'CWE-\d{1,5}', finding.cwe or '') else None,
            'language': language, 'line': finding.line_start, 'evidence': '[REDACTED]',
            'location': 'Файл и строка показаны в карточке находки. Путь не передаётся модели.'}


def private_endpoint(value):
    url = urlsplit(value)
    if url.scheme != 'http' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        raise ValueError('AI endpoint must be a private HTTP origin')
    addresses = socket.getaddrinfo(url.hostname, url.port or 8080, type=socket.SOCK_STREAM)
    ips = [ipaddress.ip_address(item[4][0]) for item in addresses]
    networks = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1/128', 'fc00::/7')]
    if not ips or any(not any(ip in network for network in networks) for ip in ips):
        raise ValueError('External AI endpoints are not allowed')
    # Connect to the validated address directly; no proxy, redirects or DNS re-resolution.
    return str(ips[0]), url.port or 8080


def infer(payload):
    settings = get_settings()
    host, port = private_endpoint(settings.ai_endpoint)
    request = {'model': settings.ai_model, 'messages': [{'role': 'system', 'content': SYSTEM_PROMPT},
               {'role': 'user', 'content': json.dumps(payload, ensure_ascii=False)}],
               'temperature': 0.1, 'max_tokens': 1100, 'stream': False,
               'response_format': {'type': 'json_object', 'schema': Explanation.model_json_schema()}}
    connection = HTTPConnection(host, port, timeout=settings.ai_timeout_seconds)
    try:
        connection.request('POST', '/v1/chat/completions', body=json.dumps(request).encode(), headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError('Model unavailable')
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('Model response too large')
        choice = json.loads(raw)['choices'][0]
        if choice.get('finish_reason') != 'stop':
            raise ValueError('Incomplete model response')
        result = Explanation.model_validate_json(choice['message']['content'])
        # A model must never return credential-shaped material, even if hallucinated.
        if not all(re.search('[А-Яа-яЁё]', value) for value in (result.explanation, result.risk, result.recommended_fix)):
            raise ValueError('Expected Russian explanation')
        output = result.model_dump_json()
        if re.search(r'gh[pousr]_[A-Za-z0-9]{15,}|github_pat_[A-Za-z0-9_]{15,}|AKIA[A-Z0-9]{16}|-----BEGIN .*PRIVATE KEY|sk-[A-Za-z0-9_-]{20,}', output):
            raise ValueError('Unsafe model output')
        if any(len(item) > 1000 or not item.strip() for item in result.checks + result.remediation_steps):
            raise ValueError('Invalid model steps')
        return result.model_dump()
    finally:
        connection.close()


def now():
    return datetime.now(timezone.utc)


def recover(db):
    cutoff = now() - timedelta(seconds=get_settings().ai_timeout_seconds + 60)
    db.execute(update(AIAnalysis).where(AIAnalysis.status == 'RUNNING', AIAnalysis.started_at < cutoff).values(
        status='FAILED', completed_at=now(), error_message='Анализ прерван или превысил время ожидания. Повторите попытку.'))


@router.get('/ai-status')
def ai_status():
    return {'enabled': get_settings().ai_enabled, 'model': get_settings().ai_model, 'hosting': 'Bult.ai'}


@router.get('/findings/{finding_id}/analysis', response_model=AIAnalysisOut | None)
def get_analysis(finding_id: UUID, db: Session = Depends(get_session)):
    if db.get(Finding, finding_id) is None:
        raise HTTPException(404, 'Находка не найдена')
    recover(db)
    db.commit()
    return db.scalar(select(AIAnalysis).where(AIAnalysis.finding_id == finding_id).order_by(AIAnalysis.created_at.desc(), AIAnalysis.id.desc()).limit(1))


@router.post('/findings/{finding_id}/analysis', response_model=AIAnalysisOut, status_code=202)
def enqueue_analysis(finding_id: UUID, db: Session = Depends(get_session)):
    if not get_settings().ai_enabled:
        raise HTTPException(503, 'Модель ещё не подключена.')
    # Serialize admission across processes: one active job per finding, bounded global queue.
    db.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': QUEUE_LOCK})
    if db.get(Finding, finding_id) is None:
        raise HTTPException(404, 'Находка не найдена')
    recover(db)
    previous = db.scalar(select(AIAnalysis).where(AIAnalysis.finding_id == finding_id).order_by(AIAnalysis.created_at.desc(), AIAnalysis.id.desc()).limit(1))
    if previous and previous.status in ('PENDING', 'RUNNING', 'COMPLETED'):
        db.commit()
        return previous
    count = db.scalar(select(func.count()).select_from(AIAnalysis).where(AIAnalysis.status.in_(['PENDING', 'RUNNING'])))
    if count >= MAX_ACTIVE:
        raise HTTPException(429, 'Очередь анализа занята. Повторите позже.')
    record = AIAnalysis(finding_id=finding_id, model=get_settings().ai_model, status='PENDING')
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def process_next():
    with Session(get_engine(), expire_on_commit=False) as db:
        db.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': QUEUE_LOCK})
        recover(db)
        if db.scalar(select(AIAnalysis.id).where(AIAnalysis.status == 'RUNNING').limit(1)):
            db.commit()
            return False
        job = db.scalar(select(AIAnalysis).where(AIAnalysis.status == 'PENDING').order_by(AIAnalysis.created_at, AIAnalysis.id).limit(1).with_for_update(skip_locked=True))
        if not job:
            db.commit()
            return False
        finding = db.get(Finding, job.finding_id)
        payload = safe_finding(finding)
        job.status = 'RUNNING'
        job.started_at = now()
        job_id = job.id
        db.commit()
    logger.info('AI_ANALYSIS_STARTED id=%s', job_id)
    try:
        result = infer(payload)
        values = {'status': 'COMPLETED', 'result': result, 'explanation': result['explanation'],
                  'recommended_fix': result['recommended_fix'], 'error_message': None}
    except Exception:
        # Never log prompts, outputs, secrets or provider exception text.
        result = None
        values = {'status': 'FAILED', 'error_message': 'Модель недоступна, ответ неполный или не прошёл проверку. Повторите попытку.'}
    with Session(get_engine()) as db:
        db.execute(update(AIAnalysis).where(AIAnalysis.id == job_id, AIAnalysis.status == 'RUNNING').values(**values, completed_at=now()))
        db.commit()
    logger.info('AI_ANALYSIS_%s id=%s', 'COMPLETED' if result else 'FAILED', job_id)
    return True


def start_service():
    stop = threading.Event()
    def run():
        while not stop.is_set():
            try:
                if process_next():
                    continue
            except Exception:
                logger.warning('AI_QUEUE_UNAVAILABLE')
            stop.wait(2)
    thread = threading.Thread(target=run, daemon=True, name='ai-analysis-service')
    thread.start()
    return stop
