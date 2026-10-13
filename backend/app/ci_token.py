"""Узкий доступ для CI: токен позволяет только запускать проверки и читать их результат.

Зачем: обычный вход в API идёт через GitHub и cookie, из CI так войти нельзя. Токен CI не заменяет вход: он выключен, пока
не заданы CI_TRIGGER_TOKEN и CI_TRIGGER_OWNER_ID, и даёт ровно три действия от имени одного владельца проектов:
POST /api/checks (запустить проверку), GET /api/checks/<id> и GET /api/checks/<id>/report (прочитать). Остальное API
с этим токеном закрыто (403), а проверки, как и для человека, видят только данные этого владельца.
Токен хранится только на сервере и в секретах CI, сравнивается за постоянное время, в логи и ответы не попадает.
"""
import hashlib
import hmac
import re
import uuid

from .config import get_settings

CHECK_PATH = re.compile(r'/api/checks/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:/report)?')
MAX_HEADER = 512


def _digest(value):
    return hashlib.sha256(value.encode()).digest()


def ci_access(request):
    """Возвращает (решение, владелец): ('none', None) токена нет или он не подошёл,
    ('ok', owner) токен верный и действие разрешено, ('denied', None) токен верный, но действие не разрешено."""
    settings = get_settings()
    secret = settings.ci_trigger_token.get_secret_value()
    header = request.headers.get('authorization', '')
    if not secret or len(header) > MAX_HEADER or header[:7].lower() != 'bearer ':
        return 'none', None
    if not hmac.compare_digest(_digest(header[7:].strip()), _digest(secret)):
        return 'none', None
    path, method = request.url.path, request.method
    if (method == 'POST' and path == '/api/checks') or (method == 'GET' and CHECK_PATH.fullmatch(path)):
        return 'ok', uuid.UUID(settings.ci_trigger_owner_id)
    return 'denied', None
