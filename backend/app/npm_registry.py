"""Список версий npm-пакета и пометки «устарело» из публичного реестра.

Нужен, чтобы не предложить версию, которую авторы пакета сами пометили устаревшей (так было с lodash 4.18.0).
Обращение идёт только к registry.npmjs.org по HTTPS, ответ ограничен по размеру и времени. Ошибка реестра
никогда не превращается в пустой список: вызывающий код получает исключение и отправляет находку на ручной разбор.
"""
import json
import re
import urllib.error
import urllib.request
from urllib.parse import quote

BASE = 'https://registry.npmjs.org/'
MAX_BYTES = 20 * 1024 * 1024
# Имя проверяется так же строго, как в песочнице: первый символ буква или цифра.
_PACKAGE = re.compile(r'(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*')
_ACCEPT = 'application/vnd.npm.install-v1+json'


class RegistryError(RuntimeError):
    """Реестр недоступен или вернул неожиданный ответ."""


def fetch_versions(package, *, timeout=20, opener=urllib.request.urlopen):
    """Возвращает (все версии, версии с пометкой deprecated) для пакета."""
    if not isinstance(package, str) or not _PACKAGE.fullmatch(package) or len(package) > 214:
        raise RegistryError('Некорректное имя пакета.')
    request = urllib.request.Request(BASE + quote(package, safe='@').replace('/', '%2F'),
                                     headers={'Accept': _ACCEPT, 'User-Agent': 'bultshield-security-agent'})
    try:
        with opener(request, timeout=timeout) as response:
            raw = response.read(MAX_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RegistryError(f'Реестр npm недоступен: {type(exc).__name__}.') from None
    if len(raw) > MAX_BYTES:
        raise RegistryError('Ответ реестра npm превышает лимит размера.')
    try:
        versions = json.loads(raw).get('versions')
    except (ValueError, AttributeError):
        raise RegistryError('Ответ реестра npm не удалось разобрать.') from None
    if not isinstance(versions, dict) or not versions:
        raise RegistryError('В ответе реестра npm нет списка версий.')
    deprecated = [version for version, meta in versions.items()
                  if isinstance(meta, dict) and isinstance(meta.get('deprecated'), str) and meta['deprecated']]
    return list(versions), deprecated
