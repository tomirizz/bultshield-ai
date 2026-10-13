#!/usr/bin/env python3
"""Запуск проверки образа из CI после сборки. Только стандартная библиотека Python: файл можно просто скопировать в репозиторий проекта.

Пример (после docker build и docker push, образ указывается по digest, чтобы результат относился к конкретной сборке):
  BULTSHIELD_URL=https://bultshield.example BULTSHIELD_REPOSITORY_ID=<id> BULTSHIELD_TOKEN=<токен CI> \\
  python3 ci_check.py --image registry.example/app@sha256:... --watch --wait 600

Настройки: --url / BULTSHIELD_URL, --repository-id / BULTSHIELD_REPOSITORY_ID, токен только из окружения BULTSHIELD_TOKEN
(в аргументах командной строки он был бы виден в списке процессов; сервер без входа через GitHub, например локальный, токен не требует).

Проверка НЕ блокирует деплой: код возврата 0, даже если найдены уязвимости или проверку не удалось запустить. В последнем случае
скрипт громко предупреждает (в GitHub Actions как warning): «проверка не выполнена» никогда не означает «уязвимостей нет».
С --strict код возврата 2, если проверка не запустилась или завершилась ошибкой (находки код возврата не меняют).
--watch: образ опубликован, сервер будет перепроверять его по расписанию.
--wait N: ждать результат до N секунд и показать итог; без него скрипт только ставит проверку в очередь.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

DONE = ('COMPLETED', 'FAILED')
LOCAL = ('localhost', '127.0.0.1', '::1')


class Refused(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # токен не должен уйти на другой адрес


def warn(message):
    # В GitHub Actions строка станет заметным предупреждением в интерфейсе запуска.
    print(f'::warning title=BultShield::{message}' if os.environ.get('GITHUB_ACTIONS') else f'ВНИМАНИЕ: {message}', flush=True)


def call(method, url, token, body=None, timeout=30):
    headers = {'Accept': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    data = None
    if body is not None:
        data, headers['Content-Type'] = json.dumps(body).encode(), 'application/json'
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=timeout) as response:
            return response.status, json.loads(response.read(5_000_000))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read(100_000)).get('detail')
        except (ValueError, AttributeError):
            detail = None
        return exc.code, {'detail': detail if isinstance(detail, str) else None}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise Refused(f'сервис проверки недоступен ({type(getattr(exc, "reason", exc)).__name__})') from None


REFUSALS = {401: 'сервер не принял токен или вход не выполнен (проверьте BULTSHIELD_TOKEN)',
            403: 'токену CI это действие запрещено',
            404: 'репозиторий не найден (проверьте BULTSHIELD_REPOSITORY_ID)',
            409: 'для этого репозитория уже идёт другая проверка',
            422: 'запрос отклонён',
            429: 'очередь проверок заполнена'}


def explain(status, body):
    text = REFUSALS.get(status, f'неожиданный ответ сервера (HTTP {status})')
    return f"{text}: {body['detail']}" if body.get('detail') and status in (409, 422, 429) else text


def show_result(base, check, token):
    status, report = call('GET', f"{base}/api/checks/{check['id']}/report?limit=1", token)
    if status != 200:
        warn(f'проверка завершена, но отчёт не прочитан: {explain(status, report)}')
        return
    verdict, facts = report['verdict'], report['facts']
    print(f"Итог: {verdict['statement']}")
    print(f"Находок: {facts['total_findings']}; по серьёзности: {facts['by_severity']}; по статусам: {facts['by_status']}")
    changes = report.get('changes_since_previous')
    if changes:
        print(f"С прошлой проверки образа: новых {changes['new']}, исправлено {changes['fixed']}. {changes['explanation']}")
    print("Это проверка образа в реестре, а не гарантия, что именно он запущен в эксплуатации.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--url', default=os.environ.get('BULTSHIELD_URL', ''))
    parser.add_argument('--repository-id', default=os.environ.get('BULTSHIELD_REPOSITORY_ID', ''))
    parser.add_argument('--image', required=True, help='ссылка на образ в реестре, лучше с digest: registry/app@sha256:...')
    parser.add_argument('--watch', action='store_true', help='перепроверять образ по расписанию')
    parser.add_argument('--wait', type=int, default=0, metavar='СЕКУНДЫ', help='ждать результат не дольше этого времени (0: не ждать)')
    parser.add_argument('--strict', action='store_true', help='код возврата 2, если проверка не запустилась или завершилась ошибкой')
    args = parser.parse_args()
    token = os.environ.get('BULTSHIELD_TOKEN', '')
    failed = False
    try:
        base = args.url.rstrip('/')
        parsed = urlsplit(base)
        if not parsed.hostname or parsed.scheme not in ('http', 'https') or not args.repository_id:
            raise Refused('не заданы BULTSHIELD_URL (адрес сервиса) или BULTSHIELD_REPOSITORY_ID')
        if token and parsed.scheme != 'https' and parsed.hostname not in LOCAL:
            raise Refused('токен нельзя отправлять по http: используйте https')
        status, check = call('POST', f'{base}/api/checks', token,
                             {'repository_id': args.repository_id, 'image': args.image, 'watch': args.watch, 'trigger': 'ci'})
        if status != 202:
            raise Refused(explain(status, check))
        print(f"Проверка образа поставлена в очередь: {check['id']}\nОтчёт: {base}/api/checks/{check['id']}/report", flush=True)
        deadline = time.monotonic() + max(0, args.wait)
        while args.wait and check['status'] not in DONE and time.monotonic() < deadline:
            time.sleep(min(5, max(0.5, deadline - time.monotonic())))
            status, check = call('GET', f"{base}/api/checks/{check['id']}", token)
            if status != 200:
                raise Refused(explain(status, check))
        if args.wait and check['status'] not in DONE:
            warn(f"результат не получен за {args.wait} с: проверка продолжается на сервере (статус {check['status']}), отчёт по ссылке выше")
        elif check['status'] == 'FAILED':
            failed = True
            warn(f"ПРОВЕРКА ЗАВЕРШИЛАСЬ ОШИБКОЙ, образ НЕ проверен до конца: {check.get('error_message') or check.get('error_code')}. "
                 'Это не значит, что уязвимостей нет.')
        elif check['status'] == 'COMPLETED':
            show_result(base, check, token)
    except Refused as exc:
        failed = True
        warn(f'ПРОВЕРКА НЕ ЗАПУЩЕНА: {exc}. Образ не проверен; это не значит, что уязвимостей нет. Деплой не блокируется.')
    sys.exit(2 if failed and args.strict else 0)


if __name__ == '__main__':
    main()
