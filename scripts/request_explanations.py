#!/usr/bin/env python3
"""Запрос пояснений модели к находкам проверки и ожидание результата. Только стандартная библиотека.

Пример:  BULTSHIELD_URL=http://127.0.0.1:8080 python scripts/request_explanations.py <id проверки> [--wait 120]

Работу выполняет worker в фоне; скрипт ставит задание, ждёт его и печатает итог. Сервер и worker должны быть запущены
с подключённой моделью (LLM_PROVIDER=fake для проверки без сети). Пояснения — предположения модели: статусы находок они не меняют.
Если модель недоступна, скрипт так и пишет, а результаты проверки остаются прежними.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

DONE = ('COMPLETED', 'FAILED')


def call(method, url, timeout=30):
    request = urllib.request.Request(url, method=method, headers={'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read(5_000_000))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read(100_000)).get('detail')
        except (ValueError, AttributeError):
            detail = None
        return exc.code, {'detail': detail if isinstance(detail, str) else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('check_id')
    parser.add_argument('--url', default=os.environ.get('BULTSHIELD_URL', ''))
    parser.add_argument('--wait', type=int, default=120, help='сколько секунд ждать результат (0: только поставить в очередь)')
    args = parser.parse_args()
    if not args.url.startswith(('http://', 'https://')):
        sys.exit('Укажите адрес сервера: --url или BULTSHIELD_URL (например http://127.0.0.1:8080).')
    base = f"{args.url.rstrip('/')}/api/checks/{args.check_id}"
    try:
        status, job = call('POST', base + '/explanations')
        if status != 202:
            sys.exit(f"Задание не создано ({status}): {job.get('detail') or 'причина не указана'}")
        print(f"Задание {job['id']}: {job['status']}" + (' (уже было в работе)' if job.get('already_running') else ''))
        deadline = time.monotonic() + args.wait
        while job['status'] not in DONE and time.monotonic() < deadline:
            time.sleep(2)
            status, state = call('GET', base + '/explanations')
            if status != 200:
                sys.exit(f'Не удалось прочитать состояние ({status}).')
            job = state['job']
        status, state = call('GET', base + '/explanations')
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        sys.exit(f'Сервер недоступен или ответил неожиданно ({type(exc).__name__}). Пояснения не получены; это не меняет результаты проверки.')
    job = state['job'] or job
    if job['status'] not in DONE:
        print(f"Задание ещё выполняется ({job['status']}). Запустите worker или посмотрите позже: GET {base}/explanations")
        return
    if job['status'] == 'FAILED':
        print(f"ЗАДАНИЕ НЕ ВЫПОЛНЕНО: {job['error']} Результаты сканеров и статусы от этого не зависят.")
        return
    result = job['result'] or {}
    print(f"Итог запросов к модели: {result.get('status')}. Получено: {result.get('completed', 0)}, уже были: {result.get('reused', 0)}, "
          f"сбоев: {result.get('failed', 0)}, пропущено: {result.get('skipped', 0)}")
    print(f"Токены: {result.get('input_tokens', 0)} входных, {result.get('output_tokens', 0)} выходных, стоимость ${result.get('cost_usd', 0):.4f}")
    print(f"Раздел llm отчёта: {state['llm']['status']}: {state['llm']['message']}")
    for failure in state['llm']['failures'][:5]:
        print(f"  причина: {failure['subject']}: {failure['message']}")
    status, report = call('GET', base + '/report?limit=500')
    shown = [a for a in report.get('assumptions', []) if a.get('source') == 'llm_explanation'][:2] if status == 200 else []
    for item in shown:
        print(f"\n[{item['subject']}] (предположение модели {item['model']})\n  Что это: {item['explanation']}\n  Что делать: {item['recommended_fix']}")
    print(f'\nВсе пояснения: GET {base}/report (раздел assumptions)')


if __name__ == '__main__':
    main()
