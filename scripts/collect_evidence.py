#!/usr/bin/env python3
"""Сбор настоящих результатов для сдачи: ничего не придумывается, всё берётся из работающей системы.

Запуск (из корня проекта, API и worker запущены, Docker Desktop запущен):
  python scripts/collect_evidence.py --url http://127.0.0.1:8080

Что делает (каждый шаг независим: сбой одного не останавливает остальные и честно записывается в итог):
  1. отчёты последних проверок (в том числе завершившихся ошибкой) -> docs/handover/examples/*.json;
  2. причины ошибок проверок, завершившихся FAILED -> docs/handover/evidence/failed-scans.txt;
  3. обновление, которое ломает приложение: песочница с uuid 11.1.1 (ожидается BREAKS_APP) -> docs/handover/evidence/breaking-update.txt;
  4. пояснения модели (если в API и worker включён LLM_PROVIDER) -> docs/handover/evidence/llm-explanations.txt;
  5. оценка расходов на модель (ничего не отправляется) -> docs/handover/evidence/llm-estimate.txt;
  6. summary.txt: что получилось, а что нет.
Токены и ключи в файлы не попадают: скрипт их не читает и не печатает.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'handover'
HOME = Path.home()


def get(base, path, method='GET', timeout=30):
    request = urllib.request.Request(base + path, method=method, headers={'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read(20_000_000))
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read(100_000))
        except ValueError:
            body = {}
        return exc.code, body


def save(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def export_reports(base, count, log):
    status, scans = get(base, '/api/scans?limit=50')
    if status != 200:
        log.append(f'ОТЧЁТЫ: список проверок не получен ({status}).')
        return
    chosen = [s for s in scans if s.get('kind') != 'verification'][:count]
    for scan in chosen:
        code, report = get(base, f"/api/checks/{scan['id']}/report?limit=500")
        name = f"{scan.get('kind')}-{scan.get('status')}-{scan['id'][:8]}.json"
        if code == 200:
            log.append('ОТЧЁТ: ' + save(OUT / 'examples' / name, json.dumps(report, ensure_ascii=False, indent=1, default=str)))
        else:
            log.append(f"ОТЧЁТ {scan['id'][:8]}: не получен ({code}).")


def failed_scans(base, log):
    status, scans = get(base, '/api/scans?limit=100')
    if status != 200:
        log.append(f'FAILED-ПРОВЕРКИ: список не получен ({status}).')
        return
    lines = []
    for scan in scans:
        if scan.get('status') != 'FAILED':
            continue
        lines.append(f"{scan['id']} вид={scan.get('kind')} создана={scan.get('created_at')}")
        lines.append(f"  сообщение: {scan.get('error_message')} код: {scan.get('error_code')}")
        for name, result in (scan.get('scanner_results') or {}).items():
            lines.append(f"  сканер {name}: {result.get('status')} {result.get('error') or ''}".rstrip())
    log.append('FAILED-ПРОВЕРКИ: ' + save(OUT / 'evidence' / 'failed-scans.txt', '\n'.join(lines) or 'Проверок со статусом FAILED нет.'))


def breaking_update(log):
    project, baseline = HOME / 'projects' / 'sandbox-trial', HOME / 'projects' / 'image-scans' / 'no-fix.json'
    if not project.is_dir() or not baseline.is_file():
        log.append(f'СЛОМАННОЕ ОБНОВЛЕНИЕ: не найдены {project} или {baseline}.')
        return
    command = [sys.executable, str(ROOT / 'scripts' / 'run_sandbox.py'), str(project), 'uuid', '11.1.1', str(baseline)]
    started = time.monotonic()
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=1800, cwd=ROOT)
        text = f'$ python scripts/run_sandbox.py ~/projects/sandbox-trial uuid 11.1.1 ~/projects/image-scans/no-fix.json\n{done.stdout}{done.stderr}'
    except subprocess.TimeoutExpired:
        text = 'Песочница не завершилась за 30 минут: результат не определён.'
    first = next((line for line in text.splitlines() if line.startswith('ИТОГ')), 'ИТОГ не напечатан')
    log.append(f'СЛОМАННОЕ ОБНОВЛЕНИЕ: {first} ({int(time.monotonic() - started)} с) -> ' + save(OUT / 'evidence' / 'breaking-update.txt', text))


def llm_run(base, log, wait):
    status, scans = get(base, '/api/scans?limit=50')
    done = [s for s in scans if status == 200 and s.get('kind') == 'image' and s.get('status') == 'COMPLETED']
    if not done:
        log.append('ПОЯСНЕНИЯ МОДЕЛИ: нет завершённой проверки образа.')
        return
    check = done[0]['id']
    code, job = get(base, f'/api/checks/{check}/explanations', 'POST')
    if code != 202:
        log.append(f"ПОЯСНЕНИЯ МОДЕЛИ: задание не создано ({code}): {job.get('detail')}")
        save(OUT / 'evidence' / 'llm-explanations.txt', f"Проверка {check}: задание не создано ({code}): {job.get('detail')}")
        return
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        time.sleep(3)
        code, state = get(base, f'/api/checks/{check}/explanations')
        if code == 200 and state['job']['status'] in ('COMPLETED', 'FAILED'):
            break
    code, state = get(base, f'/api/checks/{check}/explanations')
    log.append('ПОЯСНЕНИЯ МОДЕЛИ: ' + save(OUT / 'evidence' / 'llm-explanations.txt', json.dumps({'check_id': check, **state}, ensure_ascii=False, indent=1, default=str)))


def llm_estimate(base, log):
    """Оценка расходов на модель для демо-проверки: что отправится и сколько это токенов (ничего не отправляется)."""
    status, scans = get(base, '/api/scans?limit=50')
    done = [s for s in scans if status == 200 and s.get('kind') == 'image' and s.get('status') == 'COMPLETED']
    if not done:
        log.append('ОЦЕНКА РАСХОДОВ: нет завершённой проверки образа.')
        return
    command = [sys.executable, str(ROOT / 'scripts' / 'run_llm_explain.py'), done[0]['id'], '--dry-run']
    env = {**os.environ, 'LLM_PROVIDER': os.environ.get('LLM_PROVIDER', 'fake')}
    done_process = subprocess.run(command, capture_output=True, text=True, timeout=300, cwd=ROOT, env=env)
    text = f'$ python scripts/run_llm_explain.py {done[0]["id"]} --dry-run\n{done_process.stdout}{done_process.stderr}'
    log.append('ОЦЕНКА РАСХОДОВ: ' + save(OUT / 'evidence' / 'llm-estimate.txt', text))


def main():
    global OUT
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--url', default=os.environ.get('BULTSHIELD_URL', ''))
    parser.add_argument('--reports', type=int, default=8, help='сколько последних проверок выгрузить')
    parser.add_argument('--skip-sandbox', action='store_true', help='не запускать песочницу (она идёт несколько минут и требует Docker)')
    parser.add_argument('--skip-estimate', action='store_true', help='не считать оценку расходов на модель (нужен доступ к БД)')
    parser.add_argument('--llm-wait', type=int, default=120)
    parser.add_argument('--out', default=str(OUT), help='куда сложить результаты (по умолчанию docs/handover)')
    args = parser.parse_args()
    OUT = Path(args.out).resolve()
    if not args.url.startswith(('http://', 'https://')):
        sys.exit('Укажите адрес: --url http://127.0.0.1:8080 или переменная BULTSHIELD_URL.')
    base, log = args.url.rstrip('/'), []
    steps = [('отчёты', lambda: export_reports(base, args.reports, log)), ('FAILED-проверки', lambda: failed_scans(base, log)),
             ('пояснения модели', lambda: llm_run(base, log, args.llm_wait))]
    if not args.skip_estimate:
        steps.append(('оценка расходов', lambda: llm_estimate(base, log)))
    if not args.skip_sandbox:
        steps.append(('сломанное обновление', lambda: breaking_update(log)))
    for name, step in steps:
        print(f'... {name}', flush=True)
        try:
            step()
        except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
            log.append(f'{name.upper()}: НЕ ВЫПОЛНЕНО ({type(exc).__name__}). Это не значит, что проблем нет.')
        print('   ' + log[-1], flush=True)
    print('\nИТОГ записан в ' + save(OUT / 'evidence' / 'summary.txt', '\n'.join(log)))


if __name__ == '__main__':
    main()
