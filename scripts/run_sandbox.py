"""Ручной запуск песочницы: проверить обновление пакета в копии проекта.

Пример:
  python scripts/run_sandbox.py ~/projects/sandbox-trial lodash 4.18.1 ~/projects/image-scans/demo-main.json
Где последний аргумент — JSON-отчёт Trivy по исходному образу (до исправления).
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from app.image_report import ImageReportError, parse_image_report  # noqa: E402
from app.sandbox import FixCandidate, verify_fix  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('project')
    parser.add_argument('package')
    parser.add_argument('version')
    parser.add_argument('baseline', help='JSON-отчёт Trivy по исходному образу')
    parser.add_argument('--json', help='сохранить полный результат в этот файл')
    args = parser.parse_args()
    try:
        baseline = parse_image_report(json.loads(Path(args.baseline).expanduser().read_text())).findings
        candidate = FixCandidate(args.package, args.version)
    except (OSError, ValueError, ImageReportError) as exc:
        sys.exit(f'Не удалось подготовить проверку: {exc}')
    result = verify_fix(Path(args.project).expanduser(), candidate, baseline)
    print(f'ИТОГ: {result.outcome}')
    print(result.reason)
    print('\nШаги:')
    for step in result.steps:
        print(f"  {step['name']:<8} {step['status']:<8} {step['seconds']:>6} c")
    if result.failed_step:
        failed = [s for s in result.steps if s['name'] == result.failed_step]
        if failed and failed[-1]['log_tail']:
            print(f'\nКонец лога шага «{result.failed_step}»:\n{failed[-1]["log_tail"]}')
    for title, items in (('Закрыто', result.resolved), ('Осталось', result.remaining), ('Новые', result.introduced)):
        print(f'\n{title}: ' + (', '.join(f"{i['rule_id']} ({i['package']})" for i in items) or 'нет'))
    if result.diff:
        print('\nDiff (кратко):')
        print('\n'.join(line for line in result.diff.splitlines() if line.startswith(('+', '-')) and not line.startswith(('+++', '---'))))
    if args.json:
        Path(args.json).expanduser().write_text(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
        print(f'\nПолный результат: {args.json}')
    sys.exit(0 if result.outcome == 'FIX_VERIFIED' else 1)


if __name__ == '__main__':
    main()
