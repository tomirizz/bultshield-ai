"""Ручной запуск агента исправлений: план обновлений и проверка каждого в песочнице.

Пример:
  python scripts/run_fix_agent.py ~/projects/sandbox-trial ~/projects/image-scans/demo-main.json
  python scripts/run_fix_agent.py ~/projects/sandbox-trial ~/projects/image-scans/demo-main.json --plan-only
Последний режим только выбирает версии (нужен интернет для реестра npm) и не запускает Docker.
"""
import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from app.fix_agent import FIX_PASSED, FIX_PROPOSED, run_fix_agent  # noqa: E402
from app.image_report import ImageReportError, parse_image_report  # noqa: E402
from app.sandbox import INCONCLUSIVE  # noqa: E402

LABELS = {FIX_PASSED: 'ИСПРАВЛЕНИЕ ПРОШЛО ПРОВЕРКУ', FIX_PROPOSED: 'ИСПРАВЛЕНИЕ ПРЕДЛОЖЕНО',
          'manual_intervention': 'РУЧНОЕ ВМЕШАТЕЛЬСТВО'}


def plan_only(project, candidate, baseline, **kwargs):
    reason = 'проверка в песочнице не запускалась (режим --plan-only).'
    return SimpleNamespace(outcome=INCONCLUSIVE, reason=reason, as_dict=lambda: {'outcome': INCONCLUSIVE, 'reason': reason})


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('project')
    parser.add_argument('baseline', help='JSON-отчёт Trivy по исходному образу')
    parser.add_argument('--plan-only', action='store_true', help='только план, без Docker')
    parser.add_argument('--json', help='сохранить полный результат в этот файл')
    args = parser.parse_args()
    try:
        findings = parse_image_report(json.loads(Path(args.baseline).expanduser().read_text())).findings
    except (OSError, ValueError, ImageReportError) as exc:
        sys.exit(f'Не удалось прочитать отчёт: {exc}')
    kwargs = {'verify': plan_only} if args.plan_only else {}
    result = run_fix_agent(Path(args.project).expanduser(), findings, **kwargs)
    print('Пакеты приложения:')
    for item in result.packages:
        target = f'{item.installed} -> {item.target}' if item.target else item.installed
        review = '  [нужен просмотр человеком]' if item.needs_review else ''
        print(f'\n  {item.package}  {target}{review}\n    {LABELS[item.status]}\n    {item.reason}')
        if item.verification and item.verification.get('method'):
            print(f"    способ: {item.verification['method']}")
    if result.other:
        print('\nНе приложение (ручной разбор, песочница не применяется):')
        for group in result.other:
            print(f"  {group['origin']:<13} {group['count']:>3} шт.: {group['reason']}")
    print(f'\nИтого: {result.summary}')
    if args.json:
        Path(args.json).expanduser().write_text(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
        print(f'Полный результат: {args.json}')


if __name__ == '__main__':
    main()
