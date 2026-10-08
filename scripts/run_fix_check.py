"""Запуск агента исправлений для проверки образа из БД и сохранение результата.

Пример:
  python scripts/run_fix_check.py <id проверки образа> ~/projects/bultshield-training-app
  python scripts/run_fix_check.py <id проверки образа> ~/projects/bultshield-training-app --plan-only

Что делает: берёт находки этой проверки из БД, проверяет обновления в песочнице (Docker) на копии проекта,
записывает результат в БД и печатает статусы так, как их покажет отчёт GET /api/checks/<id>/report.
Версию кода берёт из git проекта: если в каталоге есть незакоммиченные изменения, запуск отклоняется.
Нужны DATABASE_URL (переменная окружения или .env) и применённые миграции.
"""
import argparse
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.check_report import load_report  # noqa: E402
from app.database import get_engine  # noqa: E402
from app.fix_runs import FixRunError, run_agent_for_scan  # noqa: E402
from app.models import Scan  # noqa: E402
from run_fix_agent import plan_only  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('check_id', type=uuid.UUID, help='идентификатор завершённой проверки образа')
    parser.add_argument('project')
    parser.add_argument('--commit', help='полный SHA коммита проекта (по умолчанию из git проекта)')
    parser.add_argument('--plan-only', action='store_true', help='только план версий, без Docker')
    args = parser.parse_args()
    project = Path(args.project).expanduser()
    if not project.is_dir():
        sys.exit(f'Каталог проекта не найден: {project}')
    kwargs = {'verify': plan_only} if args.plan_only else {}
    with sessionmaker(bind=get_engine(), expire_on_commit=False)() as db:
        print('Проверяю обновления в песочнице (несколько минут)...')
        try:
            run = run_agent_for_scan(db, args.check_id, project, commit_sha=args.commit, **kwargs)
        except FixRunError as exc:
            sys.exit(f'Запуск не выполнен: {exc}')
        report = load_report(db, db.get(Scan, args.check_id), limit=500)
    section = report['fix_run']
    print(f"\nЗапуск {run.id}: {section['status']}, коммит {section['commit_sha'] or 'не определён'}")
    print(f"Образ: {section['image_digest']}")
    for item in report['findings']['items']:
        if item['origin'] != 'app':
            continue
        print(f"  {item['status_text']:<38} {item['rule_id']:<16} {item['component']} {item['installed_version']}"
              + (f"\n      {item['status_reason']}" if item['status_reason'] else ''))
    print(f"\nПо статусам: {report['facts']['by_status']}")
    print('Это результат проверки в песочнице: работающее приложение не исправлено.')


if __name__ == '__main__':
    main()
