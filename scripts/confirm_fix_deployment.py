"""Подтверждение, что исправление применено: PR слит, образ собран после слияния, повторный скан не видит находку.

Порядок:
  1. Человек сливает PR на GitHub (система слияние не выполняет).
  2. Образ пересобирается из слитого кода и публикуется в реестр.
  3. Запускается новая проверка этого образа (POST /api/checks) и дожидается завершения.
  4. python scripts/confirm_fix_deployment.py <id запуска агента> <id новой проверки образа>

Нужны GITHUB_FIX_TOKEN (достаточно прав на чтение: Contents и Pull requests: Read), FIX_PR_ALLOWED_REPOS и DATABASE_URL.
Если доказательств не хватает, находка остаётся «прошла проверку», а скрипт называет причину.
"""
import argparse
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from app.check_report import load_report  # noqa: E402
from app.database import get_engine  # noqa: E402
from app.fix_deployment import confirm_deployment  # noqa: E402
from app.fix_runs import FixRunError  # noqa: E402
from app.github_pr import GitHubClient, GitHubError  # noqa: E402
from app.models import DependencyFixRun, Scan  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('run_id', type=uuid.UUID, help='идентификатор запуска агента (его печатает run_fix_check.py)')
    parser.add_argument('rescan_id', type=uuid.UUID, help='идентификатор новой завершённой проверки пересобранного образа')
    args = parser.parse_args()
    try:
        client = GitHubClient.from_environment()
    except GitHubError as exc:
        sys.exit(str(exc))
    with sessionmaker(bind=get_engine(), expire_on_commit=False)() as db:
        try:
            run = confirm_deployment(db, args.run_id, args.rescan_id, client)
        except FixRunError as exc:
            sys.exit(f'Подтверждение не выполнено: {exc}')
        deployment = run.deployment
        report = load_report(db, db.get(Scan, db.get(DependencyFixRun, run.id).scan_id), limit=500)
    print(f"Итог: {deployment['status']}  (образ {deployment['image_digest']})")
    pull = deployment['pull_request']
    print(f"PR №{pull['number']}: {'слит ' + str(pull['merged_at']) if pull['merged'] else 'не слит'}")
    for reason in deployment['reasons']:
        print(f'  Не хватает: {reason}')
    print(f"Находки: {deployment['counts']}")
    print(f"По статусам в отчёте: {report['facts']['by_status']}")
    print('Проверен опубликованный образ: система не наблюдает, что именно он запущен в эксплуатации.')


if __name__ == '__main__':
    main()
