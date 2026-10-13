"""Перепроверка опубликованных образов вручную (то же, что worker делает по расписанию).

Примеры:
  python scripts/run_image_rescan.py --list                      # какие образы под наблюдением и когда проверялись
  python scripts/run_image_rescan.py --older-than-hours 0        # поставить в очередь перепроверку сразу, не дожидаясь срока
  python scripts/run_image_rescan.py --older-than-hours 24 --limit 5

Образ попадает под наблюдение, если его последняя проверка запущена с watch (ci_check.py --watch или поле watch в POST /api/checks).
Скрипт только ставит перепроверки в очередь; саму проверку делает worker. Нужны DATABASE_URL и применённые миграции.
"""
import argparse
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from app.database import get_engine  # noqa: E402
from app.image_rescan import rescan_due, watched_images  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--list', action='store_true', help='только показать образы под наблюдением')
    parser.add_argument('--older-than-hours', type=float, default=24, help='перепроверять образы, последняя проверка которых старше (по умолчанию 24)')
    parser.add_argument('--limit', type=int, default=1, help='сколько перепроверок поставить в очередь за запуск')
    args = parser.parse_args()
    with sessionmaker(bind=get_engine(), expire_on_commit=False)() as db:
        if args.list:
            images = watched_images(db)
            for scan in images:
                age = datetime.now(UTC) - (scan.completed_at or scan.created_at)
                print(f"{scan.scanner_config['image']['reference']}: последняя проверка {scan.status.value}, {age.total_seconds() / 3600:.1f} ч назад ({scan.id})")
            print(f'Под наблюдением образов: {len(images)}')
            return
        created = rescan_due(db, timedelta(hours=args.older_than_hours), limit=args.limit)
        for scan in created:
            print(f"В очередь поставлена перепроверка {scan.id}: {scan.scanner_config['image']['reference']} (предыдущая {scan.scanner_config.get('rescan_of')})")
        if not created:
            print('Нет образов, которые пора перепроверить (или очередь заполнена).')
        else:
            print('Результат появится, когда worker закончит проверку: GET /api/checks/<id>/report, блок changes_since_previous.')


if __name__ == '__main__':
    main()
