"""Запуск агента исправлений для проверки образа из БД и сохранение результата.

Пример:
  python scripts/run_fix_check.py <id проверки образа> ~/projects/bultshield-training-app
  python scripts/run_fix_check.py <id проверки образа> ~/projects/bultshield-training-app --plan-only
  python scripts/run_fix_check.py <id> ~/projects/bultshield-training-app --create-pr --repo владелец/репозиторий

С --create-pr после проверки показывается текст PR, и PR создаётся только после подтверждения (нужны GITHUB_FIX_TOKEN
и FIX_PR_ALLOWED_REPOS). PR привязывается к запуску: позже его слияние подтверждает scripts/confirm_fix_deployment.py.

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
from app.fix_runs import FixRunError, execute_run, record_pull_request  # noqa: E402
from app.github_pr import GitHubClient, GitHubError, build_pr_body, create_fix_pr, fix_set_from_agent  # noqa: E402
from app.llm_change import draft_change_note  # noqa: E402
from app.llm_plan import make_planner  # noqa: E402
from app.models import Scan  # noqa: E402
from run_fix_agent import plan_only  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('check_id', type=uuid.UUID, help='идентификатор завершённой проверки образа')
    parser.add_argument('project')
    parser.add_argument('--commit', help='полный SHA коммита проекта (по умолчанию из git проекта)')
    parser.add_argument('--plan-only', action='store_true', help='только план версий, без Docker')
    parser.add_argument('--no-llm-plan', action='store_true', help='не просить модель выбирать версии (только правила)')
    parser.add_argument('--create-pr', action='store_true', help='после проверки создать PR (с подтверждением)')
    parser.add_argument('--repo', help='владелец/репозиторий на GitHub (для --create-pr)')
    parser.add_argument('--base-branch', default='main')
    parser.add_argument('--project-path', default='', help='папка проекта внутри репозитория, например app/')
    args = parser.parse_args()
    project = Path(args.project).expanduser()
    if not project.is_dir():
        sys.exit(f'Каталог проекта не найден: {project}')
    if args.create_pr and (args.plan_only or not args.repo):
        sys.exit('--create-pr нужен вместе с --repo и без --plan-only: PR создаётся только по настоящей проверке.')
    kwargs = {'verify': plan_only} if args.plan_only else {}
    with sessionmaker(bind=get_engine(), expire_on_commit=False)() as db:
        if not args.no_llm_plan:
            kwargs['planner'] = make_planner(db, args.check_id)   # без подключённой модели выбирают правила
        print('Проверяю обновления в песочнице (несколько минут)...')
        try:
            run, result = execute_run(db, args.check_id, project, commit_sha=args.commit, **kwargs)
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
    for choice in section['version_choices']:
        who = 'модель' if choice['accepted'] else 'правила'
        print(f"  Версия {choice['package']}: {choice['installed']} -> {choice['final_target']} (выбрали: {who}; "
              f"модель предложила {choice['model_target'] or 'ничего'}, правила {choice['rule_target']}"
              + (f"; отказ: {choice['rejected_outcome']}" if choice['rejected_outcome'] else '') + ')')
    print(f"\nПо статусам: {report['facts']['by_status']}")
    print('Это результат проверки в песочнице: работающее приложение не исправлено.')
    if args.create_pr:
        create_pull_request(args, run, result)


def describe_change(run, fix):
    """Описание изменения от модели для текста PR. Нет модели или сбой: PR остаётся прежним, причина попадёт в его текст."""
    with sessionmaker(bind=get_engine(), expire_on_commit=False)() as db:
        note = draft_change_note(db, run.scan_id, run.id, fix)
    if note['status'] == 'NOT_CONFIGURED':
        return None   # модель не подключена: ничего не запрашивалось, текст PR без раздела модели
    print(f"Описание от модели: {note['status']}" + (f" ({note['message']})" if note['message'] else '')
          + f", токены {note['input_tokens']}+{note['output_tokens']}, ${note['cost_usd']:.4f}" + (' (повторное использование)' if note['reused'] else ''))
    return note


def create_pull_request(args, run, result):
    if not run.commit_sha:
        sys.exit('PR не создан: проект не является git-репозиторием, версию кода определить нельзя.')
    try:
        fix = fix_set_from_agent(result)
    except GitHubError as exc:
        sys.exit(f'PR не создан: {exc}')
    fix.note = describe_change(run, fix)
    print('\n--- Текст PR ---\n' + build_pr_body(fix, run.commit_sha))
    if input(f'Создать PR в {args.repo}? Для подтверждения введите имя репозитория: ').strip() != args.repo:
        sys.exit('Не подтверждено, PR не создан.')
    try:
        pr = create_fix_pr(GitHubClient.from_environment(), args.repo, base_branch=args.base_branch, base_sha=run.commit_sha,
                           fix=fix, confirmed=True, project_path=args.project_path)
        with sessionmaker(bind=get_engine(), expire_on_commit=False)() as db:
            record_pull_request(db, run.id, url=pr['url'], branch=pr['branch'], base_sha=run.commit_sha, created=pr['created'])
    except (GitHubError, FixRunError) as exc:
        sys.exit(f'PR не создан или не записан: {exc}')
    print(('Создан PR: ' if pr['created'] else 'PR уже был открыт: ') + pr['url'])
    print(f'PR привязан к запуску {run.id}. Слияние выполняет человек; потом: scripts/confirm_fix_deployment.py {run.id} <id новой проверки образа>')


if __name__ == '__main__':
    main()
