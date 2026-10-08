"""Агент исправлений + создание PR после подтверждения.

Сначала без GitHub (токен не нужен), покажет, что попадёт в PR:
  python scripts/run_fix_pr.py ~/projects/sandbox-trial ~/projects/image-scans/no-fix.json --dry-run

Настоящий PR (нужны GITHUB_FIX_TOKEN и FIX_PR_ALLOWED_REPOS=владелец/репозиторий):
  python scripts/run_fix_pr.py ПРОЕКТ ОТЧЁТ.json --repo владелец/репозиторий --base-sha <40 символов>
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from app.fix_agent import run_fix_agent  # noqa: E402
from app.github_pr import GitHubClient, GitHubError, build_pr_body, create_fix_pr, fix_set_from_agent  # noqa: E402
from app.image_report import ImageReportError, parse_image_report  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('project')
    parser.add_argument('baseline', help='JSON-отчёт Trivy по исходному образу')
    parser.add_argument('--repo', help='владелец/репозиторий на GitHub')
    parser.add_argument('--base-branch', default='main')
    parser.add_argument('--base-sha', help='полный SHA коммита, для которого сделана проверка')
    parser.add_argument('--project-path', default='', help='папка проекта внутри репозитория, например app/')
    parser.add_argument('--dry-run', action='store_true', help='только показать PR, ничего не отправлять')
    args = parser.parse_args()
    try:
        findings = parse_image_report(json.loads(Path(args.baseline).expanduser().read_text())).findings
    except (OSError, ValueError, ImageReportError) as exc:
        sys.exit(f'Не удалось прочитать отчёт: {exc}')
    print('Проверяю обновления в песочнице (несколько минут)...')
    result = run_fix_agent(Path(args.project).expanduser(), findings)
    try:
        fix = fix_set_from_agent(result)
    except GitHubError as exc:
        sys.exit(f'{exc}\nИтоги по пакетам: {result.summary}')
    names = ', '.join(item['package'] for item in fix.packages)
    print(f'\nВ PR войдут: {names}')
    for name in sorted(fix.files):
        print(f'  {name}: {len(fix.original[name])} -> {len(fix.files[name])} байт')
    if args.dry_run:
        print('\n--- Текст PR ---\n' + build_pr_body(fix, args.base_sha))
        print('Dry-run: ничего не отправлено.')
        return
    if not args.repo or not args.base_sha:
        sys.exit('Для настоящего PR нужны --repo и --base-sha.')
    print('\n--- Текст PR ---\n' + build_pr_body(fix, args.base_sha))
    if input(f'Создать PR в {args.repo}? Для подтверждения введите имя репозитория: ').strip() != args.repo:
        sys.exit('Не подтверждено, PR не создан.')
    try:
        pr = create_fix_pr(GitHubClient.from_environment(), args.repo, base_branch=args.base_branch, base_sha=args.base_sha,
                           fix=fix, confirmed=True, project_path=args.project_path)
    except GitHubError as exc:
        sys.exit(f'PR не создан: {exc}')
    print(('Создан PR: ' if pr['created'] else 'PR уже был открыт: ') + pr['url'])


if __name__ == '__main__':
    main()
