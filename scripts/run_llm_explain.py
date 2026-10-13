"""Пояснения языковой модели к находкам проверки: что отправится, запрос к модели, что вошло в отчёт.

Примеры:
  python scripts/run_llm_explain.py <id проверки> --dry-run     # только показать, что отправится (ничего не отправляется)
  LLM_PROVIDER=fake python scripts/run_llm_explain.py <id>       # тестовая модель без сети
  LLM_PROVIDER=fake LLM_FAKE_MODE=unavailable python scripts/run_llm_explain.py <id>   # имитация недоступной модели

Настройки (переменные окружения или .env): LLM_PROVIDER (disabled | fake | openai | anthropic), LLM_API_KEY, LLM_MODEL, LLM_BASE_URL,
LLM_MAX_CALLS_PER_CHECK, LLM_DAILY_CALL_LIMIT, LLM_PRICE_INPUT_PER_MTOK, LLM_PRICE_OUTPUT_PER_MTOK.
Ключ читается только из окружения сервера и нигде не печатается.

Пояснение модели — предположение: оно не меняет находки, статусы и исправления. Если модель недоступна,
проверка и отчёт остаются прежними, а причина отсутствия пояснений показывается в разделе llm отчёта.
"""
import argparse
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from app.check_report import load_report  # noqa: E402
from app.database import get_engine  # noqa: E402
from app.llm_explain import explain_check  # noqa: E402
from app.models import Scan  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('check_id', type=uuid.UUID, help='идентификатор проверки')
    parser.add_argument('--dry-run', action='store_true', help='показать, что отправится модели, ничего не отправляя и не сохраняя')
    parser.add_argument('--max-calls', type=int, help='не больше стольки запросов за этот запуск (и не больше LLM_MAX_CALLS_PER_CHECK)')
    args = parser.parse_args()
    with sessionmaker(bind=get_engine(), expire_on_commit=False)() as db:
        try:
            summary = explain_check(db, args.check_id, dry_run=args.dry_run, max_calls=args.max_calls)
        except LookupError as exc:
            sys.exit(str(exc))
        if summary['status'] == 'NOT_CONFIGURED':
            sys.exit(f"Модель не подключена: {summary['message']}\nДля проверки без сети: LLM_PROVIDER=fake")
        print(f"Провайдер: {summary['provider']}, модель: {summary['model']}")
        if args.dry_run:
            print(f"\nРЕЖИМ ПРОВЕРКИ: ничего не отправлено. Было бы запросов: {summary['planned']}, пропущено из-за лимита: {summary['skipped']}")
            for p in summary['prompts']:
                print(f"\n--- {p['subject']} (~{p['estimated_input_tokens']} входных токенов)")
                print('Отправится модели:', p['request'])
            print(f"\nОценка: входных токенов ~{summary['estimated_input_tokens']}, выходных не больше {summary['max_output_tokens']}, "
                  f"стоимость не больше ${summary['estimated_cost_usd_max']:.4f} (если цены заданы в настройках)")
            return
        print(f"\nИтог: {summary['status']}. Новых пояснений: {summary['completed']}, уже были: {summary['reused']}, "
              f"сбоев: {summary['failed']}, пропущено: {summary['skipped']}")
        print(f"Токены: {summary['input_tokens']} входных, {summary['output_tokens']} выходных, стоимость ${summary['cost_usd']:.4f}")
        for error in summary['errors']:
            print('  причина:', error)
        report = load_report(db, db.get(Scan, args.check_id), limit=500)
    print(f"\nРаздел llm отчёта: {report['llm']['status']} — {report['llm']['message']}")
    for a in report['assumptions']:
        if a['source'] == 'llm_explanation':
            print(f"\n[{a['subject']}] (предположение модели {a['model']})\n  Что это: {a['explanation']}\n  Риск: {a['risk']}\n  Что делать: {a['recommended_fix']}")
    print(f"\nСтатусы находок не менялись: {report['facts']['by_status']}")


if __name__ == '__main__':
    main()
