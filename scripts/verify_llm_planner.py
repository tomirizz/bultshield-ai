"""Проверка выбранной модели на выборе версий для обновления. Запускать с собственным ключом, база данных не нужна.

Пример (ключ только в переменных окружения, скрипт его не печатает и не сохраняет):
  export LLM_PROVIDER=openai LLM_API_KEY=... LLM_MODEL=<модель> DATABASE_URL=postgresql+psycopg://x:x@localhost/x
  python scripts/verify_llm_planner.py            # 6 встроенных случаев
  python scripts/verify_llm_planner.py --repeat 3 # каждый случай трижды: видно, насколько ответ стабилен

Для каждого случая модель получает ровно тот запрос, что и агент исправлений (набор допустимых версий определяет код),
а ответ проходит ту же проверку parse_plan. Скрипт считает: сколько ответов прошло проверку, сколько раз модель
согласилась с версией правил, сколько раз выбрала другую допустимую версию, сколько отклонено и почему, токены и стоимость
(стоимость только если заданы LLM_PRICE_INPUT_PER_MTOK и LLM_PRICE_OUTPUT_PER_MTOK из тарифа провайдера).
Это проверка формата и дисциплины модели; безопасность версии определяет песочница, а не этот скрипт.
"""
import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from app.config import get_settings  # noqa: E402
from app.dependency_fix import candidate_versions  # noqa: E402
from app.llm import LLMError, LLMNotConfigured, build_provider, cost_usd  # noqa: E402
from app.llm_explain import InvalidResponse  # noqa: E402
from app.llm_plan import SYSTEM_PROMPT, parse_plan, plan_request  # noqa: E402

# (пакет, установленная версия, находки [(id, исправлено в, серьёзность)], версии из реестра, версия правил)
CASES = [
    ('lodash', '4.17.15', [('CVE-2021-23337', '4.17.21', 'HIGH'), ('CVE-2020-8203', '4.17.19', 'HIGH')],
     ['4.17.15', '4.17.19', '4.17.20', '4.17.21'], '4.17.21'),
    ('qs', '6.5.1', [('CVE-2022-24999', '6.5.3', 'HIGH')], ['6.5.1', '6.5.3', '6.9.7', '6.11.0', '6.14.0'], '6.5.3'),
    ('minimist', '1.2.0', [('CVE-2021-44906', '1.2.6', 'CRITICAL')], ['1.2.0', '1.2.6', '1.2.8'], '1.2.6'),
    ('express', '4.16.0', [('CVE-2024-29041', '4.19.2', 'MEDIUM'), ('CVE-2022-24999', '4.17.3', 'HIGH')],
     ['4.16.0', '4.17.3', '4.19.2', '4.21.2', '5.0.0', '5.1.0'], '4.19.2'),
    ('jsonwebtoken', '8.5.1', [('CVE-2022-23529', '9.0.0', 'HIGH')], ['8.5.1', '9.0.0', '9.0.2'], '9.0.0'),
    ('axios', '0.21.0', [('CVE-2021-3749', '0.21.2', 'HIGH'), ('CVE-2023-45857', '1.6.0', 'MEDIUM')],
     ['0.21.0', '0.21.2', '0.27.2', '1.6.0', '1.7.9'], '1.6.0'),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--repeat', type=int, default=1, help='сколько раз повторить каждый случай (1-5)')
    args = parser.parse_args()
    settings = get_settings()
    try:
        provider = build_provider(settings)
    except LLMNotConfigured as exc:
        sys.exit(f'Модель не настроена: {exc}')
    if provider.name == 'fake':
        sys.exit('LLM_PROVIDER=fake: это не настоящая модель. Задайте openai, anthropic или bult.')
    print(f'Провайдер: {provider.name}, модель: {getattr(provider, "model", None)}')
    totals, outcomes, inp, out = Counter(), Counter(), 0, 0
    for package, installed, found, available, default in CASES:
        findings = [{'rule_id': i, 'fixed_version': f, 'severity': s} for i, f, s in found]
        candidates = candidate_versions(installed, [(i, f) for i, f, _ in found], available, default=default)
        request = plan_request(package, installed, findings, candidates, default)
        print(f'\n{package} {installed}: допустимо {[c["version"] for c in candidates]}, правила -> {default}')
        if len(candidates) < 2:
            print('  один допустимый вариант: агент модель не спрашивает, случай пропущен')
            continue
        for _ in range(max(1, min(args.repeat, 5))):
            totals['asked'] += 1
            try:
                reply = provider.complete(SYSTEM_PROMPT, request, settings.llm_max_output_tokens)
            except LLMError as exc:
                outcomes[f'ошибка провайдера: {exc.code or type(exc).__name__}'] += 1
                print(f'  ошибка провайдера: {exc}')
                continue
            inp, out = inp + reply.input_tokens, out + reply.output_tokens
            try:
                plan = parse_plan(reply.text, request, candidates)
            except InvalidResponse as exc:
                outcomes[f'отклонён: {exc.code}'] += 1
                print(f'  отклонён ({exc.code}): {exc}')
                continue
            totals['valid'] += 1
            totals['agrees' if plan['target'] == default else 'differs'] += 1
            totals['review'] += plan['needs_review']
            print(f'  выбрано {plan["target"]} ({"как у правил" if plan["target"] == default else "иначе, чем у правил"}), '
                  f'нужен просмотр: {plan["needs_review"]}\n    причина: {plan["reason"]}\n    риск: {plan["risk"]}')
    print(f'\nЗапросов: {totals["asked"]}; ответ прошёл проверку: {totals["valid"]}; совпало с правилами: {totals["agrees"]}; '
          f'другая допустимая версия: {totals["differs"]}; с пометкой просмотра: {totals["review"]}')
    for name, count in outcomes.items():
        print(f'  {name}: {count}')
    print(f'Токены: вход {inp}, выход {out}.' + (f' Стоимость по заданному тарифу: ${cost_usd(inp, out, settings):.4f}.'
          if settings.llm_price_input_per_mtok or settings.llm_price_output_per_mtok else ' Тариф не задан, стоимость не считалась.'))
    print('Версию, которую выбрала модель, все равно проверяет песочница; при отказе действует версия правил.')


if __name__ == '__main__':
    main()
