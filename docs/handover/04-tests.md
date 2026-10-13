# Проверки и доказательства

## Итог после живой проверки LLM

**840 passed, 4 skipped, 1 warning in 103.56s** — [полный лог](evidence/backend-tests-llm-final.txt), код `51fdac6`. Дополнительно 177 целевых тестов, Ruff и проверка diff прошли. Новые регрессии защищают точные названия пакетов, отклоняют смешанные алфавиты и противоречащий успешным тестам ответ настоящей Qwen. Реальные ответы модели, описание PR и повтор без расхода токенов — [09](09-test-prototype-llm-acceptance.md).

Новые доказательства: `examples/bult-live/bult-llm-v6-report.json`, `bult-llm-v6-job.json`, `bult-llm-v6-cached.json`; `evidence/bult-pr-description-real.json`, `bult-pr-description-preview.md`, `backend-tests-llm-final.txt`. Четыре пропущенных теста не засчитываются как пройденные.

## Предыдущий прогон живого стенда

Актуальный прогон после исправлений живого стенда: **836 passed, 4 skipped, 1 warning in 96.03s**. Лог: [backend-tests-live-release.txt](evidence/backend-tests-live-release.txt). Дополнительно 3 frontend-теста, TypeScript/Vite build и Ruff прошли; [CI ac769fc](https://github.com/tomirizz/bultshield-ai/actions/runs/38452715093) — success. Новые регрессии проверяют блокировку очереди/аудита, Docker Hub digest, транспорт Bult и ограничение ожидания интерфейса. Живые результаты Bult и непроверенные пункты — в [08](08-function1-live-acceptance.md).

## Исторический локальный прогон до исправлений Bult

Итог полного прогона на отдельной PostgreSQL `bultshield_handover_test`: **815 passed, 4 skipped, 1 warning in 90.57s (0:01:30)**. Собрано 819 тестов. Запуск: `python scripts/check_backend.py` с `TEST_DATABASE_URL`; одновременно работал только один процесс pytest. Лог: [evidence/backend-tests.txt](evidence/backend-tests.txt).

Четыре пропуска: реальный Gitleaks, два теста реального Semgrep (включая цикл исправления), реальный Nuclei. Эти исполняемые файлы не установлены в локальном окружении. Реальный Trivy 0.74.0 доступен, его проверка выполнилась. Предупреждение Starlette о будущем изменении тестового HTTP-клиента не является падением; обновление зависимостей вне этой задачи не выполнялось.

Автотесты используют настоящую PostgreSQL, серверные обработчики через TestClient и функции worker; внешние сервисы в большинстве тестов заменены тестовыми ответами. Это не означает 819 проверок настоящего Docker, GitHub и LLM. Отдельно проведены живые сценарии ниже, с настоящими API, Docker и Trivy.

## Что проверить при сдаче — все шесть сценариев

| Сценарий | Автотест | Живой результат |
|---|---|---|
| Исправимая уязвимость | `test_sandbox.py::test_verified_fix_runs_every_step_in_isolation`; `test_several_fixes_are_verified_together_in_one_pass` | `evidence/fixable-before-after.json`: form-data 2.5.6 + qs 6.16.0, `FIX_VERIFIED`, 4 целевые находки исчезли; установка, тесты, сборка, запуск, здоровье и повторный скан успешны; diff сохранён |
| Нет доступного исправления | `test_fix_agent.py::test_finding_without_fixed_version_is_manual` | `evidence/no-fix-plan.json` и полный агент: request 2.88.2, CVE-2023-28155, ручное рассмотрение |
| Обновление ломает тесты | `test_sandbox.py::test_failing_tests_break_the_app_and_stop_the_pipeline` | `evidence/breaking-update.txt`: uuid 11.1.1, `BREAKS_APP`, ошибка загрузки `uuid/v4` на шаге тестов; воспроизведено и полным агентом |
| После изменения проблема осталась | `test_sandbox.py::test_still_vulnerable_is_detected_by_finding_not_by_count` | `evidence/still-detected.json`: `STILL_DETECTED`, по lodash 4 закрыты / 3 остались; оговорка о понижении версии и историческом сравнении в 03 |
| Сбой сканера/сервиса не выглядит чистым | `test_check_report.py::test_verdicts_never_turn_failure_into_clean`; `test_image_pipeline.py::test_scanner_failure_is_stored_as_failed_not_as_clean`; `test_ci_rescan.py` | три `static-FAILED-*.json` имеют `INCOMPLETE`; `evidence/ci-unavailable.txt` предупреждает о не выполненной проверке, код возврата 0 |
| Модель недоступна | `test_llm_jobs.py::test_unavailable_model_finishes_the_job_and_changes_nothing_else`; `test_llm.py` | `evidence/llm-unavailable.json`: реальное задание API завершилось, итог модели `UNAVAILABLE`, факты до/после совпадают; внешний сбой имитировался режимом fake |

## Требования функции 1

| Требование | Подтверждение и граница |
|---|---|
| Сканировать зависимости и образ | Trivy в `ci-live-report.json`: 265 находок, 4 CRITICAL / 62 HIGH / 117 MEDIUM / 78 LOW / 4 UNKNOWN; `test_image_scan.py`, `test_image_report.py`, `test_trivy.py` |
| Связь версии кода и образа | `revision-linked-report.json`, `revision-link.json`: коммит `cde718910cf0c6398c7c083b51851da00e8843fb` и digest `sha256:727eae31d4351274db6c28287f2496809cb0e8311159a7301f08a0c257b809e8`; `test_image_jobs.py::test_image_revision_survives_worker_storage_and_report` проверяет метку и её отсутствие |
| Единый формат находок | `findings.items` в примерах содержит проблему, критичность, компонент, источник, доступную версию/причину ручного решения; `test_image_pipeline.py`, `test_check_report.py` |
| Пояснения LLM и описание изменений | `llm-explained-report.json`: 20 fake-пояснений, 32 группы пропущены по лимиту; `test_llm.py`, `test_llm_change.py`. Это исторический fake-прогон; настоящая модель и описание PR теперь проверены в [09](09-test-prototype-llm-acceptance.md) |
| Изолированная проверка исправления | полный Docker-цикл в `fixable-before-after.json`; ограничения изоляции в 05; `test_sandbox.py` |
| Показать diff и причину неудачи | `diff`, `reason`, `steps` в `fixable-before-after.json`/`still-detected.json`; `test_sandbox.py`, `test_check_report.py` |
| Проверка после сборки и повторные сканы | `ci-live-report.json` (`trigger=ci`), `scheduled-live-report.json` (`trigger=schedule`), оба завершены; механизм расписания принудительно вызван с возрастом 0, ожидание суток не выполнялось; `test_ci_rescan.py` |
| Не блокировать деплой | недоступный сервис: код 0 и явное предупреждение, `ci-unavailable.txt`; `test_ci_rescan.py` |
| Подтверждение человеком перед PR | `test_github_pr.py` проверяет защиту; новых PR в этой работе нет; подготовленный diff доступен локально |
| Раздельные «проверено» и «применено» | `fixable-before-after.json` — локальная песочница; исторический `image-COMPLETED-7da01386.json` — сохранённое применение к опубликованному образу, не к работающему сервису; `test_check_report.py::test_verified_fix_is_not_reported_as_deployed`, `test_fix_deployment.py` |

## Общие требования ТЗ

| Требование | Подтверждение |
|---|---|
| Ключи только на backend, не в интерфейсе | настройки скрывают ключ; `test_llm.py`, `test_ci_rescan.py`; для живого демо ключи не использовались |
| Не отправлять секреты и необработанные данные | обезличенные запросы в `llm-estimate.txt`, тесты очистки в `test_llm.py`, `test_llm_change.py` |
| Учитывать запросы/токены/стоимость и лимиты | `llm-explanations.txt`, `llm-estimate.txt`, 06; тесты в `test_llm.py`; цены реального провайдера не заданы |
| Таймаут, ограничения API, плохие ответы | `test_llm.py`, `test_llm_change.py` используют локальный подставной HTTP-сервер; живой негативный режим — `llm-unavailable.json` |
| Проверять формат и не исполнять текст LLM | `test_llm.py`, `test_llm_change.py`; модель даёт пояснение к детерминированному плану обновления |
| Длительные операции в фоне, сохранённые результаты | API/worker + PostgreSQL: `ci-live-report.json`, `llm-unavailable.json`; `test_image_jobs.py`, `test_llm_jobs.py` |
| Повтор без дубликатов | два запроса вернули то же активное задание в `llm-unavailable.json`; повтор использует 20 пояснений без новых токенов в `llm-reuse.json`; `test_llm_jobs.py`, `test_ci_rescan.py`, `test_github_pr.py` |
| Проверять доступ владельца | автоматические тесты `test_auth.py`, `test_llm.py`, `test_llm_jobs.py`, `test_ci_rescan.py`. Живое демо работает без авторизации только на 127.0.0.1; многопользовательская эксплуатация не проверена |
| Тестовый адаптер и реальные API Bult | **Будущий этап интеграции, не требуется сейчас по уточнению ментора**: адаптера ресурсов Bult в этой версии нет; интерфейсы LLM не засчитываются за Bult. Требуются контракт и отдельный стенд |
| Разделять факты, предположения, действия | реальные JSON-отчёты: `facts`, `assumptions`, `proposed_actions`; `test_check_report.py` |

## Причины трёх FAILED-проверок исходников

| Проверка | Подтверждённая причина | Итог отчёта |
|---|---|---|
| `3bd56c8b` | Gitleaks и Semgrep не установлены; Trivy завершился, 4 находки сохранены | `FAILED / INCOMPLETE` |
| `4247ede4` | Gitleaks и Semgrep не установлены; Trivy завершился, 8 находок сохранены | `FAILED / INCOMPLETE` |
| `e7065736` | `CHECKOUT_FAILED`: не удалось загрузить репозиторий; точная низкоуровневая причина старого сбоя не сохранена | `FAILED / INCOMPLETE`, даже при 0 находок |

Точный текст вывода: «Проверка выполнена не полностью. Отсутствие находок в этом отчёте не означает отсутствие уязвимостей». Гипотеза об отсутствующих сканерах объясняет только первые две проверки.

## Исправленные дефекты и повторные проверки

1. Рабочая база обновлена с `0012` до `0013`; API и worker работают с fake-моделью. `environment.txt` фиксирует успешную готовность.
2. Исправлены права вложенных тестовых данных. Первый неудачный и повторный успешный по сценарию результаты сохранены; содержимое тестового приложения не подгонялось.
3. Тест настроек очищает `LLM_PROVIDER` для проверки значения по умолчанию; исходный полный прогон имел 1 падение, лог сохранён. После исправления: 813 прошли / 4 пропущены.
4. Исправлена потеря коммита образа. Новый регрессионный тест до изменения падал, после изменения прошли оба случая (метка есть / метки нет). Финальный полный прогон: 815 прошли / 4 пропущены.
5. Проверка качества кода Ruff нашла два старых нарушения в импортах тестов; исправлены только импорты. Проверка всего `backend` и `scripts` теперь проходит. Затронутые тестовые модули дополнительно выполнены после этой правки; отдельный лог `import-cleanup-tests.txt`.

Ни один из этих прогонов не использовал рабочую базу для очищающих тестов. Данные прежних демонстраций сохранены. Для этих исторических прогонов настоящая LLM и PR не проверялись. Актуальные живые результаты и границы — в 09; будущая интеграция — в 05.

## Реально созданные примеры и доказательства

### examples/

- [ci-live-report.json](examples/ci-live-report.json) — Свежий полный отчёт проверки с trigger=ci.
- [image-COMPLETED-14233040.json](examples/image-COMPLETED-14233040.json) — История проверки 14233040: COMPLETED, итог FINDINGS, находок 259.
- [image-COMPLETED-6f20e71d.json](examples/image-COMPLETED-6f20e71d.json) — История проверки 6f20e71d: COMPLETED, итог FINDINGS, находок 265.
- [image-COMPLETED-7da01386.json](examples/image-COMPLETED-7da01386.json) — История проверки 7da01386: COMPLETED, итог FINDINGS, находок 263.
- [image-COMPLETED-a67e6414.json](examples/image-COMPLETED-a67e6414.json) — История проверки a67e6414: COMPLETED, итог FINDINGS, находок 259.
- [image-COMPLETED-ef3146d5.json](examples/image-COMPLETED-ef3146d5.json) — История проверки ef3146d5: COMPLETED, итог FINDINGS, находок 265.
- [llm-explained-report.json](examples/llm-explained-report.json) — Факты сканера и 20 пояснений fake, отделённых от фактов.
- [llm-unavailable-report.json](examples/llm-unavailable-report.json) — Отчёт после недоступной fake-модели с сохранёнными фактами.
- [revision-linked-report.json](examples/revision-linked-report.json) — Живой отчёт с коммитом и digest после исправления передачи метки.
- [scheduled-live-report.json](examples/scheduled-live-report.json) — Свежий полный отчёт повторной проверки с trigger=schedule.
- [static-FAILED-3bd56c8b.json](examples/static-FAILED-3bd56c8b.json) — История проверки 3bd56c8b: FAILED, итог INCOMPLETE, находок 4.
- [static-FAILED-4247ede4.json](examples/static-FAILED-4247ede4.json) — История проверки 4247ede4: FAILED, итог INCOMPLETE, находок 8.
- [static-FAILED-e7065736.json](examples/static-FAILED-e7065736.json) — История проверки e7065736: FAILED, итог INCOMPLETE, находок 0.

### evidence/

- [backend-tests-before-revision-fix.txt](evidence/backend-tests-before-revision-fix.txt) — Полный прогон после исправления теста настроек, до добавления двух проверок метки.
- [backend-tests-first-attempt.txt](evidence/backend-tests-first-attempt.txt) — Первый полный прогон и падение из-за LLM_PROVIDER в окружении.
- [backend-tests.txt](evidence/backend-tests.txt) — Финальный полный прогон: 815 успешно, 4 пропущены.
- [breaking-update.txt](evidence/breaking-update.txt) — Настоящий BREAKS_APP при uuid 11.1.1.
- [ci-image-check.txt](evidence/ci-image-check.txt) — Запуск Trivy-проверки опубликованного образа через CI-скрипт.
- [ci-unavailable.txt](evidence/ci-unavailable.txt) — Недоступный API, явное предупреждение и код возврата 0.
- [commands-help.txt](evidence/commands-help.txt) — Проверенные аргументы всех девяти CLI-скриптов.
- [environment.txt](evidence/environment.txt) — Здоровье API/БД, миграция 0013 и версия Trivy.
- [failed-scans.txt](evidence/failed-scans.txt) — Причины трёх существующих FAILED-проверок.
- [fixable-before-after.json](evidence/fixable-before-after.json) — Полный план и результаты Docker-проверок, diff и совместный FIX_VERIFIED.
- [fixable-before-after.txt](evidence/fixable-before-after.txt) — Читаемый вывод агента по пяти пакетам.
- [import-cleanup-tests.txt](evidence/import-cleanup-tests.txt) — Дополнительные тесты после исправления импортов.
- [llm-estimate.txt](evidence/llm-estimate.txt) — Dry-run: 20 запросов, около 15 305 входных, максимум 12 000 выходных токенов.
- [llm-explanations.txt](evidence/llm-explanations.txt) — Первый успешный фоновой запуск fake-пояснений и срабатывание лимита.
- [llm-reuse.json](evidence/llm-reuse.json) — Повтор: 20 переиспользований, 0 новых токенов.
- [llm-unavailable.json](evidence/llm-unavailable.json) — Имитация недоступности, одинаковое активное задание, неизменные факты.
- [no-fix-plan.json](evidence/no-fix-plan.json) — Машиночитаемый план, request без доступного исправления.
- [no-fix-plan.txt](evidence/no-fix-plan.txt) — Читаемый план без Docker; версии получены через npm.
- [revision-link.json](evidence/revision-link.json) — Реальная связь локально собранного образа с коммитом, без изменений GitHub.
- [revision-regression-after.txt](evidence/revision-regression-after.txt) — Оба случая метки коммита проходят после исправления.
- [revision-regression-before.txt](evidence/revision-regression-before.txt) — Тест воспроизводит потерю коммита до исправления.
- [ruff-before.txt](evidence/ruff-before.txt) — Два нарушения импортов до исправления.
- [ruff.txt](evidence/ruff.txt) — Успешная проверка качества кода backend и scripts.
- [scheduled-rescan.txt](evidence/scheduled-rescan.txt) — Принудительный запуск того же механизма расписания и результат worker.
- [still-detected-first-attempt.json](evidence/still-detected-first-attempt.json) — Первый неудачный запуск: права файлов не позволяли Node.js читать package.json.
- [still-detected-first-attempt.txt](evidence/still-detected-first-attempt.txt) — Читаемый журнал ошибки прав файлов; сохранён без подмены.
- [still-detected.json](evidence/still-detected.json) — Повтор после исправления прав: 4 находки закрыты, 3 остались.
- [still-detected.txt](evidence/still-detected.txt) — Читаемый STILL_DETECTED, пройденные шаги и разница файлов.
- [summary.txt](evidence/summary.txt) — Первоначальный итог штатного collect_evidence.py.

## Повторная проверка перед публикацией GitHub

По отдельному запросу владельца полностью повторены локальные тесты: **815 прошли, 4 пропущены, 1 предупреждение, 90.08 с**. Сборка интерфейса и Ruff проходят. npm audit обнаружил уязвимость высокой критичности в транзитивной зависимости сборки `source-map-js 1.2.1`; точечное обновление до 1.2.2 закрыло её, повторный audit — 0 известных уязвимостей. Тестовое уязвимое приложение не изменялось.

- [backend-recheck.txt](evidence/backend-recheck.txt) — повторный полный прогон на отдельной тестовой базе.
- [frontend-audit-before.json](evidence/frontend-audit-before.json) — исходная находка npm audit с идентификатором advisory.
- [frontend-audit-after.json](evidence/frontend-audit-after.json) — повторная проверка после обновления, 0 находок.
- [github-preflight.json](evidence/github-preflight.json) — сводка локальной проверки перед отправкой. Результат GitHub Actions проверяется отдельно на удалённом коммите.

## Живая проверка Bult и Qwen

13 октября проверены панель Bult, health endpoints, вход через GitHub и свежий запрос старого помощника к Qwen. Задание `8ff60afc-5f04-44ec-86e1-6b114ddec82c` завершилось COMPLETED; журнал llama.cpp подтвердил генерацию. Выявлены неточная рекомендация модели и расхождение версий: стенд main/schema 0009, новая ветка/schema 0013. Это не приёмка нового LLM-пути функции 1 или отсутствующего адаптера ресурсов Bult. Полный отчёт — [07](07-bult-live-verification.md). Код приложения в ходе этой проверки не менялся, полный набор тестов повторно не запускался.

- [bult-live-verification.json](evidence/bult-live-verification.json) — наблюдения панели, endpoints, контрольный вопрос и ответ, границы проверки.
- [bult-model-runtime.txt](evidence/bult-model-runtime.txt) — точно переписанные выдержки живого журнала llama.cpp, время и счётчики токенов.
