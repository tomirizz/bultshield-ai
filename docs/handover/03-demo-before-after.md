# Воспроизводимый сценарий «до/после»

Команды выполняются из корня `bultshield-ai` в окружении из [01-run.md](01-run.md). Все изменения зависимостей выполняются в временной копии Docker. Репозиторий `bultshield-training-app` и исходный `sandbox-trial` в этой работе не изменялись. PR, push и слияния не выполнялись.

## Данные

`docs/handover/data/sandbox-trial/` — Node.js-приложение с тестами и Dockerfile, без `.git` и `node_modules`. `data/image-scans/no-fix.json` и `demo-main.json` — сохранённые отчёты Trivy, не искусственные ответы. Большие `.tar` не входят в пакет.

Файлы приложения должны быть читаемы в контейнере: файлы 0644, каталоги 0755. При первой проверке копии имели права 0600/0700, из-за чего Node.js не мог прочитать `/app/package.json`; исправлены права, не содержимое приложения. Оба результата сохранены в `evidence/still-detected-first-attempt.*` и `evidence/still-detected.*`.

## 1. Исправимая уязвимость

Команда полного агента: `python scripts/run_fix_agent.py docs/handover/data/sandbox-trial docs/handover/data/image-scans/no-fix.json --json docs/handover/evidence/fixable-before-after.json`.

Агент получает находки из исходного отчёта, выбирает версии по реестру npm, устанавливает их в копии, запускает тесты без сети, собирает Docker-образ, запускает приложение без сети, проверяет `/health` и повторяет Trivy-скан. Результат нового запуска: **совместное обновление `form-data` до 2.5.6 и `qs` до 6.16.0 — `FIX_VERIFIED`, закрыты 4 целевые находки**. Изменения файлов показаны в поле `diff` полного JSON-результата. Сводка всех пакетов: 3 прошли индивидуальную проверку, 2 требуют ручного вмешательства; одно из прошедших обновлений требует просмотра человеком и не входит в совместный набор.

Это локально проверенный diff (разница между исходными и изменёнными файлами), а не применённое исправление в эксплуатации. Реальные выходы: [evidence/fixable-before-after.txt](evidence/fixable-before-after.txt), [evidence/fixable-before-after.json](evidence/fixable-before-after.json).

## 2. Уязвимость без исправления

`python scripts/run_fix_agent.py docs/handover/data/sandbox-trial docs/handover/data/image-scans/no-fix.json --plan-only --json docs/handover/evidence/no-fix-plan.json`.

Порядок аргументов: **сначала проект, потом отчёт**. `--plan-only` отключает Docker, но для выбора версий других пакетов всё ещё нужен доступ к реестру npm. `request 2.88.2`, `CVE-2023-28155` получает ручное рассмотрение: исправленной версии в исходном отчёте нет. Доказательства: `evidence/no-fix-plan.*` и полный запуск выше.

## 3. Обновление ломает тесты

`python scripts/run_sandbox.py docs/handover/data/sandbox-trial uuid 11.1.1 docs/handover/data/image-scans/no-fix.json`.

Получено `BREAKS_APP` на шаге `tests`: тест `request library loads` падает с `ERR_PACKAGE_PATH_NOT_EXPORTED`, поскольку `request` загружает `uuid/v4`. Дальнейшая сборка не выполняется. [evidence/breaking-update.txt](evidence/breaking-update.txt) содержит действительный вывод запуска на исходном `~/projects/sandbox-trial`; полный агент отдельно воспроизвёл эту ошибку на вложенных данных пакета.

## 4. Уязвимость осталась

`python scripts/run_sandbox.py docs/handover/data/sandbox-trial lodash 4.17.21 docs/handover/data/image-scans/demo-main.json --json docs/handover/evidence/still-detected.json`.

Получено `STILL_DETECTED`: из 7 целевых находок по lodash исчезли 4, остались 3. Установка, тесты, сборка, запуск, проверка здоровья и повторный скан прошли. Здесь lodash намеренно **понижается с 4.18.1 до 4.17.21**. Старый `demo-main.json` содержит иной набор зависимостей, поэтому 7 находок других пакетов показаны как новые относительно этого отчёта; это не доказывает, что их создало изменение lodash. Этот сценарий демонстрирует сохранение конкретных находок, а не корректный подбор обновления.

## 5. Ошибка проверки

`python scripts/ci_check.py --url http://127.0.0.1:9 --repository-id 00000000-0000-0000-0000-000000000000 --image localhost:5001/bultshield-training-app:main`.

Получено предупреждение «ПРОВЕРКА НЕ ЗАПУЩЕНА… это не значит, что уязвимостей нет» и код возврата 0: деплой не блокируется. Доказательство: `evidence/ci-unavailable.txt`. Три прежних сбоя исходников возвращают `INCOMPLETE` («Проверка выполнена не полностью»), в том числе при нуле находок; детали в `evidence/failed-scans.txt`.

## 6. Недоступность модели и повторные запросы

Для отдельной завершённой проверки без готовых пояснений запустить единственный worker с `LLM_PROVIDER=fake LLM_FAKE_MODE=unavailable`, затем: `python scripts/request_explanations.py "$CHECK_ID" --url http://127.0.0.1:8080 --wait 120`.

Не оставляйте одновременно обычный и тестовый worker: иначе задание может забрать другой процесс. В выполненном сценарии API поставил задание, повторный запрос вернул тот же идентификатор, обработчик завершил его с результатом `UNAVAILABLE`. Контрольные суммы фактов до/после совпали: `evidence/llm-unavailable.json`. Проверялись реальные API и база; сбой внешней модели имитировался намеренно. После проверки возвращён обычный режим `fake/ok`.

Повторное пояснение уже обработанной проверки переиспользовало 20 результатов, новых запросов и токенов — 0: `evidence/llm-reuse.json`. Если готовые пояснения уже есть, режим `unavailable` может переиспользовать их, поэтому для негативного сценария нужен другой ещё не пояснённый отчёт.

## 7. CI и повторное сканирование

CI — запуск проверки после сборки. Команда `ci_check.py --watch --wait 120` из [01-run.md](01-run.md) реально поставила задание, worker просканировал опубликованный digest: 265 находок, из них 263 `MANUAL_REVIEW`, 2 `FOUND`. Отчёт: `examples/ci-live-report.json`.

Не ждать 24 часа, а вызвать тот же механизм перепроверки вручную: `python scripts/run_image_rescan.py --older-than-hours 0 --limit 1`. Worker завершил задание с `trigger=schedule`, тем же digest и 265 находками; новых и исчезнувших относительно предыдущей проверки — 0. Доказательства: `evidence/scheduled-rescan.txt`, `examples/scheduled-live-report.json`. Ожидание полного суточного интервала в этой работе не выполнялось.

## Сохранённая история применения от 9 октября 2026

Эта история прочитана из существующей базы и не воспроизводилась через GitHub заново.

| Этап | Проверка | Наблюдение |
|---|---|---|
| До исправления | `7da01386-21ef-4433-a8f1-2d383b4dbbbf` | 263 находки; запуск `2af892bd-8d98-4bf4-86ed-f1f19eaaddf3`, коммит `aa7759883f250c81139e7f2a28bba00cf73c6246`; совместный набор закрыл 4 находки |
| Промежуточный образ | `14233040-1f10-4b6a-9241-f4809a993976` | 259 находок; это не исходное «до» |
| После пересборки | `a67e6414-8c7f-48da-bb4c-b261f0b0e08c` | 259 находок, digest `sha256:04aaf9075337deea3f9a019f9eb1ace2a64dae874b5c2975813b6655b9f33f43` |
| Сохранённое подтверждение | в отчёте `7da01386` | `CONFIRMED`, 4 `gone`, 0 `still_detected`, 0 `not_seen`; четыре исходные находки имеют `FIX_DEPLOYED` |

Эти числа — снимок прежних результатов. Новые проверки того же исправленного digest находят 265 уязвимостей с обновлённой базой Trivy; нельзя обещать постоянное общее число находок. Исчезновение целевых уязвимостей проверяется по их идентификаторам и пакетам.

Для будущего запуска, только с отдельным разрешением владельца и созданным им токеном: `python scripts/run_fix_check.py "$CHECK_ID" ~/projects/bultshield-training-app --create-pr --repo tomirizz/bultshield-training-app`. Этот скрипт сам показывает изменения и требует подтверждения; текущая копия учебного репозитория уже содержит прошлое исправление, поэтому не воспроизводит исходное «до» без отдельной копии старой версии.

После подтверждённого человеком слияния, новой сборки, публикации и проверки: `python scripts/confirm_fix_deployment.py "$FIX_RUN_ID" "$NEW_CHECK_ID"`. В этой работе оба действия с GitHub пропущены по прямому ограничению владельца. Проверка опубликованного образа не подтверждает, что именно он запущен у пользователей.

## Привязка образа к версии кода

При сборке нужно указывать полный коммит в метке `org.opencontainers.image.revision`. На текущем неизменённом учебном репозитории команда: `docker build --platform linux/amd64 --provenance=false --label org.opencontainers.image.revision=cde718910cf0c6398c7c083b51851da00e8843fb -t localhost:5001/bultshield-handover:revision ~/projects/bultshield-training-app`.

Публикация **только в локальный реестр**: `docker push localhost:5001/bultshield-handover:revision`. Затем сканирование: `python scripts/ci_check.py --image localhost:5001/bultshield-handover:revision --wait 120` при настроенных BULTSHIELD_URL и BULTSHIELD_REPOSITORY_ID.

В выполненном запуске образ собран из отдельной копии файлов этого коммита без изменения учебного репозитория. Доказательства: `evidence/revision-link.json`, `examples/revision-linked-report.json`. В будущем SHA метки должен соответствовать реально собираемому коммиту; старую метку нельзя слепо переносить на новый код. Без метки отчёт оставляет коммит неизвестным.
