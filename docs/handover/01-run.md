# Запуск локального прототипа

## Действующий Bult-стенд

На 14 октября app и worker используют `feature/security-agent`, проверенный код `51fdac6` (результат — в [09](09-test-prototype-llm-acceptance.md)), миграции `0013`. Более поздние правки ветки (выбор версий моделью, [10](10-llm-planner.md)) на Bult пока не развёрнуты; схема базы не менялась, новая миграция не нужна. В существующих сервисах заданы `LLM_PROVIDER=bult`, `IMAGE_ALLOWED_REGISTRIES=docker.io`, `LLM_MAX_CALLS_PER_CHECK=3`; `AI_ENDPOINT` указывает на существующую приватную модель. Секреты не копировать в документы. App применяет миграции при запуске, затем запускается обновлённый worker.

Откройте https://bultshield-app-bultshield-ai-brick.fin1.bult.app и войдите через GitHub. В проекте раздел «Проверки образов и зависимостей» принимает полный SHA коммита либо адрес готового образа. Отчёт и пояснения появляются там же. Пример и границы приёмки — [08](08-function1-live-acceptance.md). Исполнитель песочницы на Bult пока отсутствует; следующие команды Docker относятся к локальному стенду.

## Локальный запуск

Проверено на macOS Apple Silicon, Python 3.12, PostgreSQL 17, Docker Desktop и Trivy 0.74.0. Команды ниже выполняются из корня `bultshield-ai`, каждая команда — одна строка. API — интерфейс запросов к серверу; worker — отдельный процесс, который выполняет задания из очереди.

## Окружение

1. Активировать установленное окружение: `conda activate bultshield`.
2. Установить зависимости, если окружение создаётся заново: `python -m pip install -r backend/requirements-dev.txt`.
3. Запустить Docker Desktop. Проверить доступность: `docker info`.
4. Добавить закреплённый Trivy в путь на этом Mac: `export PATH="$HOME/tools/trivy-0.74.0:$PATH"`. Проверить: `trivy --version`.
5. В каждом окне терминала задать `DATABASE_URL` из существующих локальных настроек. Значение с паролем здесь намеренно не публикуется. Рабочая база этого стенда — `bultshield_demo`, PostgreSQL доступен на `127.0.0.1:5433` в контейнере `bultshield-test-db`. Не используйте рабочую базу для тестов.
6. Для демо: `export LLM_PROVIDER=fake IMAGE_ALLOWED_REGISTRIES=localhost:5001`.

Gitleaks и Semgrep, дополнительные проверки исходников, в окружении этого Mac отсутствуют. Это не препятствует проверке Docker-образов Trivy, но проверка исходников завершается как неполная. Причины трёх сохранённых сбоев — в [04-tests.md](04-tests.md).

## Запуск сервера и обработчика

Миграции, то есть обновление структуры таблиц: `(cd backend && python -m alembic upgrade head)`.

Окно 1: `(cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8080)`.

Окно 2: `(cd backend && python -m app.worker)`.

Проверка процесса: `curl --fail --silent http://127.0.0.1:8080/health/live`.

Проверка базы и миграций: `curl --fail --silent http://127.0.0.1:8080/health/ready`.

Пути здоровья начинаются с `/health`, без `/api`. На проверенном стенде оба вернули HTTP 200, миграция — `0013`. Поле `ai_enabled` относится к прежней подсистеме анализа исходников; пояснения функции 1 управляются отдельной настройкой `LLM_PROVIDER`. Проверять их нужно через `/api/checks/{id}/explanations`.

## Первая проверка

Создать проект с публичным репозиторием (один раз): `curl --fail --silent -X POST http://127.0.0.1:8080/api/projects -H 'Content-Type: application/json' -d '{"name":"Security demo","repository":{"url":"https://github.com/tomirizz/bultshield-training-app","default_branch":"main"}}'`.

Взять `repositories[0].id` из ответа и сохранить в переменную `BULTSHIELD_REPOSITORY_ID`. Для уже существующего проекта этого стенда: `export BULTSHIELD_REPOSITORY_ID=72706e3e-b306-4bfb-bb4b-eafbcb07f1d3 BULTSHIELD_URL=http://127.0.0.1:8080`.

Запуск по опубликованному образу: `python scripts/ci_check.py --image localhost:5001/bultshield-training-app@sha256:04aaf9075337deea3f9a019f9eb1ace2a64dae874b5c2975813b6655b9f33f43 --watch --wait 120`.

Этот digest (неизменяемый отпечаток содержимого образа) существует в локальном реестре данного Mac. На другом компьютере сначала нужен собственный реестр и опубликованный туда образ; идентификатор проекта также будет другим. Не копируйте сохранённые идентификаторы в новую пустую базу.

Прочитать отчёт по выданному идентификатору: `curl --fail --silent "http://127.0.0.1:8080/api/checks/$CHECK_ID/report?limit=500"`, предварительно задав `CHECK_ID` из ответа.

## Настройки

| Переменная | Назначение и значение по умолчанию |
|---|---|
| `DATABASE_URL` | подключение к рабочей PostgreSQL; задаётся владельцем, не коммитится |
| `TEST_DATABASE_URL` | отдельная локальная одноразовая база с окончанием `_test` |
| `AUTH_ENABLED` | в локальном демо `false`; внешнее размещение требует авторизации |
| `IMAGE_ALLOWED_REGISTRIES` | разрешённые реестры, список через запятую; пустой список запрещает сканирование |
| `IMAGE_DB_MAX_AGE_HOURS` | максимальный возраст базы уязвимостей Trivy, 48 часов |
| `IMAGE_SCAN_PLATFORM` | платформа образа, `linux/amd64` |
| `IMAGE_RESCAN_HOURS` | период перепроверки наблюдаемых образов, 24 часа; 0 отключает |
| `LLM_PROVIDER` | `disabled` по умолчанию; `fake` — демо без сети и ключей; `bult` — приватная модель Bult; `openai` (и любой OpenAI-совместимый сервер) и `anthropic` — свой провайдер, см. [10](10-llm-planner.md) |
| `LLM_FAKE_MODE` | только для `fake`: `ok`, `unavailable`, `garbage`, `invented_version`, `leak`, `english`, `link`, `prefer_latest` (негативные сценарии и выбор более свежей версии) |
| `LLM_API_KEY`, `LLM_MODEL`, `LLM_BASE_URL` | параметры своего провайдера; ключ только в окружении сервера. Приватная Qwen Bult проверена вживую ([09](09-test-prototype-llm-acceptance.md)); `openai`/`anthropic` проверены только подставным HTTP-сервером |
| `LLM_MAX_TOKENS_PARAM`, `LLM_OMIT_TEMPERATURE`, `LLM_JSON_MODE`, `LLM_RETRIES` | подстройка запроса под модель и повторы при 429/5xx: см. [10](10-llm-planner.md) |
| `LLM_MAX_CALLS_PER_CHECK`, `LLM_DAILY_CALL_LIMIT` | лимиты 20 групп на запуск проверки и 200 отправленных запросов за скользящие 24 часа |
| `LLM_MAX_OUTPUT_TOKENS`, `LLM_TIMEOUT_SECONDS` | максимум токенов ответа (600 по умолчанию, до 16000 для «рассуждающих» моделей) и таймаут 30 секунд |
| `LLM_PRICE_INPUT_PER_MTOK`, `LLM_PRICE_OUTPUT_PER_MTOK` | цены выбранного провайдера за миллион токенов; 0 означает незаданные цены, а не бесплатную настоящую модель |
| `GITHUB_FIX_TOKEN`, `FIX_PR_ALLOWED_REPOS` | только для явно подтверждённого создания PR; в этой работе не используются |
| `CI_TRIGGER_TOKEN`, `CI_TRIGGER_OWNER_ID` | авторизация CI при включённом входе; создаёт владелец |

Для CLI-скриптов и процессов в разных каталогах надёжнее задать переменные в окружении каждого терминала: автоматическое чтение `.env` зависит от текущего каталога. Не сохраняйте секреты в документах и истории команд.

## Проверки и сбор доказательств

Тесты очищают таблицы. Разрешена только отдельная локальная база с окончанием `_test`, например `bultshield_handover_test`. Задайте её адрес через `TEST_DATABASE_URL`, затем выполните **один процесс**: `python scripts/check_backend.py`.

Сбор существующей истории и негативного сценария: `python scripts/collect_evidence.py --url http://127.0.0.1:8080`. Для встроенного шага песочницы этот скрипт использует папки `~/projects/sandbox-trial` и `~/projects/image-scans/no-fix.json`. Если их нет, он честно пишет об этом; переносимые команды с данными из репозитория приведены в [03-demo-before-after.md](03-demo-before-after.md).

Дополнительные сценарии из этой сдачи лежат в `evidence/`; сборщик автоматически создаёт только базовые пять текстовых файлов и отчёты истории. Аргументы всех девяти скриптов проверены через `--help`, вывод сохранён в [evidence/commands-help.txt](evidence/commands-help.txt).
