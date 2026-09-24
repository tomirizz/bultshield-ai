# Этап 2: развёртывание на Bult.ai

## Что разворачиваем

Один проект **BultShield AI**, два работающих сервиса:

| Сервис | Источник | Доступ | Данные |
| --- | --- | --- | --- |
| `postgres` | PostgreSQL template; для проверенной конфигурации — PostgreSQL 17 | Только внутренняя сеть | Отдельный persistent volume |
| `bultshield-app` | GitHub `bultshield-ai`, ветка `main`, корневой `Dockerfile` | Публичный HTTPS, HTTP port 8080 | Данные в PostgreSQL |

Для минимальной демонстрации начните с небольшого compute для App и PostgreSQL, затем проверьте фактическое потребление. Точный тариф, баланс и стоимость должны быть видны в вашем Bult workspace до создания ресурсов. Worker и LLM Server на этом этапе не запускаются.

## 1. GitHub

1. Создать главный репозиторий `bultshield-ai` в выбранном аккаунте.
2. Загрузить содержимое корня этого проекта. `Dockerfile` должен быть в корне репозитория.
3. Убедиться, что `.env`, `.venv`, `node_modules`, `work` и локальные пароли не попали в commit.
4. Для private repository предоставить Bult доступ именно к этому репозиторию через штатное подключение GitHub.

## 2. PostgreSQL на Bult

1. Создать Bult project `BultShield AI`.
2. Добавить PostgreSQL через template. Выделить отдельный постоянный том. Для `postgres:17` путь данных — `/var/lib/postgresql/data`.
3. Дождаться Ready / Running у базы.
4. Скопировать внутреннюю connection string из Bult. Не включать её в README, GitHub или сообщения чата.
5. Не публиковать PostgreSQL в интернете. App должен подключаться по внутреннему адресу, показанному платформой.

## 3. App на Bult

1. Добавить Git service `bultshield-app` из `bultshield-ai`, ветка `main`.
2. Выбрать Dockerfile build: path `Dockerfile`, build context `.`, финальная стадия `app`.
3. Не заменять start command: образ сам ждёт БД, выполняет `alembic upgrade head` и запускает API.
4. Указать HTTP port `8080`.
5. Задать переменные:

```text
DATABASE_URL=<внутренняя PostgreSQL connection string из Bult>
APP_ENV=production
PORT=8080
```

`FRONTEND_DIST` уже задан в образе. Сборка frontend включена в Dockerfile; отдельный frontend-хостинг не нужен.

6. Создать публичный HTTP(S) route только для `bultshield-app`.
7. Выполнить Deploy и открыть Bult URL приложения.

## 4. Проверка результата

- Build завершился, App и PostgreSQL имеют статус Running.
- В логе App есть `BULTSHIELD_DATABASE_READY`, затем запуск Uvicorn.
- `GET /health/live` → 200.
- `GET /health/ready` → 200, `database: connected`, `schema_revision: 0001`.
- `GET /api/overview` возвращает счётчики из БД.
- В UI создать проект и сохранить GitHub URL; после обновления страницы они остаются.
- После перезапуска App тот же проект остаётся. Это проверяет, что данные хранятся в PostgreSQL, а не в памяти frontend.
- Раздел «Система» показывает подключённую БД, а Worker и LLM — «Следующий этап».
- Scan недоступен; счётчики сканирований и находок равны нулю, пока сканеры не подключены.

Этап 2 завершён только после проверки настоящего Bult URL. Успешная локальная сборка этого не заменяет.

## Если приложение не запускается

- `Waiting for PostgreSQL...`: проверить внутренний hostname, database/user/password и доступность БД.
- Ошибка миграции: изучить причину в логе; не удалять persistent volume и не запускать downgrade на рабочей БД.
- HTTP 503 на readiness: база или миграции недоступны; liveness отдельно проверяет процесс приложения.
- UI не открывается: проверить route на порт 8080 и Dockerfile/context, а не Nixpacks-конфигурацию.

Официальные источники: [Bult Builds](https://docs.bult.ai/guides/builds), [Bult Database](https://docs.bult.ai/guides/database), [Bult CLI](https://github.com/bultcloud/cli).
