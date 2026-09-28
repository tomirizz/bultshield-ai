# GitHub OAuth для BultShield на Bult.ai

Используются существующие app, worker и PostgreSQL. Новые платные сервисы не нужны.

1. GitHub → Settings → Developer settings → OAuth Apps → New OAuth App.
2. Application name: `BultShield`.
3. Homepage URL: `https://bultshield-app-bultshield-ai-brick.fin1.bult.app`.
4. Authorization callback URL: `https://bultshield-app-bultshield-ai-brick.fin1.bult.app/api/auth/callback`.
5. Сохранить приложение. Client ID и новый Client Secret указать только в Environment сервиса app на Bult.ai.

Переменные app:

- `GITHUB_CLIENT_ID`: Client ID приложения.
- `GITHUB_CLIENT_SECRET`: Client Secret, не помещать в GitHub или чат.
- `GITHUB_TOKEN_KEY`: необязательный отдельный ключ Fernet. Если не задан, ключ шифрования получается через SHA-256 с отдельным контекстом из Client Secret; секрет GitHub должен оставаться неизменным, иначе потребуется повторный вход. Отдельный ключ позволяет независимо ротировать Client Secret.
- `PUBLIC_URL`: `https://bultshield-app-bultshield-ai-brick.fin1.bult.app`.
- `LEGACY_OWNER_GITHUB_ID`: `191625826` — проверенный GitHub ID tomirizz, владельца существующих проектов. Не login; получить через `https://api.github.com/users/tomirizz`. Без этой настройки существующие проекты не присваиваются новому пользователю.
- `AUTH_ENABLED=true`: для локальной проверки входа. В `APP_ENV=production` вход обязателен независимо от этого флага. Настроить OAuth до выкладки новой версии, иначе защищённые API будут закрыты до входа.

Генерация ключа в защищённом терминале app: `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`. Не публиковать вывод и не добавлять в логи приложения.

Вход использует PKCE S256, одноразовый state, Secure/HttpOnly cookie максимум на 12 часов (не дольше срока OAuth token). OAuth токены шифруются в PostgreSQL; ключ хранится отдельно в Environment app. Права `read:user public_repo`: текущая версия выбирает и проверяет публичные репозитории; `public_repo` также позволяет по явному действию создать отдельную ветку с одобренным исправлением. Приватные репозитории не поддерживаются.

После deploy: проверить вход владельца, доступ к старым проектам, выход, отказ анонимным API-запросам. Второй GitHub-пользователь должен видеть только собственные проекты. Не объявлять OAuth подключённым до проверки реального входа.

Документация GitHub: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
