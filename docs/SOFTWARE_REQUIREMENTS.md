# Требования к ПО

## Архитектура

- Python 3.11, Django 5.2, Telethon 1.x и PostgreSQL 16.
- Бизнес-логика находится в `core/services`; views отвечают только за HTTP flow.
- Repository abstraction вводится только для сложных запросов или сменного backend.
- Все функции аннотируются; mypy запускается в CI.
- Celery не используется. Telegram supervisor является самостоятельным процессом.

## Безопасность

- VPN-only ingress, Django sessions, Argon2, CSRF, CSP и rate limiting.
- Максимальный request body по умолчанию — 64 KiB.
- Tenant-owned querysets обязательны для пользовательских endpoints.
- Phrase, MTProto session, phone, OTP и 2FA не логируются.
- Phrase/session — envelope encrypted; transient auth secrets имеют TTL пять минут.
- Отменённый или заменённый auth flow не может сохранить запоздавшую session.
- Mini App rules принадлежат конкретному `TelegramAccount`; текстовые значения шифруются.
- Mini App audit не содержит полный текст сообщений, session или WebView content.
- Открытая фраза не включается в HTML списка и выдаётся только отдельным
  авторизованным `no-store` запросом.
- Пользователь может удалить обычное правило сразу; protected removal и disconnect
  требуют operator approval.

## Тестирование

Для критической логики применяется цикл TDD: failing test, минимальная реализация,
рефакторинг, полный regression run.

- pytest и pytest-django — единый тестовый стек.
- Минимум 95% coverage для matcher/deletion/security и 85% по `core`.
- Обязательны negative tenant tests, auth lifecycle mocks, URL cases, retry behavior
  и проверка отсутствия sensitive logging.
- Обязательна матрица входящих/исходящих новых сообщений и edits для private chat,
  basic group, supergroup и channel с наличием и отсутствием права удаления.
- MTProto Mini App operations тестируются только через mock client; CI не использует
  реальные Telegram credentials или аккаунты.
- CI использует временный PostgreSQL; production database не используется.

## Код

- Ruff заменяет комбинацию black/isort/flake8.
- Запрещены `print()` и bare `except`.
- Не используется искусственный лимит длины функции; сложные функции разделяются
  по ответственности и удерживаются ниже cyclomatic complexity 10.
- Конфигурация — environment variables; логи — stdout/stderr.
- Миграции выполняются отдельным platform deployment stage.
- IPv4 используется для bind и Telegram connections.

## API и интерфейсы

Публичного REST API нет. Интерфейсы v1:

- Django web cabinet и русскоязычный `/operator/`;
- Django Admin как резервный технический интерфейс;
- собранная статика через WhiteNoise при `DJANGO_DEBUG=false`;
- `/livez` — process liveness;
- `/healthz` — database и worker readiness;
- PostgreSQL heartbeat между web и worker;
- `repository_dispatch` между product CI и platform CD.
