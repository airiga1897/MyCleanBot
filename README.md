# MyCleanBot

MyCleanBot — закрытый многопользовательский сервис самофильтрации Telegram.
Пользователь подключает собственный аккаунт через MTProto, добавляет запрещённые
фразы, а worker проверяет новые и отредактированные входящие и исходящие сообщения.
Для каждого правила выбираются направление и режим `observe`, `warn` или `enforce`.

> Фильтрация выполняется только после получения Telegram update. Исходящее сообщение
> или push-уведомление может быть кратковременно видно получателю. Для удаления
> входящего сообщения у всех участников супергруппы или канала аккаунту нужны
> административные права; без них событие только фиксируется.

## Возможности

- до десяти Telegram-аккаунтов в одном deployment;
- регистрация только по одноразовым приглашениям;
- QR-вход и резервный вход по телефону, коду и 2FA с автоматическим завершением;
- поиск в тексте, captions, видимом и скрытом URL;
- раздельные режимы и направления правил, безопасный тест правила без Telegram;
- компактный список без открытых фраз и обезличенный журнал результатов;
- полная фоновая проверка доступной облачной истории Telegram с прогрессом,
  остановкой и приоритетом realtime updates;
- `/mc_status` только в «Избранном»;
- индивидуальное envelope encryption правил и MTProto-сессий;
- немедленное удаление обычных правил и approval оператора для защищённых;
- русскоязычные личный кабинет и `/operator/`; Django Admin оставлен резервным;
- индивидуальные allow/deny-политики для attachment/side-menu Mini Apps;
- режимы Mini Apps `observe`, `warn` и `enforce` (по умолчанию `observe`);
- platform-owned PostgreSQL и GitHub Actions CI/CD.

## Локальный запуск

Требуются Python 3.11+ и PostgreSQL. Для быстрого локального smoke-теста допустим
SQLite, если `DATABASE_URL` не задан.

```powershell
poetry config virtualenvs.in-project true --local
poetry install --with dev --no-root
$env:DJANGO_DEBUG="true"
$env:MASTER_ENCRYPTION_KEY="созданный Fernet.generate_key() ключ"
poetry run python manage.py migrate
poetry run python manage.py createsuperuser
poetry run python manage.py runserver
```

Worker запускается отдельно:

```powershell
poetry run python manage.py run_telegram_worker
```

Полный history scan по умолчанию использует временный development-контракт
`preview → подтверждение → удаление`. Он управляется
`HISTORY_SCAN_REQUIRE_PREVIEW=true`; выключение этой защиты требует отдельного
продуктового решения. Secret chats недоступны через облачный MTProto history API.

Poetry создаёт изолированное окружение непосредственно в `.venv`; точные версии
всех зависимостей фиксируются в `poetry.lock`. CI и Docker используют тот же lock-файл.

`TELEGRAM_API_ID` и `TELEGRAM_API_HASH` выдаются для Telegram API application.
Секреты и session-данные нельзя добавлять в Git.

## Документация

- [План проекта](docs/PROJECT_PLAN.md)
- [Требования](docs/SOFTWARE_REQUIREMENTS.md)
- [Безопасность](docs/SECURITY.md)
- [CI/CD](docs/CI_CD.md)
- [Ограничение Telegram Mini Apps](docs/MINI_APPS.md)
