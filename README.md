# MyCleanBot

MyCleanBot — закрытый многопользовательский сервис самофильтрации Telegram.
Пользователь подключает собственный аккаунт через MTProto, добавляет запрещённые
фразы, а worker удаляет новые исходящие сообщения и правки, содержащие совпадение.

> Удаление выполняется после отправки. Получатель может кратковременно увидеть
> сообщение или push-уведомление.

## Возможности

- до десяти Telegram-аккаунтов в одном deployment;
- регистрация только по одноразовым приглашениям;
- QR-вход и резервный вход по телефону, коду и 2FA;
- поиск в тексте, captions, видимом и скрытом URL;
- `/mc_status` только в «Избранном»;
- индивидуальное envelope encryption правил и MTProto-сессий;
- добавление правил пользователем, удаление и disconnect только после approval;
- Django Admin для оператора и изолированный пользовательский кабинет;
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

Poetry создаёт изолированное окружение непосредственно в `.venv`; точные версии
всех зависимостей фиксируются в `poetry.lock`. CI и Docker используют тот же lock-файл.

`TELEGRAM_API_ID` и `TELEGRAM_API_HASH` выдаются для Telegram API application.
Секреты и session-данные нельзя добавлять в Git.

## Документация

- [План проекта](docs/PROJECT_PLAN.md)
- [Требования](docs/SOFTWARE_REQUIREMENTS.md)
- [Безопасность](docs/SECURITY.md)
- [CI/CD](docs/CI_CD.md)
