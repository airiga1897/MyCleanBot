# Security

## Секреты

Никогда не добавляются в Git, image, artifact или application log:

- `DJANGO_SECRET_KEY`;
- `MASTER_ENCRYPTION_KEY`;
- `TELEGRAM_API_ID` и `TELEGRAM_API_HASH`;
- MTProto StringSession;
- phone, OTP и Telegram 2FA password;
- PostgreSQL credentials;
- `PLATFORM_DISPATCH_TOKEN`.

Platform master key хранится отдельно от PostgreSQL backup. Потеря master key делает
зашифрованные данные невосстановимыми; его backup должен выполняться средствами
платформенного secret management.

## Модель угроз

- Пользовательские querysets всегда ограничиваются `request.user`.
- Operator admin не отображает ciphertext или открытые правила.
- Один Telegram account связывается только с одним application user.
- Auth input шифруется, живёт не более пяти минут и очищается после consumption.
- URL никогда не запрашиваются по сети, что исключает SSRF через matcher.
- AccountRunner защищён advisory lock от одновременного запуска в двух replicas.
- Mini App allow/deny rules и audit events всегда привязаны к одному TelegramAccount.
- Allow rule имеет приоритет над deny rule, чтобы снизить риск ошибочного ограничения.
- Regex ограничены длиной и безопасным подмножеством без lookaround, backreference и
  квантифицированных групп.
- В Mini App audit сохраняются только account, rule, event type, bot id/username,
  timestamp, result и короткий error code.

## Инциденты

При утечке Telegram session:

1. отозвать session в Telegram → «Устройства»;
2. сменить platform master key через процедуру re-encryption;
3. проверить audit платформы и application error codes;
4. повторно авторизовать затронутый аккаунт.

Уязвимости не следует публиковать в открытом issue. Используйте private security
advisory репозитория.
