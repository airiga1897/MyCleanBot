# CI/CD

## Product repository

На PR и push workflow выполняет:

1. secret scan;
2. Ruff и mypy;
3. Django checks и проверку отсутствующих миграций;
4. pytest с PostgreSQL 16 и coverage;
5. Docker build.

После успешного `main` образ публикуется как
`ghcr.io/airiga1897/mycleanbot@sha256:<digest>`. Tag не является deploy identity.

## Platform handoff

Product workflow отправляет `repository_dispatch`:

```json
{
  "event_type": "mycleanbot-image-published",
  "client_payload": {
    "instance": "mycleanbot",
    "environment": "prod",
    "image_ref": "ghcr.io/airiga1897/mycleanbot@sha256:<digest>",
    "source_sha": "<40 hex characters>"
  }
}
```

Для dispatch используется fine-grained `PLATFORM_DISPATCH_TOKEN`, ограниченный
репозиторием `AI_Service_Platform`.

## Platform deployment

`AI_Service_Platform` проверяет payload и registry, требует approval защищённого
environment `mycleanbot-prod`, затем выполняет:

1. pull immutable digest;
2. one-off `python manage.py migrate`;
3. replacement web и worker;
4. `/healthz`;
5. запись deployment state.

PostgreSQL не включается в MyCleanBot Compose. `DATABASE_URL`, application secrets,
backup, monitoring и rollback принадлежат платформе.

