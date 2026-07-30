from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class Invitation(models.Model):
    token_hash = models.CharField(max_length=64, unique=True)
    created_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name="created_invites")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    consumed_by = models.OneToOneField(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="invitation"
    )

    def __str__(self) -> str:
        return f"Invitation #{self.pk}"

    @classmethod
    def issue(cls, created_by: User) -> tuple[Invitation, str]:
        token = secrets.token_urlsafe(32)
        invitation = cls.objects.create(
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            created_by=created_by,
            expires_at=timezone.now() + timedelta(hours=24),
        )
        return invitation, token

    def is_valid(self) -> bool:
        return (
            self.consumed_at is None
            and self.revoked_at is None
            and self.expires_at > timezone.now()
        )


class UserKey(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="encryption_key")
    encrypted_dek = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"User key #{self.pk}"


class TelegramAccount(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Ожидает подключения"
        CONNECTING = "connecting", "Подключается"
        ACTIVE = "active", "Активен"
        DISCONNECTED = "disconnected", "Отключён"
        ERROR = "error", "Ошибка"

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="telegram_account")
    encrypted_session = models.TextField(blank=True)
    telegram_user_fingerprint = models.CharField(max_length=64, unique=True, null=True, blank=True)
    encrypted_identity = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    desired_enabled = models.BooleanField(default=True)
    last_heartbeat_at = models.DateTimeField(null=True, blank=True)
    last_update_at = models.DateTimeField(null=True, blank=True)
    last_update_direction = models.CharField(max_length=16, blank=True)
    last_update_result = models.CharField(max_length=32, blank=True)
    last_error_code = models.CharField(max_length=64, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"Telegram account for {self.user.username}"


class ForbiddenRule(models.Model):
    class Direction(models.TextChoices):
        INCOMING = "incoming", "Входящие"
        OUTGOING = "outgoing", "Исходящие"
        BOTH = "both", "Входящие и исходящие"

    class Mode(models.TextChoices):
        OBSERVE = "observe", "Наблюдение"
        WARN = "warn", "Предупреждение"
        ENFORCE = "enforce", "Удаление"

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="forbidden_rules")
    encrypted_phrase = models.TextField()
    phrase_fingerprint = models.CharField(max_length=64)
    active = models.BooleanField(default=True)
    direction = models.CharField(
        max_length=16, choices=Direction.choices, default=Direction.BOTH
    )
    mode = models.CharField(max_length=16, choices=Mode.choices, default=Mode.ENFORCE)
    is_locked = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "phrase_fingerprint"], name="unique_user_phrase"
            )
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Rule #{self.pk}"


class RuleRemovalRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Ожидает"
        APPROVED = "approved", "Одобрен"
        REJECTED = "rejected", "Отклонён"

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="rule_removal_requests")
    rule = models.ForeignKey(ForbiddenRule, on_delete=models.SET_NULL, null=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    def __str__(self) -> str:
        return f"Rule removal request #{self.pk}"


class DisconnectRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Ожидает"
        APPROVED = "approved", "Одобрен"
        REJECTED = "rejected", "Отклонён"

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="disconnect_requests")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    def __str__(self) -> str:
        return f"Disconnect request #{self.pk}"


class FilterEvent(models.Model):
    class Direction(models.TextChoices):
        INCOMING = "incoming", "Входящее"
        OUTGOING = "outgoing", "Исходящее"

    class Result(models.TextChoices):
        DETECTED = "detected", "Обнаружено"
        WARNED = "warned", "Предупреждение"
        DELETED_SELF = "deleted_self", "Удалено для себя"
        DELETED_ALL = "deleted_all", "Удалено для всех"
        DELETED = "deleted", "Удалено"
        FAILED = "failed", "Ошибка"

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="filter_events")
    rule_ids = models.JSONField(default=list)
    direction = models.CharField(
        max_length=16, choices=Direction.choices, default=Direction.OUTGOING
    )
    source = models.CharField(max_length=16)
    chat_type = models.CharField(max_length=16)
    result = models.CharField(max_length=16, choices=Result.choices)
    error_code = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Filter event #{self.pk}"

    def get_source_display(self) -> str:
        return {
            "body": "текст",
            "caption": "подпись",
            "link_target": "ссылка",
        }.get(self.source, self.source)

    def get_chat_type_display(self) -> str:
        return {
            "saved": "Избранное",
            "private": "личный чат",
            "group": "группа",
            "supergroup": "супергруппа",
            "channel": "канал",
        }.get(self.chat_type, self.chat_type)


class MiniAppPolicy(models.Model):
    class Mode(models.TextChoices):
        OBSERVE = "observe", "Наблюдение"
        WARN = "warn", "Предупреждение"
        ENFORCE = "enforce", "Ограничение"

    account = models.OneToOneField(
        TelegramAccount, on_delete=models.CASCADE, related_name="mini_app_policy"
    )
    mode = models.CharField(max_length=16, choices=Mode.choices, default=Mode.OBSERVE)
    block_bot = models.BooleanField(default=False)
    notify_user = models.BooleanField(default=True)
    notify_admin = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"Mini App policy for account #{self.account_id}"


class MiniAppRule(models.Model):
    class ListType(models.TextChoices):
        ALLOW = "allow", "Белый список"
        DENY = "deny", "Чёрный список"

    class MatchType(models.TextChoices):
        BOT_ID = "bot_id", "Bot ID"
        USERNAME = "username", "Username бота"
        TITLE = "title", "Название Mini App"
        KEYWORD = "keyword", "Ключевое слово"
        REGEX = "regex", "Регулярное выражение"

    account = models.ForeignKey(
        TelegramAccount, on_delete=models.CASCADE, related_name="mini_app_rules"
    )
    list_type = models.CharField(max_length=8, choices=ListType.choices)
    match_type = models.CharField(max_length=16, choices=MatchType.choices)
    bot_id = models.BigIntegerField(null=True, blank=True)
    encrypted_pattern = models.TextField(blank=True)
    pattern_fingerprint = models.CharField(max_length=64)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["account", "list_type", "match_type", "pattern_fingerprint"],
                name="unique_account_mini_app_rule",
            )
        ]
        ordering = ["list_type", "match_type", "-created_at"]

    def __str__(self) -> str:
        return f"Mini App rule #{self.pk}"


class MiniAppAuditEvent(models.Model):
    class EventType(models.TextChoices):
        MENU_DETECTED = "menu_detected", "Mini App обнаружено в меню"
        OUTGOING_DETECTED = "outgoing_detected", "Исходящее сообщение обнаружено"
        MENU_DISABLED = "menu_disabled", "Mini App отключено в меню"
        BOT_BLOCKED = "bot_blocked", "Бот заблокирован"
        MESSAGE_DELETED = "message_deleted", "Сообщение удалено"
        USER_WARNED = "user_warned", "Пользователь предупреждён"
        ADMIN_NOTIFIED = "admin_notified", "Администратор уведомлён"

    class Result(models.TextChoices):
        OBSERVED = "observed", "Обнаружено"
        WARNED = "warned", "Предупреждено"
        SUCCEEDED = "succeeded", "Выполнено"
        FAILED = "failed", "Ошибка"
        SKIPPED = "skipped", "Пропущено"

    account = models.ForeignKey(
        TelegramAccount, on_delete=models.CASCADE, related_name="mini_app_events"
    )
    rule = models.ForeignKey(
        MiniAppRule, on_delete=models.SET_NULL, null=True, blank=True, related_name="events"
    )
    event_type = models.CharField(max_length=32, choices=EventType.choices)
    bot_id = models.BigIntegerField(null=True, blank=True)
    bot_username = models.CharField(max_length=64, blank=True)
    result = models.CharField(max_length=16, choices=Result.choices)
    error_code = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["account", "-created_at"], name="miniapp_event_account_time")
        ]

    def __str__(self) -> str:
        return f"Mini App audit event #{self.pk}"


class WorkerHeartbeat(models.Model):
    name = models.CharField(max_length=64, unique=True)
    updated_at = models.DateTimeField(auto_now=True)
    state = models.CharField(max_length=32, default="running")

    def __str__(self) -> str:
        return self.name


class TelegramAuthFlow(models.Model):
    class Kind(models.TextChoices):
        QR = "qr", "QR"
        PHONE = "phone", "Телефон"

    class State(models.TextChoices):
        QUEUED = "queued", "Ожидает worker"
        QR_READY = "qr_ready", "QR готов"
        CODE_REQUIRED = "code_required", "Нужен код"
        PASSWORD_REQUIRED = "password_required", "Нужен 2FA"
        VERIFYING = "verifying", "Проверка"
        COMPLETE = "complete", "Готово"
        FAILED = "failed", "Ошибка"
        EXPIRED = "expired", "Истёк"
        CANCELLED = "cancelled", "Отменено"

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="telegram_auth_flows")
    kind = models.CharField(max_length=8, choices=Kind.choices)
    state = models.CharField(max_length=24, choices=State.choices, default=State.QUEUED)
    encrypted_payload = models.TextField(blank=True)
    error_code = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"Telegram auth flow #{self.pk}"

    @classmethod
    def new(cls, user: User, kind: str, encrypted_payload: str = "") -> TelegramAuthFlow:
        cls.objects.filter(user=user).exclude(
            state__in=[
                cls.State.COMPLETE,
                cls.State.FAILED,
                cls.State.EXPIRED,
                cls.State.CANCELLED,
            ]
        ).update(state=cls.State.EXPIRED, encrypted_payload="")
        return cls.objects.create(
            user=user,
            kind=kind,
            encrypted_payload=encrypted_payload,
            expires_at=timezone.now() + timedelta(minutes=5),
        )
