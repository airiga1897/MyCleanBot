from __future__ import annotations

from django.contrib import admin, messages
from django.utils import timezone

from core.models import (
    DisconnectRequest,
    FilterEvent,
    ForbiddenRule,
    HistoryScan,
    Invitation,
    MiniAppAuditEvent,
    MiniAppPolicy,
    MiniAppRule,
    RuleRemovalRequest,
    TelegramAccount,
    TelegramAuthFlow,
    UserKey,
    WorkerHeartbeat,
)

admin.site.site_header = "Администрирование MyCleanBot"
admin.site.site_title = "MyCleanBot"
admin.site.index_title = "Техническое администрирование"

for model, singular, plural in (
    (Invitation, "приглашение", "приглашения"),
    (TelegramAccount, "аккаунт Telegram", "аккаунты Telegram"),
    (ForbiddenRule, "правило текста", "правила текста"),
    (RuleRemovalRequest, "запрос удаления правила", "запросы удаления правил"),
    (DisconnectRequest, "запрос отключения", "запросы отключения"),
    (FilterEvent, "событие фильтра", "события фильтра"),
    (HistoryScan, "проверка истории", "проверки истории"),
    (MiniAppPolicy, "политика Mini Apps", "политики Mini Apps"),
    (MiniAppRule, "правило Mini Apps", "правила Mini Apps"),
    (MiniAppAuditEvent, "событие Mini Apps", "события Mini Apps"),
    (WorkerHeartbeat, "служебный сигнал worker", "служебные сигналы worker"),
    (TelegramAuthFlow, "подключение Telegram", "подключения Telegram"),
):
    model._meta.verbose_name = singular
    model._meta.verbose_name_plural = plural


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "created_by",
        "created_at",
        "expires_at",
        "consumed_at",
        "revoked_at",
    )
    readonly_fields = (
        "token_hash",
        "created_by",
        "created_at",
        "expires_at",
        "consumed_at",
        "revoked_at",
        "consumed_by",
    )

    def has_add_permission(self, request: object) -> bool:
        return False


@admin.register(TelegramAccount)
class TelegramAccountAdmin(admin.ModelAdmin):
    list_display = ("user", "status", "desired_enabled", "last_heartbeat_at", "updated_at")
    readonly_fields = (
        "user",
        "status",
        "desired_enabled",
        "last_heartbeat_at",
        "last_update_at",
        "last_update_direction",
        "last_update_result",
        "last_error_code",
        "updated_at",
    )
    exclude = (
        "encrypted_session",
        "encrypted_identity",
        "telegram_user_fingerprint",
    )

    def has_add_permission(self, request: object) -> bool:
        return False


@admin.register(ForbiddenRule)
class ForbiddenRuleAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "direction", "mode", "is_locked", "active", "created_at")
    readonly_fields = (
        "user",
        "direction",
        "mode",
        "is_locked",
        "active",
        "created_at",
    )
    exclude = ("encrypted_phrase", "phrase_fingerprint")

    def has_add_permission(self, request: object) -> bool:
        return False


@admin.action(description="Одобрить удаление выбранных правил")
def approve_rule_removal(
    modeladmin: admin.ModelAdmin,
    request: object,
    queryset: object,
) -> None:
    approved = 0
    for removal in queryset.filter(status=RuleRemovalRequest.Status.PENDING).select_related("rule"):
        if removal.rule_id:
            removal.rule.delete()
            removal.rule = None
        removal.status = RuleRemovalRequest.Status.APPROVED
        removal.resolved_at = timezone.now()
        removal.resolved_by = request.user
        removal.save(update_fields=["status", "resolved_at", "resolved_by"])
        approved += 1
    modeladmin.message_user(request, f"Одобрено запросов: {approved}", messages.SUCCESS)


@admin.action(description="Отклонить выбранные запросы")
def reject_rule_removal(
    modeladmin: admin.ModelAdmin,
    request: object,
    queryset: object,
) -> None:
    queryset.filter(status=RuleRemovalRequest.Status.PENDING).update(
        status=RuleRemovalRequest.Status.REJECTED,
        resolved_at=timezone.now(),
        resolved_by=request.user,
    )


@admin.register(RuleRemovalRequest)
class RuleRemovalRequestAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "rule_id", "status", "created_at", "resolved_at")
    readonly_fields = ("user", "rule", "status", "created_at", "resolved_at", "resolved_by")
    actions = (approve_rule_removal, reject_rule_removal)


@admin.action(description="Одобрить отключение Telegram")
def approve_disconnect(
    modeladmin: admin.ModelAdmin,
    request: object,
    queryset: object,
) -> None:
    approved = 0
    for item in queryset.filter(status=DisconnectRequest.Status.PENDING):
        TelegramAccount.objects.filter(user=item.user).update(desired_enabled=False)
        item.status = DisconnectRequest.Status.APPROVED
        item.resolved_at = timezone.now()
        item.resolved_by = request.user
        item.save(update_fields=["status", "resolved_at", "resolved_by"])
        approved += 1
    modeladmin.message_user(request, f"Одобрено запросов: {approved}", messages.SUCCESS)


@admin.action(description="Отклонить выбранные запросы")
def reject_disconnect(
    modeladmin: admin.ModelAdmin,
    request: object,
    queryset: object,
) -> None:
    queryset.filter(status=DisconnectRequest.Status.PENDING).update(
        status=DisconnectRequest.Status.REJECTED,
        resolved_at=timezone.now(),
        resolved_by=request.user,
    )


@admin.register(DisconnectRequest)
class DisconnectRequestAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "status", "created_at", "resolved_at")
    readonly_fields = ("user", "status", "created_at", "resolved_at", "resolved_by")
    actions = (approve_disconnect, reject_disconnect)


@admin.register(FilterEvent)
class FilterEventAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "direction",
        "source",
        "chat_type",
        "result",
        "created_at",
    )
    readonly_fields = (
        "user",
        "rule_ids",
        "direction",
        "source",
        "chat_type",
        "result",
        "error_code",
        "created_at",
    )

    def has_add_permission(self, request: object) -> bool:
        return False


@admin.register(HistoryScan)
class HistoryScanAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "account",
        "phase",
        "status",
        "dialogs_scanned",
        "messages_scanned",
        "matches_found",
        "created_at",
    )
    readonly_fields = (
        "account",
        "phase",
        "status",
        "cancel_requested",
        "dialogs_scanned",
        "message_offset_id",
        "messages_scanned",
        "matches_found",
        "preview_matches",
        "deleted_self",
        "skipped_global",
        "failed_actions",
        "last_error_code",
        "created_at",
        "started_at",
        "confirmed_at",
        "completed_at",
        "updated_at",
    )

    def has_add_permission(self, request: object) -> bool:
        return False


@admin.register(MiniAppPolicy)
class MiniAppPolicyAdmin(admin.ModelAdmin):
    list_display = ("account", "mode", "block_bot", "notify_user", "notify_admin", "updated_at")
    readonly_fields = ("account", "mode", "block_bot", "notify_user", "notify_admin", "updated_at")

    def has_add_permission(self, request: object) -> bool:
        return False


@admin.register(MiniAppRule)
class MiniAppRuleAdmin(admin.ModelAdmin):
    list_display = ("id", "account", "list_type", "match_type", "bot_id", "active", "created_at")
    readonly_fields = (
        "account",
        "list_type",
        "match_type",
        "bot_id",
        "active",
        "created_at",
    )
    exclude = ("encrypted_pattern", "pattern_fingerprint")

    def has_add_permission(self, request: object) -> bool:
        return False


@admin.register(MiniAppAuditEvent)
class MiniAppAuditEventAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "account",
        "rule_id",
        "event_type",
        "bot_id",
        "bot_username",
        "result",
        "created_at",
    )
    readonly_fields = (
        "account",
        "rule",
        "event_type",
        "bot_id",
        "bot_username",
        "result",
        "error_code",
        "created_at",
    )

    def has_add_permission(self, request: object) -> bool:
        return False


@admin.register(WorkerHeartbeat)
class WorkerHeartbeatAdmin(admin.ModelAdmin):
    list_display = ("name", "state", "updated_at")
    readonly_fields = ("name", "state", "updated_at")

    def has_add_permission(self, request: object) -> bool:
        return False


@admin.register(TelegramAuthFlow)
class TelegramAuthFlowAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "kind", "state", "error_code", "created_at", "expires_at")
    readonly_fields = (
        "user",
        "kind",
        "state",
        "error_code",
        "created_at",
        "expires_at",
        "updated_at",
    )
    exclude = ("encrypted_payload",)

    def has_add_permission(self, request: object) -> bool:
        return False


# Cryptographic material must never be exposed through Django Admin.
admin.site.disable_action("delete_selected")
_ = UserKey
