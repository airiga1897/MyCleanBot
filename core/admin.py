from __future__ import annotations

from django.contrib import admin, messages
from django.utils import timezone

from core.models import (
    DisconnectRequest,
    FilterEvent,
    ForbiddenRule,
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


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ("id", "created_by", "created_at", "expires_at", "consumed_at")
    readonly_fields = (
        "token_hash",
        "created_by",
        "created_at",
        "expires_at",
        "consumed_at",
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
    list_display = ("id", "user", "active", "created_at")
    readonly_fields = ("user", "active", "created_at")
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
    list_display = ("id", "user", "source", "chat_type", "result", "created_at")
    readonly_fields = (
        "user",
        "rule_ids",
        "source",
        "chat_type",
        "result",
        "error_code",
        "created_at",
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
