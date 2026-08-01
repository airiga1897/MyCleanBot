import base64
import hashlib
from datetime import timedelta

import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from core.models import (
    DisconnectRequest,
    FilterEvent,
    ForbiddenRule,
    HistoryScan,
    Invitation,
    MiniAppAuditEvent,
    MiniAppRule,
    OperatorNotification,
    RuleChangeRequest,
    RuleRemovalRequest,
    TelegramAccount,
    TelegramAuthFlow,
)
from core.services.crypto import decrypt_for_user, encrypt_for_user
from core.services.miniapps import create_mini_app_rule
from core.services.rules import create_rule

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def secure_settings(settings: object) -> None:
    settings.MASTER_ENCRYPTION_KEY = base64.urlsafe_b64encode(
        hashlib.sha256(b"views").digest()
    ).decode()
    settings.RATELIMIT_ENABLE = False


def test_invitation_is_single_use(client: Client) -> None:
    admin = User.objects.create_superuser("admin", "admin@example.test", "admin-password-123")
    invite, token = Invitation.issue(admin)
    response = client.post(
        reverse("register_invite", kwargs={"token": token}),
        {
            "username": "new-user",
            "password1": "long-password-123",
            "password2": "long-password-123",
        },
    )
    assert response.status_code == 302
    assert response.url == reverse("login")
    assert "_auth_user_id" not in client.session
    invite.refresh_from_db()
    assert invite.consumed_at is not None
    assert client.get(reverse("register_invite", kwargs={"token": token})).status_code == 404


def test_invitation_registration_uses_fresh_login_form_without_rotating_csrf() -> None:
    client = Client(enforce_csrf_checks=True)
    admin = User.objects.create_superuser(
        "csrf-admin", "csrf-admin@example.test", "admin-password-123"
    )
    _invite, token = Invitation.issue(admin)
    invite_url = reverse("register_invite", kwargs={"token": token})
    assert client.get(invite_url).status_code == 200
    csrf_before = client.cookies["csrftoken"].value

    response = client.post(
        invite_url,
        {
            "username": "csrf-new-user",
            "password1": "long-password-123",
            "password2": "long-password-123",
            "csrfmiddlewaretoken": csrf_before,
        },
    )

    assert response.status_code == 302
    assert response.url == reverse("login")
    assert client.cookies["csrftoken"].value == csrf_before
    assert "_auth_user_id" not in client.session
    login_page = client.get(response.url)
    assert login_page.status_code == 200
    assert "Аккаунт создан" in login_page.content.decode()

    login_response = client.post(
        reverse("login"),
        {
            "username": "csrf-new-user",
            "password": "long-password-123",
            "csrfmiddlewaretoken": csrf_before,
        },
    )
    assert login_response.status_code == 302
    assert login_response.url == reverse("dashboard")


def test_expired_invitation_is_rejected(client: Client) -> None:
    admin = User.objects.create_superuser("admin", "admin@example.test", "admin-password-123")
    invite, token = Invitation.issue(admin)
    invite.expires_at = timezone.now() - timedelta(seconds=1)
    invite.save(update_fields=["expires_at"])
    assert client.get(reverse("register_invite", kwargs={"token": token})).status_code == 404


def test_invitation_get_renders_registration_form(client: Client) -> None:
    admin = User.objects.create_superuser("admin", "admin@example.test", "admin-password-123")
    _invite, token = Invitation.issue(admin)
    assert client.get(reverse("register_invite", kwargs={"token": token})).status_code == 200


def test_user_cannot_request_removal_of_another_users_rule(client: Client) -> None:
    owner = User.objects.create_user("owner", password="long-password-123")
    attacker = User.objects.create_user("attacker", password="long-password-123")
    rule = create_rule(owner, "secret")
    client.force_login(attacker)
    response = client.post(reverse("request_rule_removal", kwargs={"rule_id": rule.pk}))
    assert response.status_code == 404
    assert not RuleRemovalRequest.objects.exists()


def test_user_can_add_but_not_directly_delete_rule(client: Client) -> None:
    user = User.objects.create_user("owner", password="long-password-123")
    TelegramAccount.objects.create(user=user)
    client.force_login(user)
    response = client.post(
        reverse("add_rule"),
        {
            "phrase": "locked phrase",
            "direction": ForbiddenRule.Direction.BOTH,
            "mode": ForbiddenRule.Mode.ENFORCE,
            "is_locked": "on",
        },
    )
    assert response.status_code == 302
    rule = user.forbidden_rules.get()
    response = client.post(reverse("request_rule_removal", kwargs={"rule_id": rule.pk}))
    assert response.status_code == 302
    assert RuleRemovalRequest.objects.filter(user=user, rule=rule).exists()
    assert user.forbidden_rules.filter(pk=rule.pk).exists()

    duplicate = client.post(
        reverse("add_rule"),
        {
            "phrase": "LOCKED PHRASE",
            "direction": ForbiddenRule.Direction.BOTH,
            "mode": ForbiddenRule.Mode.ENFORCE,
            "is_locked": "on",
        },
    )
    assert duplicate.status_code == 200
    assert "уже существует" in duplicate.content.decode()


def test_user_can_cancel_pending_rule_removal(client: Client) -> None:
    user = User.objects.create_user("cancel-removal", password="long-password-123")
    TelegramAccount.objects.create(user=user)
    rule = create_rule(user, "keep this rule")
    removal = RuleRemovalRequest.objects.create(user=user, rule=rule)
    client.force_login(user)

    page = client.get(reverse("dashboard"))
    assert "Отменить запрос на удаление" in page.content.decode()
    response = client.post(
        reverse("cancel_rule_removal", kwargs={"rule_id": rule.pk})
    )

    assert response.status_code == 302
    removal.refresh_from_db()
    assert removal.status == RuleRemovalRequest.Status.CANCELLED
    assert removal.resolved_at is not None
    assert ForbiddenRule.objects.filter(pk=rule.pk).exists()


def test_user_cannot_cancel_another_users_removal(client: Client) -> None:
    owner = User.objects.create_user("removal-owner", password="long-password-123")
    other = User.objects.create_user("removal-other", password="long-password-123")
    rule = create_rule(owner, "private rule")
    RuleRemovalRequest.objects.create(user=owner, rule=rule)
    client.force_login(other)
    assert (
        client.post(
            reverse("cancel_rule_removal", kwargs={"rule_id": rule.pk})
        ).status_code
        == 404
    )


def test_history_scan_start_cancel_and_isolation(client: Client) -> None:
    owner = User.objects.create_user("history-owner", password="long-password-123")
    other = User.objects.create_user("history-other", password="long-password-123")
    account = TelegramAccount.objects.create(user=owner, encrypted_session="encrypted")
    other_account = TelegramAccount.objects.create(
        user=other, encrypted_session="encrypted-other"
    )
    client.force_login(owner)

    started = client.post(reverse("start_history_scan"))
    assert started.status_code == 302
    scan = account.history_scans.get()
    assert scan.phase == HistoryScan.Phase.ENFORCE
    assert scan.status == HistoryScan.Status.QUEUED
    assert client.post(reverse("start_history_scan")).status_code == 302
    assert account.history_scans.count() == 1

    assert (
        client.post(
            reverse("cancel_history_scan", kwargs={"scan_id": scan.pk})
        ).status_code
        == 302
    )
    scan.refresh_from_db()
    assert scan.status == HistoryScan.Status.CANCELLED

    foreign = HistoryScan.objects.create(
        account=other_account,
        phase=HistoryScan.Phase.PREVIEW,
    )
    assert (
        client.post(
            reverse("cancel_history_scan", kwargs={"scan_id": foreign.pk})
        ).status_code
        == 404
    )


def test_history_scan_starts_directly_in_enforce(client: Client) -> None:
    user = User.objects.create_user("direct-history", password="long-password-123")
    account = TelegramAccount.objects.create(user=user, encrypted_session="encrypted")
    client.force_login(user)
    assert client.post(reverse("start_history_scan")).status_code == 302
    assert account.history_scans.get().phase == HistoryScan.Phase.ENFORCE


def test_dashboard_status_includes_per_rule_history_progress(client: Client) -> None:
    user = User.objects.create_user("rule-progress", password="long-password-123")
    TelegramAccount.objects.create(user=user, encrypted_session="encrypted")
    rule = create_rule(user, "история", queue_history=True)
    scan = HistoryScan.objects.get(rule=rule)
    scan.messages_scanned = 120
    scan.matches_found = 4
    scan.deleted_self = 3
    scan.save(
        update_fields=["messages_scanned", "matches_found", "deleted_self"]
    )
    client.force_login(user)

    payload = client.get(reverse("dashboard_status")).json()

    assert payload["rule_scans"][str(rule.pk)]["messages_scanned"] == 120
    assert payload["rule_scans"][str(rule.pk)]["matches_found"] == 4
    assert payload["rule_scans"][str(rule.pk)]["deleted_self"] == 3
    assert payload["history_scan"]["id"] == scan.pk


def test_disconnect_creates_request_without_disabling_account(client: Client) -> None:
    user = User.objects.create_user("owner", password="long-password-123")
    account = TelegramAccount.objects.create(user=user, desired_enabled=True)
    client.force_login(user)
    response = client.post(reverse("request_disconnect"))
    assert response.status_code == 302
    assert DisconnectRequest.objects.filter(user=user).exists()
    account.refresh_from_db()
    assert account.desired_enabled


def test_dashboard_masks_rules_and_isolates_user_data(client: Client) -> None:
    first = User.objects.create_user("first", password="long-password-123")
    second = User.objects.create_user("second", password="long-password-123")
    TelegramAccount.objects.create(user=first)
    TelegramAccount.objects.create(user=second)
    create_rule(first, "visible phrase")
    create_rule(second, "hidden phrase")
    client.force_login(first)
    body = client.get(reverse("dashboard")).content.decode()
    assert "visible phrase" not in body
    assert "hidden phrase" not in body
    own_rule = first.forbidden_rules.get()
    reveal = client.post(reverse("reveal_rule", kwargs={"rule_id": own_rule.pk}))
    assert reveal.json() == {
        "phrase": "visible phrase",
        "phrases": ["visible phrase"],
    }
    assert reveal.headers["Cache-Control"] == "no-store"
    other_rule = second.forbidden_rules.get()
    assert (
        client.post(reverse("reveal_rule", kwargs={"rule_id": other_rule.pk})).status_code
        == 404
    )


def test_all_rules_require_operator_removal_even_if_legacy_caller_requests_unlocked(
    client: Client,
) -> None:
    user = User.objects.create_user("unlocked-owner", password="long-password-123")
    TelegramAccount.objects.create(user=user)
    rule = create_rule(user, "temporary", is_locked=False)
    client.force_login(user)
    response = client.post(reverse("request_rule_removal", kwargs={"rule_id": rule.pk}))
    assert response.status_code == 302
    rule.refresh_from_db()
    assert rule.is_locked
    assert ForbiddenRule.objects.filter(pk=rule.pk).exists()
    assert RuleRemovalRequest.objects.filter(rule=rule, user=user).exists()


def test_rule_test_does_not_create_audit_event(client: Client) -> None:
    user = User.objects.create_user("test-owner", password="long-password-123")
    TelegramAccount.objects.create(user=user)
    rule = create_rule(user, "hidden marker")
    client.force_login(user)
    response = client.post(
        reverse("test_rule", kwargs={"rule_id": rule.pk}),
        {"text": "contains HIDDEN   MARKER here"},
    )
    assert response.json() == {"matched": True}
    assert not FilterEvent.objects.exists()


def test_dashboard_status_is_sanitized_and_user_scoped(client: Client) -> None:
    owner = User.objects.create_user("status-owner", password="long-password-123")
    other = User.objects.create_user("status-other", password="long-password-123")
    account = TelegramAccount.objects.create(user=owner, status=TelegramAccount.Status.ACTIVE)
    TelegramAccount.objects.create(user=other)
    rule = create_rule(owner, "never expose this")
    other_rule = create_rule(other, "other secret")
    FilterEvent.objects.create(
        user=owner,
        rule_ids=[rule.pk],
        direction=FilterEvent.Direction.INCOMING,
        source="body",
        chat_type="private",
        result=FilterEvent.Result.DELETED_SELF,
    )
    FilterEvent.objects.create(
        user=other,
        rule_ids=[other_rule.pk],
        direction=FilterEvent.Direction.OUTGOING,
        source="body",
        chat_type="group",
        result=FilterEvent.Result.FAILED,
    )
    MiniAppAuditEvent.objects.create(
        account=account,
        protection_rule=rule,
        event_type=MiniAppAuditEvent.EventType.BOT_BLOCKED,
        bot_username="owner_bot",
        result=MiniAppAuditEvent.Result.SUCCEEDED,
    )
    MiniAppAuditEvent.objects.create(
        account=other.telegram_account,
        protection_rule=other_rule,
        event_type=MiniAppAuditEvent.EventType.BOT_BLOCKED,
        bot_username="other_bot",
        result=MiniAppAuditEvent.Result.FAILED,
    )
    client.force_login(owner)
    payload = client.get(reverse("dashboard_status")).json()
    assert payload["account"]["status"] == account.get_status_display()
    assert payload["stats"] == {"total": 1, "successful": 1, "failed": 0}
    assert payload["events"][0]["rule_ids"] == [rule.pk]
    assert payload["mini_app_stats"] == {"total": 1, "successful": 1, "failed": 0}
    assert payload["mini_app_events"][0]["rule_id"] == rule.pk
    assert payload["mini_app_events"][0]["bot_username"] == "owner_bot"
    serialized = str(payload)
    assert "never expose this" not in serialized
    assert "other secret" not in serialized
    assert "other_bot" not in serialized


def test_mini_app_ui_is_isolated_by_telegram_account(client: Client) -> None:
    owner = User.objects.create_user("mini-owner", password="long-password-123")
    other = User.objects.create_user("mini-other", password="long-password-123")
    owner_account = TelegramAccount.objects.create(user=owner)
    other_account = TelegramAccount.objects.create(user=other)
    owner_rule = create_rule(owner, "visible_bot")
    create_rule(other, "hidden_bot")
    MiniAppAuditEvent.objects.create(
        account=owner_account,
        protection_rule=owner_rule,
        event_type=MiniAppAuditEvent.EventType.BOT_BLOCKED,
        bot_username="visible_audit_bot",
        result=MiniAppAuditEvent.Result.SUCCEEDED,
    )
    MiniAppAuditEvent.objects.create(
        account=other_account,
        event_type=MiniAppAuditEvent.EventType.OUTGOING_DETECTED,
        bot_username="hidden_audit_bot",
        result=MiniAppAuditEvent.Result.OBSERVED,
    )
    client.force_login(owner)

    legacy_page = client.get(reverse("mini_app_settings"))
    assert legacy_page.status_code == 302
    assert legacy_page.url == f"{reverse('dashboard')}#protection-rules"
    body = client.get(reverse("dashboard")).content.decode()
    assert "visible_bot" not in body
    assert "hidden_bot" not in body
    assert "hidden_audit_bot" not in body
    assert "visible_audit_bot" in body
    assert "Уже открытый WebView Telegram закрыть удалённо нельзя" in body


def test_user_cannot_delete_another_accounts_mini_app_rule(client: Client) -> None:
    owner = User.objects.create_user("mini-rule-owner", password="long-password-123")
    attacker = User.objects.create_user("mini-rule-attacker", password="long-password-123")
    owner_account = TelegramAccount.objects.create(user=owner)
    TelegramAccount.objects.create(user=attacker)
    rule = create_mini_app_rule(
        owner_account,
        MiniAppRule.ListType.DENY,
        MiniAppRule.MatchType.BOT_ID,
        "12345",
    )
    client.force_login(attacker)
    response = client.post(reverse("delete_mini_app_rule", kwargs={"rule_id": rule.pk}))
    assert response.status_code == 404
    assert MiniAppRule.objects.filter(pk=rule.pk).exists()


def test_mini_app_policy_is_always_hard_without_extra_settings(client: Client) -> None:
    user = User.objects.create_user("mini-policy-owner", password="long-password-123")
    TelegramAccount.objects.create(user=user)
    client.force_login(user)

    page = client.get(reverse("mini_app_settings"), follow=True)
    assert page.status_code == 200
    body = page.content.decode()
    assert "Наблюдение" not in body
    assert "Предупреждение" not in body
    assert "подтверждаю включение" not in body
    assert "Все правила работают в режиме жёсткого ограничения" in body
    assert "Защитить правило" not in client.get(reverse("add_rule")).content.decode()


def test_add_mini_app_rule_creates_hard_keyword_rule(client: Client) -> None:
    user = User.objects.create_user("mini-keyword-owner", password="long-password-123")
    TelegramAccount.objects.create(user=user)
    client.force_login(user)
    response = client.post(
        reverse("add_mini_app_rule"),
        {"value": "lucid_dreams\nDream App"},
    )
    assert response.status_code == 302
    rule = ForbiddenRule.objects.get(user=user)
    assert rule.active
    assert rule.is_locked
    assert rule.mode == ForbiddenRule.Mode.ENFORCE
    assert rule.patterns.count() == 2
    scan = HistoryScan.objects.get(account__user=user)
    assert scan.phase == HistoryScan.Phase.ENFORCE
    assert scan.status == HistoryScan.Status.QUEUED


def test_legacy_mini_app_endpoints_preserve_protected_removal_contract(
    client: Client,
) -> None:
    user = User.objects.create_user("legacy-mini-owner", password="long-password-123")
    account = TelegramAccount.objects.create(user=user)
    protection_rule = create_rule(user, "legacy keyword")
    linked = create_mini_app_rule(
        account,
        MiniAppRule.ListType.DENY,
        MiniAppRule.MatchType.KEYWORD,
        "legacy keyword",
    )
    linked.protection_rule = protection_rule
    linked.save(update_fields=["protection_rule"])
    unlinked = create_mini_app_rule(
        account,
        MiniAppRule.ListType.DENY,
        MiniAppRule.MatchType.BOT_ID,
        "4242",
    )
    client.force_login(user)

    response = client.post(
        reverse("delete_mini_app_rule", kwargs={"rule_id": linked.pk})
    )
    assert response.status_code == 302
    assert RuleRemovalRequest.objects.filter(
        user=user, rule=protection_rule
    ).exists()
    assert MiniAppRule.objects.filter(pk=linked.pk).exists()

    response = client.post(
        reverse("delete_mini_app_rule", kwargs={"rule_id": unlinked.pk}),
        follow=True,
    )
    assert response.status_code == 200
    assert "только через оператора" in response.content.decode()
    assert MiniAppRule.objects.filter(pk=unlinked.pk).exists()


def test_legacy_add_mini_app_endpoint_rejects_invalid_and_duplicate(
    client: Client,
) -> None:
    user = User.objects.create_user("legacy-mini-add", password="long-password-123")
    TelegramAccount.objects.create(user=user)
    client.force_login(user)

    invalid = client.post(reverse("add_mini_app_rule"), {"value": ""}, follow=True)
    assert "Правило не добавлено" in invalid.content.decode()

    create_rule(user, "duplicate mini phrase")
    duplicate = client.post(
        reverse("add_mini_app_rule"),
        {"value": "DUPLICATE MINI PHRASE"},
        follow=True,
    )
    assert "Такое правило уже существует" in duplicate.content.decode()


def test_qr_and_phone_auth_views(client: Client) -> None:
    user = User.objects.create_user("auth-user", password="long-password-123")
    TelegramAccount.objects.create(user=user)
    client.force_login(user)

    assert client.get(reverse("telegram_auth")).status_code == 200
    assert client.post(reverse("start_qr_auth")).status_code == 302
    qr_flow = user.telegram_auth_flows.latest("created_at")
    assert qr_flow.kind == TelegramAuthFlow.Kind.QR

    assert client.get(reverse("start_phone_auth")).status_code == 200
    assert client.post(reverse("start_phone_auth"), {"phone": "+70000000000"}).status_code == 302
    phone_flow = user.telegram_auth_flows.latest("created_at")
    assert phone_flow.kind == TelegramAuthFlow.Kind.PHONE
    assert decrypt_for_user(user, phone_flow.encrypted_payload) == "+70000000000"
    qr_flow.refresh_from_db()
    assert qr_flow.state == TelegramAuthFlow.State.EXPIRED


def test_qr_page_and_secret_submission(client: Client) -> None:
    user = User.objects.create_user("qr-view-user", password="long-password-123")
    TelegramAccount.objects.create(user=user)
    client.force_login(user)
    flow = TelegramAuthFlow.objects.create(
        user=user,
        kind=TelegramAuthFlow.Kind.QR,
        state=TelegramAuthFlow.State.QR_READY,
        encrypted_payload=encrypt_for_user(user, "tg://login?token=test"),
        expires_at=timezone.now() + timedelta(minutes=5),
    )
    page = client.get(reverse("telegram_auth"))
    assert page.status_code == 200
    assert "data:image/png;base64" in page.content.decode()

    flow.state = TelegramAuthFlow.State.CODE_REQUIRED
    flow.encrypted_payload = ""
    flow.save(update_fields=["state", "encrypted_payload"])
    response = client.post(reverse("submit_auth_secret"), {"secret": "12345"})
    assert response.status_code == 302
    flow.refresh_from_db()
    assert flow.state == TelegramAuthFlow.State.VERIFYING
    assert decrypt_for_user(user, flow.encrypted_payload) == "12345"


def test_auth_waiting_refreshes_and_complete_redirects(client: Client) -> None:
    user = User.objects.create_user("auth-refresh", password="long-password-123")
    TelegramAccount.objects.create(user=user)
    client.force_login(user)
    flow = TelegramAuthFlow.objects.create(
        user=user,
        kind=TelegramAuthFlow.Kind.PHONE,
        state=TelegramAuthFlow.State.VERIFYING,
        expires_at=timezone.now() + timedelta(minutes=5),
    )
    waiting = client.get(reverse("telegram_auth"))
    assert waiting.headers["Refresh"] == "2"
    assert "Страница обновится автоматически" in waiting.content.decode()
    flow.state = TelegramAuthFlow.State.COMPLETE
    flow.save(update_fields=["state"])
    assert client.get(reverse("telegram_auth")).status_code == 302


def test_user_can_cancel_auth_flow(client: Client) -> None:
    user = User.objects.create_user("auth-cancel", password="long-password-123")
    TelegramAccount.objects.create(user=user)
    client.force_login(user)
    flow = TelegramAuthFlow.objects.create(
        user=user,
        kind=TelegramAuthFlow.Kind.QR,
        state=TelegramAuthFlow.State.QR_READY,
        encrypted_payload=encrypt_for_user(user, "tg://login?token=test"),
        expires_at=timezone.now() + timedelta(minutes=5),
    )
    assert client.post(reverse("cancel_telegram_auth")).status_code == 302
    flow.refresh_from_db()
    assert flow.state == TelegramAuthFlow.State.CANCELLED
    assert flow.encrypted_payload == ""


def test_staff_creates_invitation_and_limit_is_enforced(client: Client) -> None:
    admin = User.objects.create_superuser("operator", "operator@example.test", "admin-password-123")
    client.force_login(admin)
    assert client.get(reverse("create_invitation")).status_code == 200
    created = client.post(reverse("create_invitation"))
    assert created.status_code == 200
    assert "/invite/" in created.content.decode()
    assert "Копировать ссылку" in created.content.decode()
    assert Invitation.objects.filter(created_by=admin).count() == 1
    for index in range(9):
        user = User.objects.create_user(f"limited-{index}", password="long-password-123")
        TelegramAccount.objects.create(user=user)
    limited = client.post(reverse("create_invitation"))
    assert "Свободных мест" in limited.content.decode()
    assert Invitation.objects.filter(created_by=admin).count() == 1


def test_operator_dashboard_and_invitation_revocation_are_staff_only(
    client: Client,
) -> None:
    user = User.objects.create_user("regular", password="long-password-123")
    client.force_login(user)
    assert client.get(reverse("operator_dashboard")).status_code == 302

    operator = User.objects.create_superuser(
        "operator-ui", "operator@example.test", "admin-password-123"
    )
    client.force_login(operator)
    page = client.get(reverse("operator_dashboard"))
    assert page.status_code == 200
    assert "Кабинет оператора" in page.content.decode()
    invitation, _token = Invitation.issue(operator)
    response = client.post(
        reverse("revoke_invitation", kwargs={"invitation_id": invitation.pk})
    )
    assert response.status_code == 302
    invitation.refresh_from_db()
    assert invitation.revoked_at is not None
    assert not invitation.is_valid()


def test_operator_resolves_rule_and_disconnect_requests(client: Client) -> None:
    operator = User.objects.create_superuser(
        "operator-resolve", "operator@example.test", "admin-password-123"
    )
    user = User.objects.create_user("managed-user", password="long-password-123")
    account = TelegramAccount.objects.create(user=user, desired_enabled=True)
    rule = create_rule(user, "protected")
    removal = RuleRemovalRequest.objects.create(user=user, rule=rule)
    disconnect = DisconnectRequest.objects.create(user=user)
    client.force_login(operator)

    response = client.post(
        reverse(
            "resolve_rule_removal",
            kwargs={"request_id": removal.pk, "decision": "approve"},
        )
    )
    assert response.status_code == 302
    removal.refresh_from_db()
    assert removal.status == RuleRemovalRequest.Status.APPROVED
    assert not ForbiddenRule.objects.filter(pk=rule.pk).exists()

    response = client.post(
        reverse(
            "resolve_disconnect",
            kwargs={"request_id": disconnect.pk, "decision": "approve"},
        )
    )
    assert response.status_code == 302
    disconnect.refresh_from_db()
    account.refresh_from_db()
    assert disconnect.status == DisconnectRequest.Status.APPROVED
    assert not account.desired_enabled


def test_rule_edit_weakening_waits_for_operator_and_keeps_current_version(
    client: Client,
) -> None:
    user = User.objects.create_user("edit-owner", password="long-password-123")
    TelegramAccount.objects.create(user=user, encrypted_session="encrypted")
    rule = create_rule(user, ["первая", "вторая"], is_locked=True)
    client.force_login(user)

    response = client.post(
        reverse("edit_rule", kwargs={"rule_id": rule.pk}),
        {
            "label": "Изменённое правило",
            "phrases": "первая",
            "direction": ForbiddenRule.Direction.OUTGOING,
            "mode": ForbiddenRule.Mode.WARN,
        },
    )

    assert response.status_code == 302
    change = RuleChangeRequest.objects.get(rule=rule)
    assert change.status == RuleChangeRequest.Status.PENDING
    rule.refresh_from_db()
    assert rule.revision == 1
    assert rule.mode == ForbiddenRule.Mode.ENFORCE


def test_owner_can_cancel_pending_protected_rule_change(client: Client) -> None:
    user = User.objects.create_user("cancel-change-owner", password="long-password-123")
    TelegramAccount.objects.create(user=user)
    rule = create_rule(user, ["первая", "вторая"], is_locked=True)
    client.force_login(user)
    client.post(
        reverse("edit_rule", kwargs={"rule_id": rule.pk}),
        {
            "label": "",
            "phrases": "первая",
            "direction": ForbiddenRule.Direction.OUTGOING,
            "mode": ForbiddenRule.Mode.WARN,
        },
    )
    change = RuleChangeRequest.objects.get(rule=rule)

    response = client.post(
        reverse("cancel_rule_change", kwargs={"rule_id": rule.pk})
    )

    assert response.status_code == 302
    change.refresh_from_db()
    assert change.status == RuleChangeRequest.Status.CANCELLED
    assert change.resolved_at is not None


@pytest.mark.parametrize(
    ("decision", "expected_status"),
    [
        ("approve", RuleChangeRequest.Status.APPROVED),
        ("reject", RuleChangeRequest.Status.REJECTED),
    ],
)
def test_operator_resolves_protected_rule_change(
    client: Client,
    decision: str,
    expected_status: str,
) -> None:
    operator = User.objects.create_superuser(
        f"change-{decision}-operator",
        f"change-{decision}@example.test",
        "long-password-123",
    )
    owner = User.objects.create_user(
        f"change-{decision}-owner", password="long-password-123"
    )
    TelegramAccount.objects.create(user=owner)
    rule = create_rule(owner, ["первая", "вторая"], is_locked=True)
    owner_client = Client()
    owner_client.force_login(owner)
    owner_client.post(
        reverse("edit_rule", kwargs={"rule_id": rule.pk}),
        {
            "label": "Новое имя",
            "phrases": "первая",
            "direction": ForbiddenRule.Direction.OUTGOING,
            "mode": ForbiddenRule.Mode.WARN,
        },
    )
    change = RuleChangeRequest.objects.get(rule=rule)
    client.force_login(operator)

    response = client.post(
        reverse(
            "resolve_rule_change_request",
            kwargs={"request_id": change.pk, "decision": decision},
        )
    )

    assert response.status_code == 302
    change.refresh_from_db()
    rule.refresh_from_db()
    assert change.status == expected_status
    assert change.resolved_by == operator
    assert rule.mode == ForbiddenRule.Mode.ENFORCE
    assert rule.is_locked
    assert rule.revision == (2 if decision == "approve" else 1)


def test_operator_can_close_one_or_all_visible_notifications(client: Client) -> None:
    operator = User.objects.create_superuser(
        "notification-operator",
        "notification-operator@example.test",
        "long-password-123",
    )
    owner = User.objects.create_user("notification-owner", password="long-password-123")
    account = TelegramAccount.objects.create(user=owner)
    items = [
        OperatorNotification.objects.create(
            account=account,
            event_type=MiniAppAuditEvent.EventType.MENU_DETECTED,
            result=MiniAppAuditEvent.Result.OBSERVED,
            dedup_key=f"event-{index}",
            first_seen_at=timezone.now(),
            last_seen_at=timezone.now(),
        )
        for index in range(3)
    ]
    client.force_login(operator)

    response = client.post(
        reverse(
            "process_operator_notification",
            kwargs={"notification_id": items[0].pk},
        )
    )
    assert response.status_code == 302
    items[0].refresh_from_db()
    assert items[0].processed_by == operator

    response = client.post(
        reverse("process_visible_notifications"),
        {"notification_ids": f"{items[1].pk},{items[2].pk}"},
    )
    assert response.status_code == 302
    assert (
        OperatorNotification.objects.filter(
            pk__in=[items[1].pk, items[2].pk],
            processed_by=operator,
            processed_at__isnull=False,
        ).count()
        == 2
    )


def test_operator_blocks_user_without_exposing_vpn_control_to_product(
    client: Client,
) -> None:
    operator = User.objects.create_superuser(
        "block-operator",
        "block-operator@example.test",
        "long-password-123",
    )
    owner = User.objects.create_user("blocked-owner", password="long-password-123")
    account = TelegramAccount.objects.create(user=owner, desired_enabled=True)
    client.force_login(operator)

    response = client.post(reverse("block_user", kwargs={"user_id": owner.pk}))

    assert response.status_code == 302
    owner.refresh_from_db()
    account.refresh_from_db()
    assert not owner.is_active
    assert not account.desired_enabled
