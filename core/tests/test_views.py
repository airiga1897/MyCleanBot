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
    Invitation,
    RuleRemovalRequest,
    TelegramAccount,
    TelegramAuthFlow,
)
from core.services.crypto import decrypt_for_user, encrypt_for_user
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
    invite.refresh_from_db()
    assert invite.consumed_at is not None
    client.logout()
    assert client.get(reverse("register_invite", kwargs={"token": token})).status_code == 404


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
    response = client.post(reverse("add_rule"), {"phrase": "locked phrase", "confirm_locked": "on"})
    assert response.status_code == 302
    rule = user.forbidden_rules.get()
    response = client.post(reverse("request_rule_removal", kwargs={"rule_id": rule.pk}))
    assert response.status_code == 302
    assert RuleRemovalRequest.objects.filter(user=user, rule=rule).exists()
    assert user.forbidden_rules.filter(pk=rule.pk).exists()

    duplicate = client.post(
        reverse("add_rule"), {"phrase": "LOCKED PHRASE", "confirm_locked": "on"}
    )
    assert duplicate.status_code == 200
    assert "уже существует" in duplicate.content.decode()


def test_disconnect_creates_request_without_disabling_account(client: Client) -> None:
    user = User.objects.create_user("owner", password="long-password-123")
    account = TelegramAccount.objects.create(user=user, desired_enabled=True)
    client.force_login(user)
    response = client.post(reverse("request_disconnect"))
    assert response.status_code == 302
    assert DisconnectRequest.objects.filter(user=user).exists()
    account.refresh_from_db()
    assert account.desired_enabled


def test_dashboard_only_contains_current_users_events_and_rules(client: Client) -> None:
    first = User.objects.create_user("first", password="long-password-123")
    second = User.objects.create_user("second", password="long-password-123")
    TelegramAccount.objects.create(user=first)
    TelegramAccount.objects.create(user=second)
    create_rule(first, "visible phrase")
    create_rule(second, "hidden phrase")
    client.force_login(first)
    body = client.get(reverse("dashboard")).content.decode()
    assert "visible phrase" in body
    assert "hidden phrase" not in body


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
    assert decrypt_for_user(user, flow.encrypted_payload) == "12345"


def test_staff_creates_invitation_and_limit_is_enforced(client: Client) -> None:
    admin = User.objects.create_superuser("operator", "operator@example.test", "admin-password-123")
    client.force_login(admin)
    assert client.get(reverse("create_invitation")).status_code == 200
    created = client.post(reverse("create_invitation"))
    assert created.status_code == 200
    assert "/invite/" in created.content.decode()
    assert Invitation.objects.filter(created_by=admin).count() == 1

    for index in range(10):
        user = User.objects.create_user(f"limited-{index}", password="long-password-123")
        TelegramAccount.objects.create(user=user)
    limited = client.post(reverse("create_invitation"))
    assert "Достигнут лимит" in limited.content.decode()
    assert Invitation.objects.filter(created_by=admin).count() == 1
