from types import SimpleNamespace
from typing import Any

import pytest
from django.contrib.auth.models import User

from core import admin as core_admin
from core.models import DisconnectRequest, RuleRemovalRequest, TelegramAccount
from core.services.rules import create_rule

pytestmark = pytest.mark.django_db


class ModelAdminStub:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def message_user(self, _request: Any, message: str, _level: Any) -> None:
        self.messages.append(message)


def test_rule_removal_admin_actions() -> None:
    operator = User.objects.create_superuser(
        "operator", "operator@example.test", "admin-password-123"
    )
    user = User.objects.create_user("rule-owner", password="long-password-123")
    first_rule = create_rule(user, "first")
    approved = RuleRemovalRequest.objects.create(user=user, rule=first_rule)
    modeladmin = ModelAdminStub()
    request = SimpleNamespace(user=operator)
    core_admin.approve_rule_removal(
        modeladmin,
        request,
        RuleRemovalRequest.objects.filter(pk=approved.pk),
    )
    approved.refresh_from_db()
    assert approved.status == RuleRemovalRequest.Status.APPROVED
    assert approved.rule is None
    assert modeladmin.messages

    second_rule = create_rule(user, "second")
    rejected = RuleRemovalRequest.objects.create(user=user, rule=second_rule)
    core_admin.reject_rule_removal(
        modeladmin,
        request,
        RuleRemovalRequest.objects.filter(pk=rejected.pk),
    )
    rejected.refresh_from_db()
    assert rejected.status == RuleRemovalRequest.Status.REJECTED


def test_disconnect_admin_actions() -> None:
    operator = User.objects.create_superuser(
        "disconnect-operator", "operator@example.test", "admin-password-123"
    )
    user = User.objects.create_user("disconnect-owner", password="long-password-123")
    account = TelegramAccount.objects.create(user=user)
    approved = DisconnectRequest.objects.create(user=user)
    modeladmin = ModelAdminStub()
    request = SimpleNamespace(user=operator)
    core_admin.approve_disconnect(
        modeladmin,
        request,
        DisconnectRequest.objects.filter(pk=approved.pk),
    )
    approved.refresh_from_db()
    account.refresh_from_db()
    assert approved.status == DisconnectRequest.Status.APPROVED
    assert not account.desired_enabled

    rejected = DisconnectRequest.objects.create(user=user)
    core_admin.reject_disconnect(
        modeladmin,
        request,
        DisconnectRequest.objects.filter(pk=rejected.pk),
    )
    rejected.refresh_from_db()
    assert rejected.status == DisconnectRequest.Status.REJECTED
