from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from django.contrib.auth.models import User
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from core.forms import RuleForm
from core.models import TelegramAccount, TelegramDialog
from core.services.crypto import encrypt_for_user


@pytest.mark.django_db
@override_settings(MASTER_ENCRYPTION_KEY=Fernet.generate_key().decode())
def test_rule_form_renders_dialog_choices_with_constant_query_count() -> None:
    user = User.objects.create_user(username="form-owner", password="test-pass")
    account = TelegramAccount.objects.create(user=user)
    for index in range(5):
        TelegramDialog.objects.create(
            account=account,
            peer_fingerprint=f"peer-{index}",
            encrypted_label=encrypt_for_user(user, f"Dialog {index}"),
            kind=TelegramDialog.Kind.PRIVATE,
            available=True,
            last_seen_at=timezone.now(),
        )

    with CaptureQueriesContext(connection) as queries:
        html = str(RuleForm(user=user)["dialogs"])

    assert len(queries) <= 6
    assert "Dialog 0" in html
    assert "Dialog 4" in html
