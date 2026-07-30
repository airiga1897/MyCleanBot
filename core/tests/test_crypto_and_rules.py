import base64
import hashlib

import pytest
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from core.models import (
    ForbiddenRule,
    HistoryScan,
    RuleChangeRequest,
    TelegramAccount,
    TelegramDialog,
)
from core.services import crypto
from core.services.crypto import decrypt_for_user, encrypt_for_user
from core.services.rules import (
    DuplicateRuleError,
    create_rule,
    decrypted_rules,
    peer_fingerprint,
    resolve_rule_change,
    update_rule,
)

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def encryption_settings(settings: object) -> None:
    settings.MASTER_ENCRYPTION_KEY = base64.urlsafe_b64encode(
        hashlib.sha256(b"tests").digest()
    ).decode()


def test_envelope_encryption_is_user_scoped() -> None:
    first = User.objects.create_user("first", password="long-test-password")
    second = User.objects.create_user("second", password="long-test-password")
    encrypted = encrypt_for_user(first, "sensitive phrase")
    assert "sensitive phrase" not in encrypted
    assert decrypt_for_user(first, encrypted) == "sensitive phrase"
    with pytest.raises(ValueError):
        decrypt_for_user(second, encrypted)


def test_rule_is_encrypted_and_normalized_for_matching() -> None:
    user = User.objects.create_user("owner", password="long-test-password")
    rule = create_rule(user, "  Моя\nФраза ")
    assert "Моя" not in rule.encrypted_phrase
    specs = decrypted_rules(user)
    assert len(specs) == 1
    assert specs[0].id == rule.pk
    assert specs[0].phrases == ("моя", "фраза")
    assert specs[0].mode == ForbiddenRule.Mode.ENFORCE


def test_duplicate_rule_is_rejected_after_normalization() -> None:
    user = User.objects.create_user("owner", password="long-test-password")
    create_rule(user, "Моя   Фраза")
    with pytest.raises(DuplicateRuleError):
        create_rule(user, "моя фраза")
    assert ForbiddenRule.objects.filter(user=user).count() == 1


def test_composite_rule_is_scoped_to_selected_dialogs() -> None:
    user = User.objects.create_user("scoped-owner", password="long-test-password")
    account = TelegramAccount.objects.create(user=user)
    dialog = TelegramDialog.objects.create(
        account=account,
        peer_fingerprint=peer_fingerprint(account.pk, -10042),
        encrypted_label=encrypt_for_user(user, "Семейный чат"),
        kind=TelegramDialog.Kind.SUPERGROUP,
        last_seen_at=timezone.now(),
    )
    rule = create_rule(
        user,
        ["первая фраза", "вторая фраза"],
        label="Семья",
        dialog_ids=[dialog.pk],
    )

    spec = decrypted_rules(user)[0]
    assert spec.id == rule.pk
    assert spec.phrases == ("первая фраза", "вторая фраза")
    assert spec.dialog_fingerprints == frozenset({dialog.peer_fingerprint})
    assert "Семья" not in rule.encrypted_label


def test_locked_rule_weakening_is_atomic_and_requires_operator() -> None:
    operator = User.objects.create_superuser(
        "rules-operator",
        "rules-operator@example.test",
        "long-test-password",
    )
    user = User.objects.create_user("managed-owner", password="long-test-password")
    TelegramAccount.objects.create(user=user, encrypted_session="encrypted")
    rule = create_rule(user, ["сильная", "резервная"], is_locked=True)

    unchanged, change = update_rule(
        rule,
        label="После согласования",
        phrases=["сильная"],
        direction=ForbiddenRule.Direction.OUTGOING,
        mode=ForbiddenRule.Mode.WARN,
        is_locked=False,
        dialog_ids=[],
    )

    assert unchanged.revision == 1
    assert change is not None
    assert change.status == RuleChangeRequest.Status.PENDING
    assert "сильная" not in change.encrypted_payload
    assert decrypted_rules(user)[0].phrases == ("сильная", "резервная")

    resolve_rule_change(change, operator, approve=True)
    rule.refresh_from_db()
    assert rule.revision == 2
    assert rule.mode == ForbiddenRule.Mode.WARN
    assert not rule.is_locked
    assert decrypted_rules(user)[0].phrases == ("сильная",)
    assert not HistoryScan.objects.filter(rule=rule).exists()


def test_strengthening_rule_applies_immediately_and_queues_history() -> None:
    user = User.objects.create_user("stronger-owner", password="long-test-password")
    TelegramAccount.objects.create(user=user, encrypted_session="encrypted")
    rule = create_rule(
        user,
        "первая",
        direction=ForbiddenRule.Direction.OUTGOING,
        mode=ForbiddenRule.Mode.ENFORCE,
    )

    updated, change = update_rule(
        rule,
        label="Усилено",
        phrases=["первая", "вторая"],
        direction=ForbiddenRule.Direction.BOTH,
        mode=ForbiddenRule.Mode.ENFORCE,
        is_locked=True,
        dialog_ids=[],
    )

    assert change is None
    assert updated.revision == 2
    assert decrypted_rules(user)[0].phrases == ("первая", "вторая")
    scan = HistoryScan.objects.get(rule=rule)
    assert scan.phase == HistoryScan.Phase.ENFORCE
    assert scan.rule_revision == 2


def test_deleting_rule_cancels_its_history_job() -> None:
    user = User.objects.create_user("delete-owner", password="long-test-password")
    TelegramAccount.objects.create(user=user, encrypted_session="encrypted")
    rule = create_rule(user, "удалить", queue_history=True)
    scan = HistoryScan.objects.get(rule=rule)

    rule.delete()

    scan.refresh_from_db()
    assert scan.rule_id is None
    assert scan.status == HistoryScan.Status.CANCELLED
    assert scan.cancel_requested
    assert scan.last_error_code == "rule_deleted"


def test_master_key_validation(settings: object) -> None:
    settings.DEBUG = False
    settings.MASTER_ENCRYPTION_KEY = ""
    with pytest.raises(ImproperlyConfigured):
        crypto._master_key()
    settings.MASTER_ENCRYPTION_KEY = "invalid"
    with pytest.raises(ImproperlyConfigured):
        crypto._master_fernet()
