import base64
import hashlib

import pytest
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured

from core.models import ForbiddenRule
from core.services import crypto
from core.services.crypto import decrypt_for_user, encrypt_for_user
from core.services.rules import DuplicateRuleError, create_rule, decrypted_rules

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
    assert decrypted_rules(user) == [
        (rule.pk, "моя фраза", ForbiddenRule.Mode.ENFORCE)
    ]


def test_duplicate_rule_is_rejected_after_normalization() -> None:
    user = User.objects.create_user("owner", password="long-test-password")
    create_rule(user, "Моя   Фраза")
    with pytest.raises(DuplicateRuleError):
        create_rule(user, "моя фраза")
    assert ForbiddenRule.objects.filter(user=user).count() == 1


def test_master_key_validation(settings: object) -> None:
    settings.DEBUG = False
    settings.MASTER_ENCRYPTION_KEY = ""
    with pytest.raises(ImproperlyConfigured):
        crypto._master_key()
    settings.MASTER_ENCRYPTION_KEY = "invalid"
    with pytest.raises(ImproperlyConfigured):
        crypto._master_fernet()
