from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction

from core.models import UserKey


class DecryptionError(ValueError):
    pass


def _master_key() -> bytes:
    if not settings.MASTER_ENCRYPTION_KEY:
        if settings.DEBUG:
            return base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest())
        raise ImproperlyConfigured("MASTER_ENCRYPTION_KEY is required")
    return settings.MASTER_ENCRYPTION_KEY.encode()


def _master_fernet() -> Fernet:
    try:
        return Fernet(_master_key())
    except (TypeError, ValueError) as exc:
        raise ImproperlyConfigured("MASTER_ENCRYPTION_KEY must be a Fernet key") from exc


@transaction.atomic
def ensure_user_key(user: User) -> UserKey:
    key, created = UserKey.objects.select_for_update().get_or_create(
        user=user, defaults={"encrypted_dek": ""}
    )
    if created:
        key.encrypted_dek = _master_fernet().encrypt(Fernet.generate_key()).decode()
        key.save(update_fields=["encrypted_dek"])
    return key


def user_fernet(user: User) -> Fernet:
    wrapped = ensure_user_key(user).encrypted_dek.encode()
    try:
        return Fernet(_master_fernet().decrypt(wrapped))
    except InvalidToken as exc:
        raise DecryptionError("Unable to unwrap user key") from exc


def encrypt_for_user(user: User, value: str) -> str:
    return user_fernet(user).encrypt(value.encode()).decode()


def decrypt_for_user(user: User, value: str) -> str:
    try:
        return user_fernet(user).decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise DecryptionError("Unable to decrypt user data") from exc


def fingerprint(value: str) -> str:
    raw_key = base64.urlsafe_b64decode(_master_key())
    return hmac.new(raw_key, value.encode(), hashlib.sha256).hexdigest()
