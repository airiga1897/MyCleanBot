from __future__ import annotations

from django.contrib.auth.models import User
from django.db import IntegrityError, transaction

from core.models import ForbiddenRule
from core.services.crypto import decrypt_for_user, encrypt_for_user, fingerprint
from core.services.matcher import normalize_text


class DuplicateRuleError(ValueError):
    pass


@transaction.atomic
def create_rule(user: User, phrase: str) -> ForbiddenRule:
    normalized = normalize_text(phrase)
    if not normalized:
        raise ValueError("Phrase cannot be empty")
    try:
        return ForbiddenRule.objects.create(
            user=user,
            encrypted_phrase=encrypt_for_user(user, phrase.strip()),
            phrase_fingerprint=fingerprint(f"{user.pk}:{normalized}"),
        )
    except IntegrityError as exc:
        raise DuplicateRuleError("Rule already exists") from exc


def decrypted_rules(user: User) -> list[tuple[int, str]]:
    return [
        (rule.pk, normalize_text(decrypt_for_user(user, rule.encrypted_phrase)))
        for rule in user.forbidden_rules.filter(active=True)
    ]


def display_rules(user: User) -> list[tuple[ForbiddenRule, str]]:
    return [
        (rule, decrypt_for_user(user, rule.encrypted_phrase)) for rule in user.forbidden_rules.all()
    ]
