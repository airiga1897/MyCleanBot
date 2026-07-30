from __future__ import annotations

from django.contrib.auth.models import User
from django.db import IntegrityError, transaction

from core.models import ForbiddenRule
from core.services.crypto import decrypt_for_user, encrypt_for_user, fingerprint
from core.services.matcher import normalize_text


class DuplicateRuleError(ValueError):
    pass


@transaction.atomic
def create_rule(
    user: User,
    phrase: str,
    *,
    direction: str = ForbiddenRule.Direction.BOTH,
    mode: str = ForbiddenRule.Mode.ENFORCE,
    is_locked: bool = True,
) -> ForbiddenRule:
    normalized = normalize_text(phrase)
    if not normalized:
        raise ValueError("Phrase cannot be empty")
    try:
        return ForbiddenRule.objects.create(
            user=user,
            encrypted_phrase=encrypt_for_user(user, phrase.strip()),
            phrase_fingerprint=fingerprint(f"{user.pk}:{normalized}"),
            direction=direction,
            mode=mode,
            is_locked=is_locked,
        )
    except IntegrityError as exc:
        raise DuplicateRuleError("Rule already exists") from exc


def decrypted_rules(
    user: User, direction: str | None = None
) -> list[tuple[int, str, str]]:
    rules = user.forbidden_rules.filter(active=True)
    if direction:
        rules = rules.filter(
            direction__in=[direction, ForbiddenRule.Direction.BOTH]
        )
    return [
        (
            rule.pk,
            normalize_text(decrypt_for_user(user, rule.encrypted_phrase)),
            rule.mode,
        )
        for rule in rules
    ]


def display_rules(user: User) -> list[tuple[ForbiddenRule, str]]:
    return [
        (rule, decrypt_for_user(user, rule.encrypted_phrase)) for rule in user.forbidden_rules.all()
    ]
