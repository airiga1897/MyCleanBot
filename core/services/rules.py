from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, cast

from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.utils import timezone

from core.models import (
    ForbiddenRule,
    HistoryScan,
    MiniAppRule,
    MiniAppRulePattern,
    RuleChangeRequest,
    RuleDialogScope,
    RulePattern,
    TelegramAccount,
    TelegramDialog,
)
from core.services.crypto import (
    decrypt_for_user,
    decrypt_many_for_user,
    encrypt_for_user,
    encrypt_many_for_user,
    fingerprint,
)
from core.services.matcher import normalize_text


class DuplicateRuleError(ValueError):
    pass


class PendingRuleChangeError(ValueError):
    pass


@dataclass(frozen=True)
class RuleSpec:
    id: int
    phrases: tuple[str, ...]
    mode: str
    revision: int
    dialog_fingerprints: frozenset[str] | None


def peer_fingerprint(account_id: int, peer_id: int) -> str:
    return fingerprint(f"telegram-dialog:{account_id}:{peer_id}")


def _normalize_phrases(phrases: str | Iterable[str]) -> list[tuple[str, str]]:
    values = phrases.splitlines() if isinstance(phrases, str) else list(phrases)
    unique: dict[str, str] = {}
    for value in values:
        raw = str(value).strip()
        normalized = normalize_text(raw)
        if normalized:
            unique.setdefault(normalized, raw)
    if not unique:
        raise ValueError("At least one phrase is required")
    return list(unique.items())


def _direction_set(direction: str) -> set[str]:
    if direction == ForbiddenRule.Direction.BOTH:
        return {ForbiddenRule.Direction.INCOMING, ForbiddenRule.Direction.OUTGOING}
    return {direction}


def _is_weakening(
    rule: ForbiddenRule,
    normalized_phrases: set[str],
    direction: str,
    mode: str,
    is_locked: bool,
    dialog_ids: set[int],
) -> tuple[bool, dict[str, int | bool]]:
    encrypted_phrases = [item.encrypted_phrase for item in rule.patterns.all()]
    current_phrases = {
        normalize_text(value)
        for value in decrypt_many_for_user(
            rule.user, encrypted_phrases or [rule.encrypted_phrase]
        )
    }
    current_dialog_ids = set(rule.dialog_scopes.values_list("dialog_id", flat=True))
    mode_rank: dict[str, int] = {
        ForbiddenRule.Mode.OBSERVE: 0,
        ForbiddenRule.Mode.WARN: 1,
        ForbiddenRule.Mode.ENFORCE: 2,
    }
    removed_phrases = len(current_phrases - normalized_phrases)
    summary: dict[str, int | bool] = {
        "removed_phrases": removed_phrases,
        "direction_narrowed": not _direction_set(rule.direction).issubset(
            _direction_set(direction)
        ),
        "scope_narrowed": (
            (not current_dialog_ids and bool(dialog_ids))
            or (
                bool(current_dialog_ids)
                and bool(dialog_ids)
                and not current_dialog_ids.issubset(dialog_ids)
            )
        ),
        "mode_lowered": mode_rank[mode] < mode_rank[rule.mode],
        "unlocked": rule.is_locked and not is_locked,
    }
    return any(bool(value) for value in summary.values()), summary


def _serialized_payload(
    *,
    label: str,
    phrases: list[str],
    direction: str,
    mode: str,
    is_locked: bool,
    dialog_ids: set[int],
) -> str:
    return json.dumps(
        {
            "label": label.strip(),
            "phrases": phrases,
            "direction": direction,
            "mode": mode,
            "is_locked": is_locked,
            "dialog_ids": sorted(dialog_ids),
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def queue_history_scan(rule: ForbiddenRule) -> None:
    scans = HistoryScan.objects.filter(
        rule=rule,
        status__in=[
            HistoryScan.Status.QUEUED,
            HistoryScan.Status.RUNNING,
            HistoryScan.Status.AWAITING_CONFIRMATION,
        ],
    )
    scans.exclude(status=HistoryScan.Status.RUNNING).update(
        status=HistoryScan.Status.CANCELLED,
        cancel_requested=True,
        completed_at=timezone.now(),
    )
    scans.filter(status=HistoryScan.Status.RUNNING).update(cancel_requested=True)
    if rule.mode == ForbiddenRule.Mode.ENFORCE and rule.active:
        account, _created = TelegramAccount.objects.get_or_create(user=rule.user)
        HistoryScan.objects.create(
            account=account,
            rule=rule,
            rule_revision=rule.revision,
            phase=HistoryScan.Phase.ENFORCE,
        )


def _sync_legacy_mini_app_rule(
    rule: ForbiddenRule, normalized: list[tuple[str, str]]
) -> None:
    legacy = MiniAppRule.objects.filter(protection_rule=rule).first()
    if legacy is None:
        return
    legacy.list_type = MiniAppRule.ListType.DENY
    legacy.match_type = MiniAppRule.MatchType.KEYWORD
    legacy.bot_id = None
    encrypted_patterns = encrypt_many_for_user(
        rule.user, [raw for _value, raw in normalized]
    )
    legacy.encrypted_pattern = encrypted_patterns[0]
    legacy.pattern_fingerprint = fingerprint(
        f"miniapp-unified:{legacy.account_id}:{rule.pk}"
    )
    legacy.active = True
    legacy.save()
    legacy.patterns.all().delete()
    MiniAppRulePattern.objects.bulk_create(
        [
            MiniAppRulePattern(
                rule=legacy,
                encrypted_pattern=encrypted_pattern,
                pattern_fingerprint=fingerprint(
                    f"miniapp-unified-pattern:{legacy.pk}:{value}"
                ),
            )
            for (value, _raw), encrypted_pattern in zip(
                normalized, encrypted_patterns, strict=True
            )
        ]
    )


@transaction.atomic
def _apply_payload(rule: ForbiddenRule, data: dict[str, object]) -> ForbiddenRule:
    normalized = _normalize_phrases(
        [str(item) for item in cast(list[Any], data["phrases"])]
    )
    first_normalized, first_raw = normalized[0]
    next_fingerprint = fingerprint(f"{rule.user_id}:{first_normalized}")
    if (
        ForbiddenRule.objects.filter(
            user_id=rule.user_id,
            phrase_fingerprint=next_fingerprint,
        )
        .exclude(pk=rule.pk)
        .exists()
    ):
        raise DuplicateRuleError(
            "Первая фраза уже используется другим правилом этого пользователя"
        )
    label = str(data.get("label") or "").strip()
    raw_values = ([label] if label else []) + [first_raw] + [
        raw for _normalized_phrase, raw in normalized
    ]
    encrypted_values = iter(encrypt_many_for_user(rule.user, raw_values))
    rule.encrypted_label = next(encrypted_values) if label else ""
    rule.encrypted_phrase = next(encrypted_values)
    rule.phrase_fingerprint = next_fingerprint
    rule.direction = str(data["direction"])
    rule.mode = ForbiddenRule.Mode.ENFORCE
    rule.is_locked = True
    rule.active = True
    rule.revision += 1
    rule.save()
    rule.patterns.all().delete()
    RulePattern.objects.bulk_create(
        [
            RulePattern(
                rule=rule,
                encrypted_phrase=encrypted_phrase,
                phrase_fingerprint=fingerprint(
                    f"{rule.user_id}:{rule.pk}:{normalized_phrase}"
                ),
            )
            for (normalized_phrase, _raw), encrypted_phrase in zip(
                normalized, encrypted_values, strict=True
            )
        ]
    )
    _sync_legacy_mini_app_rule(rule, normalized)
    dialogs = TelegramDialog.objects.filter(
        account__user=rule.user,
        id__in=[
            int(item)
            for item in cast(list[Any], data.get("dialog_ids", []))
        ],
        available=True,
    )
    rule.dialog_scopes.all().delete()
    RuleDialogScope.objects.bulk_create(
        [RuleDialogScope(rule=rule, dialog=dialog) for dialog in dialogs]
    )
    queue_history_scan(rule)
    return rule


@transaction.atomic
def create_rule(
    user: User,
    phrases: str | Iterable[str],
    *,
    label: str = "",
    direction: str = ForbiddenRule.Direction.BOTH,
    mode: str = ForbiddenRule.Mode.ENFORCE,
    is_locked: bool = True,
    dialog_ids: Iterable[int] = (),
    queue_history: bool = False,
) -> ForbiddenRule:
    normalized = _normalize_phrases(phrases)
    first_normalized, first_raw = normalized[0]
    clean_label = label.strip()
    raw_values = ([clean_label] if clean_label else []) + [first_raw] + [
        raw for _value, raw in normalized
    ]
    encrypted_values = iter(encrypt_many_for_user(user, raw_values))
    encrypted_label = next(encrypted_values) if clean_label else ""
    encrypted_first = next(encrypted_values)
    try:
        rule = ForbiddenRule.objects.create(
            user=user,
            encrypted_phrase=encrypted_first,
            phrase_fingerprint=fingerprint(f"{user.pk}:{first_normalized}"),
            encrypted_label=encrypted_label,
            direction=direction,
            mode=ForbiddenRule.Mode.ENFORCE,
            is_locked=True,
            active=True,
        )
    except IntegrityError as exc:
        raise DuplicateRuleError("Rule already exists") from exc
    RulePattern.objects.bulk_create(
        [
            RulePattern(
                rule=rule,
                encrypted_phrase=encrypted_phrase,
                phrase_fingerprint=fingerprint(f"{user.pk}:{rule.pk}:{value}"),
            )
            for (value, _raw), encrypted_phrase in zip(
                normalized, encrypted_values, strict=True
            )
        ]
    )
    dialogs = TelegramDialog.objects.filter(
        account__user=user, id__in=list(dialog_ids), available=True
    )
    RuleDialogScope.objects.bulk_create(
        [RuleDialogScope(rule=rule, dialog=dialog) for dialog in dialogs]
    )
    if queue_history:
        queue_history_scan(rule)
    return rule


@transaction.atomic
def update_rule(
    rule: ForbiddenRule,
    *,
    label: str,
    phrases: str | Iterable[str],
    direction: str,
    mode: str,
    is_locked: bool,
    dialog_ids: Iterable[int],
) -> tuple[ForbiddenRule, RuleChangeRequest | None]:
    normalized = _normalize_phrases(phrases)
    raw_phrases = [raw for _value, raw in normalized]
    dialog_set = {int(item) for item in dialog_ids}
    if rule.change_requests.filter(status=RuleChangeRequest.Status.PENDING).exists():
        raise PendingRuleChangeError("A protected change is already pending")
    weakening, summary = _is_weakening(
        rule,
        {value for value, _raw in normalized},
        direction,
        ForbiddenRule.Mode.ENFORCE,
        True,
        dialog_set,
    )
    serialized = _serialized_payload(
        label=label,
        phrases=raw_phrases,
        direction=direction,
        mode=ForbiddenRule.Mode.ENFORCE,
        is_locked=True,
        dialog_ids=dialog_set,
    )
    if rule.is_locked and weakening:
        change = RuleChangeRequest.objects.create(
            user=rule.user,
            rule=rule,
            encrypted_payload=encrypt_for_user(rule.user, serialized),
            change_summary=summary,
        )
        return rule, change
    return _apply_payload(rule, json.loads(serialized)), None


@transaction.atomic
def resolve_rule_change(
    change: RuleChangeRequest, operator: User, approve: bool
) -> None:
    if change.status != RuleChangeRequest.Status.PENDING:
        raise ValueError("Rule change is already resolved")
    if approve:
        data = json.loads(decrypt_for_user(change.user, change.encrypted_payload))
        _apply_payload(change.rule, data)
        change.status = RuleChangeRequest.Status.APPROVED
    else:
        change.status = RuleChangeRequest.Status.REJECTED
    change.resolved_at = timezone.now()
    change.resolved_by = operator
    change.save(update_fields=["status", "resolved_at", "resolved_by"])


def decrypted_rules(user: User, direction: str | None = None) -> list[RuleSpec]:
    queryset = (
        user.forbidden_rules.filter(active=True)
        .prefetch_related("patterns", "dialog_scopes__dialog")
        .order_by("id")
    )
    if direction:
        queryset = queryset.filter(
            direction__in=[direction, ForbiddenRule.Direction.BOTH]
        )
    rules = list(queryset)
    encrypted_by_rule = [
        [item.encrypted_phrase for item in rule.patterns.all()]
        or [rule.encrypted_phrase]
        for rule in rules
    ]
    decrypted_values = iter(
        decrypt_many_for_user(
            user,
            [value for values in encrypted_by_rule for value in values],
        )
    )
    specs: list[RuleSpec] = []
    for rule, encrypted_values in zip(rules, encrypted_by_rule, strict=True):
        phrases = tuple(
            normalize_text(next(decrypted_values)) for _value in encrypted_values
        )
        scopes = frozenset(
            item.dialog.peer_fingerprint for item in rule.dialog_scopes.all()
        )
        specs.append(
            RuleSpec(
                id=rule.pk,
                phrases=phrases,
                mode=rule.mode,
                revision=rule.revision,
                dialog_fingerprints=scopes or None,
            )
        )
    return specs


def rule_form_initial(rule: ForbiddenRule) -> dict[str, object]:
    patterns = list(rule.patterns.all())
    encrypted_phrases = [item.encrypted_phrase for item in patterns] or [
        rule.encrypted_phrase
    ]
    encrypted_values = ([rule.encrypted_label] if rule.encrypted_label else []) + [
        *encrypted_phrases
    ]
    decrypted_values = iter(decrypt_many_for_user(rule.user, encrypted_values))
    label = next(decrypted_values) if rule.encrypted_label else ""
    phrases = list(decrypted_values)
    return {
        "label": label,
        "phrases": "\n".join(phrases),
        "direction": rule.direction,
        "mode": rule.mode,
        "is_locked": rule.is_locked,
        "dialogs": list(rule.dialog_scopes.values_list("dialog_id", flat=True)),
    }


def rule_label(rule: ForbiddenRule) -> str:
    return (
        decrypt_for_user(rule.user, rule.encrypted_label)
        if rule.encrypted_label
        else f"Правило #{rule.pk}"
    )


def rule_labels(rules: Iterable[ForbiddenRule], user: User) -> dict[int, str]:
    rule_list = list(rules)
    encrypted_labels = [
        rule.encrypted_label for rule in rule_list if rule.encrypted_label
    ]
    decrypted_labels = iter(decrypt_many_for_user(user, encrypted_labels))
    return {
        rule.pk: next(decrypted_labels)
        if rule.encrypted_label
        else f"Правило #{rule.pk}"
        for rule in rule_list
    }
