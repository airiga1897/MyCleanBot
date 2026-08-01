from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q

from core.models import ForbiddenRule, MiniAppRule, MiniAppRulePattern, TelegramAccount
from core.services.crypto import decrypt_for_user, encrypt_for_user, fingerprint
from core.services.matcher import normalize_text

MAX_MATCH_TEXT = 2000
MAX_PATTERN_LENGTH = 200
_USERNAME_RE = re.compile(r"(?<![\w@])@([A-Za-z][A-Za-z0-9_]{3,31})\b")
_COMMAND_RE = re.compile(r"(?<!\w)/[A-Za-z0-9_]{1,64}@([A-Za-z][A-Za-z0-9_]{3,31})\b")
_URL_RE = re.compile(r"https?://(?:www\.)?(?:t\.me|telegram\.me)/[^\s<>()]+", re.IGNORECASE)
_UNSAFE_REGEX_PARTS = (
    re.compile(r"\(\?"),
    re.compile(r"\\[1-9]"),
    re.compile(r"\)(?:[*+]|\{\d*,?\d*\})"),
    re.compile(r"(?:\.\*|\.\+).*(?:[*+]|\{\d*,?\d*\})"),
)


class DuplicateMiniAppRuleError(ValueError):
    pass


@dataclass(frozen=True)
class MiniAppRuleSpec:
    id: int | None
    list_type: str
    match_type: str
    value: str
    bot_id: int | None
    values: tuple[str, ...] = ()
    protection_rule_id: int | None = None
    direction: str = ForbiddenRule.Direction.BOTH
    dialog_fingerprints: frozenset[str] | None = None


@dataclass(frozen=True)
class MiniAppTarget:
    bot_id: int | None = None
    username: str = ""
    title: str = ""


@dataclass(frozen=True)
class MiniAppRuleDecision:
    denied: bool
    rule: MiniAppRuleSpec | None
    allowed_by: MiniAppRuleSpec | None = None


def normalize_username(value: str) -> str:
    username = value.strip().removeprefix("@").casefold()
    if not re.fullmatch(r"[a-z][a-z0-9_]{3,31}", username):
        raise ValidationError("Введите корректный Telegram username.")
    return username


def validate_safe_regex(value: str) -> str:
    pattern = value.strip()
    if not pattern or len(pattern) > MAX_PATTERN_LENGTH:
        raise ValidationError(
            f"Регулярное выражение должно быть от 1 до {MAX_PATTERN_LENGTH} символов."
        )
    if any(part.search(pattern) for part in _UNSAFE_REGEX_PARTS):
        raise ValidationError(
            "Lookaround, backreference и квантифицированные группы не поддерживаются."
        )
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValidationError("Некорректное регулярное выражение.") from exc
    return pattern


def normalize_rule_value(match_type: str, value: str) -> tuple[str, int | None]:
    cleaned = value.strip()
    if match_type == MiniAppRule.MatchType.BOT_ID:
        try:
            bot_id = int(cleaned)
        except ValueError as exc:
            raise ValidationError("Bot ID должен быть положительным целым числом.") from exc
        if bot_id <= 0:
            raise ValidationError("Bot ID должен быть положительным целым числом.")
        return str(bot_id), bot_id
    if match_type == MiniAppRule.MatchType.USERNAME:
        return normalize_username(cleaned), None
    if match_type == MiniAppRule.MatchType.REGEX:
        return validate_safe_regex(cleaned), None
    if not cleaned or len(cleaned) > MAX_PATTERN_LENGTH:
        raise ValidationError(f"Значение должно быть от 1 до {MAX_PATTERN_LENGTH} символов.")
    return cleaned.casefold(), None


@transaction.atomic
def create_mini_app_rule(
    account: TelegramAccount, list_type: str, match_type: str, value: str
) -> MiniAppRule:
    raw_values = (
        [line for line in value.splitlines() if line.strip()]
        if match_type == MiniAppRule.MatchType.KEYWORD
        else [value]
    )
    normalized_values: list[str] = []
    bot_id: int | None = None
    for raw_value in raw_values:
        normalized, candidate_bot_id = normalize_rule_value(match_type, raw_value)
        if normalized not in normalized_values:
            normalized_values.append(normalized)
        if candidate_bot_id is not None:
            bot_id = candidate_bot_id
    if not normalized_values:
        raise ValidationError("Добавьте хотя бы одну фразу.")
    identity = "\n".join(sorted(normalized_values))
    digest = fingerprint(f"miniapp:{account.pk}:{list_type}:{match_type}:{identity}")
    encrypted = ""
    if match_type != MiniAppRule.MatchType.BOT_ID:
        encrypted = encrypt_for_user(account.user, normalized_values[0])
    try:
        rule = MiniAppRule.objects.create(
            account=account,
            list_type=list_type,
            match_type=match_type,
            bot_id=bot_id,
            encrypted_pattern=encrypted,
            pattern_fingerprint=digest,
        )
        if match_type != MiniAppRule.MatchType.BOT_ID:
            MiniAppRulePattern.objects.bulk_create(
                [
                    MiniAppRulePattern(
                        rule=rule,
                        encrypted_pattern=encrypt_for_user(account.user, item),
                        pattern_fingerprint=fingerprint(
                            f"miniapp-pattern:{account.pk}:{rule.pk}:{item}"
                        ),
                    )
                    for item in normalized_values
                ]
            )
        return rule
    except IntegrityError as exc:
        raise DuplicateMiniAppRuleError from exc


def load_mini_app_rules(account: TelegramAccount) -> list[MiniAppRuleSpec]:
    rules: list[MiniAppRuleSpec] = []
    protection_rules = (
        account.user.forbidden_rules.filter(active=True)
        .prefetch_related("patterns", "dialog_scopes__dialog")
        .order_by("id")
    )
    for protection_rule in protection_rules:
        protection_values = tuple(
            normalize_text(decrypt_for_user(account.user, pattern.encrypted_phrase))
            for pattern in protection_rule.patterns.all()
        ) or (
            normalize_text(
                decrypt_for_user(account.user, protection_rule.encrypted_phrase)
            ),
        )
        scopes = frozenset(
            scope.dialog.peer_fingerprint
            for scope in protection_rule.dialog_scopes.all()
        )
        rules.append(
            MiniAppRuleSpec(
                id=None,
                protection_rule_id=protection_rule.pk,
                list_type=MiniAppRule.ListType.DENY,
                match_type=MiniAppRule.MatchType.KEYWORD,
                value=protection_values[0],
                values=protection_values,
                bot_id=None,
                direction=protection_rule.direction,
                dialog_fingerprints=scopes or None,
            )
        )
    queryset = account.mini_app_rules.filter(active=True).filter(
        Q(protection_rule__isnull=True) | Q(match_type=MiniAppRule.MatchType.BOT_ID)
    ).prefetch_related("patterns")
    for legacy_rule in queryset:
        values: tuple[str, ...]
        if legacy_rule.match_type == MiniAppRule.MatchType.BOT_ID:
            values = (str(legacy_rule.bot_id),)
        else:
            values = tuple(
                decrypt_for_user(account.user, pattern.encrypted_pattern)
                for pattern in legacy_rule.patterns.all()
            ) or (decrypt_for_user(account.user, legacy_rule.encrypted_pattern),)
        rules.append(
            MiniAppRuleSpec(
                id=legacy_rule.pk,
                list_type=legacy_rule.list_type,
                match_type=legacy_rule.match_type,
                value=values[0],
                bot_id=legacy_rule.bot_id,
                values=values,
                protection_rule_id=legacy_rule.protection_rule_id,
            )
        )
    return rules


def display_mini_app_rules(account: TelegramAccount) -> list[tuple[MiniAppRule, str]]:
    displayed: list[tuple[MiniAppRule, str]] = []
    for rule in account.mini_app_rules.prefetch_related("patterns").all():
        if rule.match_type == MiniAppRule.MatchType.BOT_ID:
            values = [str(rule.bot_id)]
        else:
            values = [
                decrypt_for_user(account.user, pattern.encrypted_pattern)
                for pattern in rule.patterns.all()
            ] or [decrypt_for_user(account.user, rule.encrypted_pattern)]
        displayed.append((rule, " · ".join(values)))
    return displayed


def extract_bot_usernames(text: str) -> set[str]:
    limited = text[:MAX_MATCH_TEXT]
    usernames = {match.group(1).casefold() for match in _USERNAME_RE.finditer(limited)}
    usernames.update(match.group(1).casefold() for match in _COMMAND_RE.finditer(limited))
    for match in _URL_RE.finditer(limited):
        parsed = urlparse(match.group(0))
        parts = [part for part in parsed.path.split("/") if part]
        if not parts:
            continue
        query = parse_qs(parsed.query, keep_blank_values=True)
        if "startapp" in query or len(parts) >= 2:
            try:
                usernames.add(normalize_username(parts[0]))
            except ValidationError:
                continue
    return usernames


def _rule_matches(rule: MiniAppRuleSpec, target: MiniAppTarget, text: str) -> bool:
    if rule.match_type == MiniAppRule.MatchType.BOT_ID:
        return target.bot_id is not None and target.bot_id == rule.bot_id
    values = rule.values or (rule.value,)
    if rule.match_type == MiniAppRule.MatchType.USERNAME:
        return bool(target.username) and any(
            target.username.casefold() == value for value in values
        )
    if rule.match_type == MiniAppRule.MatchType.TITLE:
        return any(
            (bool(target.title) and target.title.casefold() == value)
            or value in text[:MAX_MATCH_TEXT].casefold()
            for value in values
        )
    haystack = " ".join(part for part in (target.title, text[:MAX_MATCH_TEXT]) if part)
    if rule.match_type == MiniAppRule.MatchType.KEYWORD:
        return any(value in haystack.casefold() for value in values)
    if rule.match_type == MiniAppRule.MatchType.REGEX:
        return any(re.search(value, haystack, re.IGNORECASE) is not None for value in values)
    return False


def decide_mini_app_rule(
    rules: list[MiniAppRuleSpec], target: MiniAppTarget, text: str = ""
) -> MiniAppRuleDecision:
    matching_allow = next(
        (
            rule
            for rule in rules
            if rule.list_type == MiniAppRule.ListType.ALLOW
            and _rule_matches(rule, target, text)
        ),
        None,
    )
    if matching_allow:
        return MiniAppRuleDecision(denied=False, rule=None, allowed_by=matching_allow)
    matching_deny = next(
        (
            rule
            for rule in rules
            if rule.list_type == MiniAppRule.ListType.DENY
            and _rule_matches(rule, target, text)
        ),
        None,
    )
    return MiniAppRuleDecision(denied=matching_deny is not None, rule=matching_deny)
