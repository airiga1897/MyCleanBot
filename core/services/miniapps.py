from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from core.models import MiniAppRule, TelegramAccount
from core.services.crypto import decrypt_for_user, encrypt_for_user, fingerprint

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
    id: int
    list_type: str
    match_type: str
    value: str
    bot_id: int | None


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
    normalized, bot_id = normalize_rule_value(match_type, value)
    digest = fingerprint(f"miniapp:{account.pk}:{list_type}:{match_type}:{normalized}")
    encrypted = ""
    if match_type != MiniAppRule.MatchType.BOT_ID:
        encrypted = encrypt_for_user(account.user, normalized)
    try:
        return MiniAppRule.objects.create(
            account=account,
            list_type=list_type,
            match_type=match_type,
            bot_id=bot_id,
            encrypted_pattern=encrypted,
            pattern_fingerprint=digest,
        )
    except IntegrityError as exc:
        raise DuplicateMiniAppRuleError from exc


def load_mini_app_rules(account: TelegramAccount) -> list[MiniAppRuleSpec]:
    rules: list[MiniAppRuleSpec] = []
    for rule in account.mini_app_rules.filter(active=True):
        value = (
            str(rule.bot_id)
            if rule.match_type == MiniAppRule.MatchType.BOT_ID
            else decrypt_for_user(account.user, rule.encrypted_pattern)
        )
        rules.append(
            MiniAppRuleSpec(
                id=rule.pk,
                list_type=rule.list_type,
                match_type=rule.match_type,
                value=value,
                bot_id=rule.bot_id,
            )
        )
    return rules


def display_mini_app_rules(account: TelegramAccount) -> list[tuple[MiniAppRule, str]]:
    displayed: list[tuple[MiniAppRule, str]] = []
    for rule in account.mini_app_rules.all():
        value = (
            str(rule.bot_id)
            if rule.match_type == MiniAppRule.MatchType.BOT_ID
            else decrypt_for_user(account.user, rule.encrypted_pattern)
        )
        displayed.append((rule, value))
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
    if rule.match_type == MiniAppRule.MatchType.USERNAME:
        return bool(target.username) and target.username.casefold() == rule.value
    if rule.match_type == MiniAppRule.MatchType.TITLE:
        return (
            (bool(target.title) and target.title.casefold() == rule.value)
            or rule.value in text[:MAX_MATCH_TEXT].casefold()
        )
    haystack = " ".join(part for part in (target.title, text[:MAX_MATCH_TEXT]) if part)
    if rule.match_type == MiniAppRule.MatchType.KEYWORD:
        return rule.value in haystack.casefold()
    if rule.match_type == MiniAppRule.MatchType.REGEX:
        return re.search(rule.value, haystack, re.IGNORECASE) is not None
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
