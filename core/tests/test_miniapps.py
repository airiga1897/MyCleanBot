import base64
import hashlib

import pytest
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils import timezone

from core.models import (
    ForbiddenRule,
    MiniAppAuditEvent,
    MiniAppRule,
    TelegramAccount,
    TelegramDialog,
)
from core.services.crypto import decrypt_for_user
from core.services.miniapps import (
    DuplicateMiniAppRuleError,
    MiniAppRuleSpec,
    MiniAppTarget,
    create_mini_app_rule,
    decide_mini_app_rule,
    display_mini_app_rules,
    extract_bot_usernames,
    load_mini_app_rules,
    normalize_rule_value,
)
from core.services.rules import create_rule, peer_fingerprint, update_rule

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def encryption_key(settings: object) -> None:
    settings.MASTER_ENCRYPTION_KEY = base64.urlsafe_b64encode(
        hashlib.sha256(b"mini-app-tests").digest()
    ).decode()


def test_rule_values_are_normalized_encrypted_and_unique() -> None:
    user = User.objects.create_user("mini-owner", password="long-password-123")
    account = TelegramAccount.objects.create(user=user)
    username_rule = create_mini_app_rule(
        account,
        MiniAppRule.ListType.DENY,
        MiniAppRule.MatchType.USERNAME,
        "@Example_Bot",
    )
    bot_id_rule = create_mini_app_rule(
        account,
        MiniAppRule.ListType.ALLOW,
        MiniAppRule.MatchType.BOT_ID,
        "123456",
    )

    assert "example_bot" not in username_rule.encrypted_pattern
    assert bot_id_rule.bot_id == 123456
    assert [item.value for item in load_mini_app_rules(account)] == [
        "123456",
        "example_bot",
    ]
    assert [value for _rule, value in display_mini_app_rules(account)] == [
        "123456",
        "example_bot",
    ]
    with pytest.raises(DuplicateMiniAppRuleError):
        create_mini_app_rule(
            account,
            MiniAppRule.ListType.DENY,
            MiniAppRule.MatchType.USERNAME,
            "example_bot",
        )


def test_keyword_rule_supports_multiple_encrypted_or_patterns() -> None:
    user = User.objects.create_user("mini-or-owner", password="long-password-123")
    account = TelegramAccount.objects.create(user=user)
    rule = create_mini_app_rule(
        account,
        MiniAppRule.ListType.DENY,
        MiniAppRule.MatchType.KEYWORD,
        "Lucid_Dreams\nDream App\nlucid_dreams",
    )

    spec = load_mini_app_rules(account)[0]
    assert spec.values == ("lucid_dreams", "dream app")
    assert rule.patterns.count() == 2
    assert "lucid_dreams" not in rule.encrypted_pattern
    assert all(
        "dream" not in pattern.encrypted_pattern.casefold()
        for pattern in rule.patterns.all()
    )
    assert decide_mini_app_rule(
        [spec], MiniAppTarget(title="My Dream App")
    ).denied
    assert display_mini_app_rules(account)[0][1] == "lucid_dreams · dream app"


def test_unified_rule_is_loaded_for_mini_apps_with_direction_and_scope() -> None:
    user = User.objects.create_user("unified-owner", password="long-password-123")
    account = TelegramAccount.objects.create(user=user)
    dialog = TelegramDialog.objects.create(
        account=account,
        peer_fingerprint=peer_fingerprint(account.pk, 123),
        encrypted_label="unused",
        kind=TelegramDialog.Kind.PRIVATE,
        last_seen_at=timezone.now(),
    )
    rule = create_rule(
        user,
        ["lucid_dreams", "Dream App"],
        direction=ForbiddenRule.Direction.INCOMING,
        dialog_ids=[dialog.pk],
    )

    spec = next(item for item in load_mini_app_rules(account) if item.protection_rule_id)

    assert spec.id is None
    assert spec.protection_rule_id == rule.pk
    assert spec.values == ("lucid_dreams", "dream app")
    assert spec.direction == ForbiddenRule.Direction.INCOMING
    assert spec.dialog_fingerprints == frozenset({dialog.peer_fingerprint})
    assert decide_mini_app_rule(
        [spec], MiniAppTarget(title="Dream App")
    ).denied


def test_legacy_rule_linked_to_unified_rule_is_not_loaded_twice() -> None:
    user = User.objects.create_user("linked-owner", password="long-password-123")
    account = TelegramAccount.objects.create(user=user)
    protection_rule = create_rule(user, "lucid_dreams")
    legacy = create_mini_app_rule(
        account,
        MiniAppRule.ListType.DENY,
        MiniAppRule.MatchType.KEYWORD,
        "lucid_dreams",
    )
    legacy.protection_rule = protection_rule
    legacy.save(update_fields=["protection_rule"])

    specs = load_mini_app_rules(account)

    assert len(specs) == 1
    assert specs[0].protection_rule_id == protection_rule.pk
    assert specs[0].id is None

    update_rule(
        protection_rule,
        label="",
        phrases=["lucid_dreams", "dream app"],
        direction=ForbiddenRule.Direction.BOTH,
        mode=ForbiddenRule.Mode.ENFORCE,
        is_locked=True,
        dialog_ids=[],
    )
    legacy.refresh_from_db()
    assert [
        decrypt_for_user(user, pattern.encrypted_pattern)
        for pattern in legacy.patterns.all()
    ] == ["lucid_dreams", "dream app"]

    protection_rule.delete()
    legacy.refresh_from_db()
    assert not legacy.active
    assert legacy.protection_rule_id is None
    assert load_mini_app_rules(account) == []


def test_unification_migration_preserves_legacy_patterns_and_audit() -> None:
    import importlib

    from django.apps import apps

    user = User.objects.create_user("migration-owner", password="long-password-123")
    account = TelegramAccount.objects.create(user=user)
    legacy = create_mini_app_rule(
        account,
        MiniAppRule.ListType.DENY,
        MiniAppRule.MatchType.KEYWORD,
        "lucid_dreams\nDream App",
    )
    legacy_allow = create_mini_app_rule(
        account,
        MiniAppRule.ListType.ALLOW,
        MiniAppRule.MatchType.USERNAME,
        "trusted_bot",
    )
    event = MiniAppAuditEvent.objects.create(
        account=account,
        rule=legacy,
        event_type=MiniAppAuditEvent.EventType.MENU_DETECTED,
        result=MiniAppAuditEvent.Result.SUCCEEDED,
    )
    migration = importlib.import_module(
        "core.migrations.0007_unified_protection_rules"
    )

    migration.unify_rules(apps, None)

    legacy.refresh_from_db()
    legacy_allow.refresh_from_db()
    event.refresh_from_db()
    assert legacy.protection_rule_id is not None
    assert event.protection_rule_id == legacy.protection_rule_id
    assert legacy_allow.protection_rule_id is None
    assert legacy_allow.active
    protection_rule = ForbiddenRule.objects.get(pk=legacy.protection_rule_id)
    assert protection_rule.active and protection_rule.is_locked
    assert protection_rule.mode == ForbiddenRule.Mode.ENFORCE
    assert [
        decrypt_for_user(user, pattern.encrypted_phrase)
        for pattern in protection_rule.patterns.all()
    ] == ["lucid_dreams", "dream app"]


@pytest.mark.parametrize(
    ("match_type", "value"),
    [
        (MiniAppRule.MatchType.BOT_ID, "0"),
        (MiniAppRule.MatchType.USERNAME, "bad name"),
        (MiniAppRule.MatchType.REGEX, "(a+)+"),
        (MiniAppRule.MatchType.REGEX, r"(foo)\1"),
        (MiniAppRule.MatchType.KEYWORD, ""),
    ],
)
def test_unsafe_or_invalid_rule_values_are_rejected(match_type: str, value: str) -> None:
    with pytest.raises(ValidationError):
        normalize_rule_value(match_type, value)


def test_allow_rule_has_priority_over_deny_rule() -> None:
    rules = [
        MiniAppRuleSpec(
            id=1,
            list_type=MiniAppRule.ListType.DENY,
            match_type=MiniAppRule.MatchType.KEYWORD,
            value="game",
            bot_id=None,
        ),
        MiniAppRuleSpec(
            id=2,
            list_type=MiniAppRule.ListType.ALLOW,
            match_type=MiniAppRule.MatchType.BOT_ID,
            value="42",
            bot_id=42,
        ),
    ]
    allowed = decide_mini_app_rule(
        rules, MiniAppTarget(bot_id=42, username="safe_bot", title="Game")
    )
    denied = decide_mini_app_rule(
        rules, MiniAppTarget(bot_id=43, username="other_bot", title="Game")
    )
    assert not allowed.denied
    assert allowed.allowed_by and allowed.allowed_by.id == 2
    assert denied.denied
    assert denied.rule and denied.rule.id == 1


def test_outgoing_extracts_mentions_commands_and_mini_app_links() -> None:
    text = (
        "@FirstBot /launch@SecondBot "
        "https://t.me/ThirdBot/appname https://t.me/FourthBot?startapp= "
        "https://t.me/ordinary"
    )
    assert extract_bot_usernames(text) == {
        "firstbot",
        "secondbot",
        "thirdbot",
        "fourthbot",
    }


def test_title_keyword_and_regex_match_outgoing_text_without_storing_it() -> None:
    rules = [
        MiniAppRuleSpec(
            id=1,
            list_type=MiniAppRule.ListType.DENY,
            match_type=MiniAppRule.MatchType.TITLE,
            value="bad app",
            bot_id=None,
        ),
        MiniAppRuleSpec(
            id=2,
            list_type=MiniAppRule.ListType.DENY,
            match_type=MiniAppRule.MatchType.REGEX,
            value=r"startapp=\w+",
            bot_id=None,
        ),
    ]
    assert decide_mini_app_rule(rules, MiniAppTarget(), "Try Bad App").rule.id == 1
    assert (
        decide_mini_app_rule(
            rules, MiniAppTarget(), "https://t.me/examplebot?startapp=promo"
        ).rule.id
        == 2
    )
