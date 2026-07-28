import base64
import hashlib

import pytest
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

from core.models import MiniAppRule, TelegramAccount
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
