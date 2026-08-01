from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace
from typing import Any

import pytest
from django.contrib.auth.models import User
from telethon.tl import functions

from core.models import (
    MiniAppAuditEvent,
    MiniAppPolicy,
    MiniAppRule,
    OperatorNotification,
    TelegramAccount,
)
from core.services import telegram_worker as worker
from core.services.miniapps import create_mini_app_rule

pytestmark = [pytest.mark.django_db(transaction=True), pytest.mark.asyncio]


@pytest.fixture(autouse=True)
def mini_app_settings(settings: Any) -> None:
    settings.MASTER_ENCRYPTION_KEY = base64.urlsafe_b64encode(
        hashlib.sha256(b"mini-worker-tests").digest()
    ).decode()
    settings.MINI_APP_RECONCILE_SECONDS = 300


class MockTelegramApi:
    def __init__(self) -> None:
        self.requests: list[Any] = []
        self.sent_messages: list[str] = []
        self.bot = SimpleNamespace(id=4242, username="bad_bot", bot=True)
        self.deleted_dialogs: list[Any] = []

    async def __call__(self, request: Any) -> Any:
        self.requests.append(request)
        if isinstance(request, functions.messages.GetAttachMenuBotsRequest):
            return SimpleNamespace(
                bots=[SimpleNamespace(bot_id=4242, short_name="Bad Game", inactive=False)],
                users=[self.bot],
            )
        return True

    async def get_entity(self, username: str) -> Any:
        assert username == "bad_bot"
        return self.bot

    async def send_message(self, peer: str, text: str) -> Any:
        assert peer == "me"
        self.sent_messages.append(text)
        return SimpleNamespace(id=99)

    async def delete_dialog(self, entity: Any, revoke: bool = False) -> None:
        assert not revoke
        self.deleted_dialogs.append(entity)

    async def iter_dialogs(self) -> Any:
        if False:
            yield None


class FailingTelegramApi(MockTelegramApi):
    async def __call__(self, request: Any) -> Any:
        if isinstance(request, functions.messages.GetAttachMenuBotsRequest):
            return await super().__call__(request)
        self.requests.append(request)
        raise RuntimeError("mock-api-failure")

    async def send_message(self, peer: str, text: str) -> Any:
        raise ConnectionError("mock-notification-failure")

    async def delete_dialog(self, entity: Any, revoke: bool = False) -> None:
        raise RuntimeError("mock-delete-dialog-failure")


class OutgoingEvent:
    def __init__(self, text: str, chat: Any | None = None, *, outgoing: bool = True) -> None:
        self.raw_text = text
        self.chat_id = 100
        self.is_private = True
        self.is_channel = False
        self.message = SimpleNamespace(id=7, entities=[], media=None)
        self.deleted = False
        self.chat = chat
        self.out = outgoing

    async def delete(self, revoke: bool) -> None:
        assert revoke == self.out
        self.deleted = True

    async def get_chat(self) -> Any:
        return self.chat


async def _account_with_rule(mode: str) -> tuple[TelegramAccount, MiniAppPolicy]:
    user = await User.objects.acreate_user("worker-mini-user", password="long-password-123")
    account = await TelegramAccount.objects.acreate(user=user)
    policy = await MiniAppPolicy.objects.acreate(
        account=account,
        mode=mode,
        block_bot=True,
        notify_user=False,
    )
    await worker.sync_to_async(create_mini_app_rule)(
        account,
        MiniAppRule.ListType.DENY,
        MiniAppRule.MatchType.USERNAME,
        "bad_bot",
    )
    return account, policy


async def test_enforce_reconcile_disables_menu_and_blocks_bot() -> None:
    account, _policy = await _account_with_rule(MiniAppPolicy.Mode.ENFORCE)
    api = MockTelegramApi()
    runner = worker.AccountRunner(
        {"id": account.pk, "user_id": account.user_id, "encrypted_session": "unused"}
    )
    runner.client = api

    await runner._reconcile_mini_apps()

    assert any(
        isinstance(request, functions.messages.ToggleBotInAttachMenuRequest)
        for request in api.requests
    )
    assert any(isinstance(request, functions.contacts.BlockRequest) for request in api.requests)
    assert api.deleted_dialogs == [api.bot]
    event_types = {
        event_type
        async for event_type in MiniAppAuditEvent.objects.filter(account=account).values_list(
            "event_type", flat=True
        )
    }
    assert MiniAppAuditEvent.EventType.MENU_DISABLED in event_types
    assert MiniAppAuditEvent.EventType.BOT_BLOCKED in event_types


async def test_enforce_deletes_outgoing_after_update_and_audits_no_text() -> None:
    account, _policy = await _account_with_rule(MiniAppPolicy.Mode.ENFORCE)
    api = MockTelegramApi()
    runner = worker.AccountRunner(
        {"id": account.pk, "user_id": account.user_id, "encrypted_session": "unused"}
    )
    runner.client = api
    event = OutgoingEvent("open @bad_bot")

    assert await runner._handle_mini_app_message(event, event.raw_text)
    assert event.deleted
    audit = await MiniAppAuditEvent.objects.filter(
        account=account,
        event_type=MiniAppAuditEvent.EventType.MESSAGE_DELETED,
    ).aget()
    assert audit.result == MiniAppAuditEvent.Result.SUCCEEDED
    assert audit.bot_username == "bad_bot"
    assert not hasattr(audit, "message_text")


async def test_incoming_link_from_another_bot_is_deleted_and_source_bot_removed() -> None:
    account, _policy = await _account_with_rule(MiniAppPolicy.Mode.ENFORCE)
    api = MockTelegramApi()
    runner = worker.AccountRunner(
        {"id": account.pk, "user_id": account.user_id, "encrypted_session": "unused"}
    )
    runner.client = api
    source_bot = SimpleNamespace(id=5151, username="linker_bot", bot=True)
    event = OutgoingEvent(
        "Open https://t.me/bad_bot?startapp=lucid", source_bot, outgoing=False
    )

    assert await runner._handle_mini_app_message(
        event, event.raw_text, is_outgoing=False
    )
    assert event.deleted
    assert api.deleted_dialogs == [source_bot, api.bot]
    assert any(isinstance(request, functions.contacts.BlockRequest) for request in api.requests)
    event_types = {
        item async for item in MiniAppAuditEvent.objects.filter(account=account).values_list(
            "event_type", flat=True
        )
    }
    assert MiniAppAuditEvent.EventType.INCOMING_DETECTED in event_types


async def test_profile_description_is_reconciled_and_bot_history_is_deleted() -> None:
    user = await User.objects.acreate_user(
        "profile-mini-user", password="long-password-123"
    )
    account = await TelegramAccount.objects.acreate(user=user)
    await worker.sync_to_async(create_mini_app_rule)(
        account,
        MiniAppRule.ListType.DENY,
        MiniAppRule.MatchType.KEYWORD,
        "lucid_dreams",
    )
    profile_bot = SimpleNamespace(id=9090, username="ordinary_bot", bot=True)

    class ProfileApi(MockTelegramApi):
        async def __call__(self, request: Any) -> Any:
            self.requests.append(request)
            if isinstance(request, functions.messages.GetAttachMenuBotsRequest):
                return SimpleNamespace(bots=[], users=[])
            if isinstance(request, functions.users.GetFullUserRequest):
                return SimpleNamespace(
                    full_user=SimpleNamespace(about="Launch lucid_dreams here")
                )
            return True

        async def iter_dialogs(self) -> Any:
            yield SimpleNamespace(
                id=profile_bot.id,
                entity=profile_bot,
                name="Ordinary bot",
                is_group=False,
                is_channel=False,
            )

    api = ProfileApi()
    runner = worker.AccountRunner(
        {"id": account.pk, "user_id": account.user_id, "encrypted_session": "unused"}
    )
    runner.client = api

    await runner._reconcile_mini_apps()

    assert api.deleted_dialogs == [profile_bot]
    assert any(isinstance(request, functions.contacts.BlockRequest) for request in api.requests)
    assert await MiniAppAuditEvent.objects.filter(
        account=account,
        event_type=MiniAppAuditEvent.EventType.PROFILE_DETECTED,
    ).aexists()


async def test_bare_command_in_private_bot_chat_is_matched() -> None:
    account, _policy = await _account_with_rule(MiniAppPolicy.Mode.ENFORCE)
    api = MockTelegramApi()
    runner = worker.AccountRunner(
        {"id": account.pk, "user_id": account.user_id, "encrypted_session": "unused"}
    )
    runner.client = api
    event = OutgoingEvent("/launch", chat=SimpleNamespace(id=4242, username="bad_bot", bot=True))

    assert await runner._handle_mini_app_message(event, event.raw_text)
    assert event.deleted


async def test_enforcement_action_failures_are_minimally_audited() -> None:
    account, _policy = await _account_with_rule(MiniAppPolicy.Mode.ENFORCE)
    api = FailingTelegramApi()
    runner = worker.AccountRunner(
        {"id": account.pk, "user_id": account.user_id, "encrypted_session": "unused"}
    )
    runner.client = api

    await runner._reconcile_mini_apps()

    failures = [
        event
        async for event in MiniAppAuditEvent.objects.filter(
            account=account,
            result=MiniAppAuditEvent.Result.FAILED,
        )
    ]
    assert {event.event_type for event in failures} == {
        MiniAppAuditEvent.EventType.MENU_DISABLED,
        MiniAppAuditEvent.EventType.BOT_BLOCKED,
        MiniAppAuditEvent.EventType.DIALOG_DELETED,
    }
    assert all(event.error_code == "RuntimeError" for event in failures)


async def test_operator_notification_deduplicates_and_reconcile_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    account, _policy = await _account_with_rule(MiniAppPolicy.Mode.OBSERVE)
    rule = await account.mini_app_rules.aget()
    for _repeat in range(2):
        assert await worker._notify_mini_app_operator(
            account.pk,
            rule.pk,
            MiniAppAuditEvent.EventType.MENU_DETECTED,
            3,
            "bot",
            MiniAppAuditEvent.Result.OBSERVED,
        )
    notification = await OperatorNotification.objects.aget(account=account)
    assert notification.repeat_count == 2
    assert notification.bot_username == "bot"

    runner = worker.AccountRunner(
        {
            "id": account.pk,
            "user_id": account.user_id,
            "encrypted_session": "unused",
        }
    )
    runner.client = MockTelegramApi()

    async def fail_reconcile() -> None:
        raise RuntimeError("mock-reconcile-failure")

    monkeypatch.setattr(runner, "_reconcile_mini_apps", fail_reconcile)
    await runner._maybe_reconcile_mini_apps(force=True)
    assert runner.next_mini_app_reconcile_at > 0
