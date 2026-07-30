from __future__ import annotations

import asyncio
import base64
import hashlib
from types import SimpleNamespace
from typing import Any

import pytest
from django.contrib.auth.models import User
from django.utils import timezone
from telethon.errors import AuthKeyUnregisteredError, SessionPasswordNeededError

from core.models import (
    FilterEvent,
    ForbiddenRule,
    HistoryScan,
    TelegramAccount,
    TelegramAuthFlow,
    TelegramDialog,
    WorkerHeartbeat,
)
from core.services import telegram_worker as worker
from core.services.crypto import decrypt_for_user
from core.services.rules import create_rule

pytestmark = [pytest.mark.django_db(transaction=True), pytest.mark.asyncio]


@pytest.fixture(autouse=True)
def worker_settings(settings: Any) -> None:
    settings.MASTER_ENCRYPTION_KEY = base64.urlsafe_b64encode(
        hashlib.sha256(b"worker-tests").digest()
    ).decode()
    settings.TELEGRAM_API_ID = 123
    settings.TELEGRAM_API_HASH = "test-hash"
    settings.STATUS_MESSAGE_TTL_SECONDS = 0


class DummyEvent:
    def __init__(
        self,
        text: str,
        *,
        chat_id: int = 100,
        private: bool = True,
        channel: bool = False,
        group: bool = False,
        outgoing: bool = True,
        media: bool = False,
        entities: list[Any] | None = None,
    ) -> None:
        self.chat_id = chat_id
        self.raw_text = text
        self.is_private = private
        self.is_channel = channel
        self.is_group = group
        self.out = outgoing
        self.message = SimpleNamespace(
            id=5,
            entities=entities or [],
            media=media,
            out=outgoing,
        )
        self.deleted = 0
        self.revoke_values: list[bool] = []
        self.edited = ""

    async def delete(self, revoke: bool) -> None:
        self.deleted += 1
        self.revoke_values.append(revoke)

    async def edit(self, text: str) -> None:
        self.edited = text


async def test_database_helpers_encrypt_and_record() -> None:
    user = await User.objects.acreate_user("helper-user", password="long-password-123")
    encrypted = await worker._encrypt(user, "secret")
    assert await worker._decrypt(user, encrypted) == "secret"
    rule = await worker.sync_to_async(create_rule)(user, "phrase")
    rules = await worker._load_rules(user, FilterEvent.Direction.OUTGOING)
    assert len(rules) == 1
    assert rules[0].id == rule.pk
    assert rules[0].phrases == ("phrase",)
    assert rules[0].mode == ForbiddenRule.Mode.ENFORCE

    account = await TelegramAccount.objects.acreate(user=user, encrypted_session=encrypted)
    assert (await worker._account_snapshot())[0]["id"] == account.pk
    await worker._set_account_state(account.pk, TelegramAccount.Status.ACTIVE, "x" * 100)
    await worker._record_event(
        user.pk,
        [rule.pk],
        FilterEvent.Direction.OUTGOING,
        "body",
        "private",
        FilterEvent.Result.DELETED,
    )
    await worker._heartbeat()
    assert await FilterEvent.objects.filter(user=user).acount() == 1
    assert await WorkerHeartbeat.objects.filter(name="telegram-supervisor").aexists()


async def test_dialog_catalog_sync_encrypts_labels_and_marks_missing_unavailable() -> None:
    user = await User.objects.acreate_user(
        "dialog-sync-user", password="long-password-123"
    )
    account = await TelegramAccount.objects.acreate(user=user)

    await worker._sync_dialog_catalog(
        account.pk,
        [
            {"peer_id": 101, "label": "Личный чат", "kind": TelegramDialog.Kind.PRIVATE},
            {"peer_id": 202, "label": "Рабочая группа", "kind": TelegramDialog.Kind.GROUP},
        ],
    )

    dialogs = [
        item
        async for item in TelegramDialog.objects.filter(account=account).order_by("id")
    ]
    assert len(dialogs) == 2
    assert "Личный чат" not in dialogs[0].encrypted_label
    assert (
        await worker.sync_to_async(decrypt_for_user)(user, dialogs[0].encrypted_label)
        == "Личный чат"
    )
    assert all(item.available for item in dialogs)

    await worker._sync_dialog_catalog(
        account.pk,
        [{"peer_id": 202, "label": "Группа переименована", "kind": TelegramDialog.Kind.GROUP}],
    )

    await dialogs[0].arefresh_from_db()
    await dialogs[1].arefresh_from_db()
    assert not dialogs[0].available
    assert dialogs[1].available
    assert (
        await worker.sync_to_async(decrypt_for_user)(user, dialogs[1].encrypted_label)
        == "Группа переименована"
    )


async def test_account_runner_synchronizes_dialogs_and_tolerates_api_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = await User.objects.acreate_user(
        "runner-dialog-user", password="long-password-123"
    )
    account = await TelegramAccount.objects.acreate(user=user)
    runner = worker.AccountRunner(
        {"id": account.pk, "user_id": user.pk, "encrypted_session": ""}
    )
    runner.own_id = 77

    class DialogClient:
        async def iter_dialogs(self) -> Any:
            yield SimpleNamespace(id=77, name="Me", is_user=True, is_channel=False)
            yield SimpleNamespace(
                id=88,
                name="Команда",
                is_user=False,
                is_channel=True,
                entity=SimpleNamespace(megagroup=True),
            )

    runner.client = DialogClient()  # type: ignore[assignment]
    await runner._maybe_sync_dialogs()
    assert await TelegramDialog.objects.filter(account=account).acount() == 2

    runner.next_dialog_sync_at = 0

    class BrokenDialogClient:
        async def iter_dialogs(self) -> Any:
            if False:
                yield None
            raise ConnectionError("safe test failure")

    runner.client = BrokenDialogClient()  # type: ignore[assignment]
    await runner._maybe_sync_dialogs()
    assert runner.next_dialog_sync_at > 0

    await worker._clear_account_session(account.pk)
    await account.arefresh_from_db()
    assert account.status == TelegramAccount.Status.DISCONNECTED
    assert account.encrypted_session == ""


async def test_chat_types_and_non_postgres_lock() -> None:
    assert worker._lock_key(4) != worker._lock_key(5)
    assert worker._chat_type(SimpleNamespace(chat_id=1), 1) == "saved"
    assert worker._chat_type(SimpleNamespace(chat_id=2, is_private=True), 1) == "private"
    assert (
        worker._chat_type(SimpleNamespace(chat_id=2, is_private=False, is_channel=True), 1)
        == "channel"
    )
    assert (
        worker._chat_type(SimpleNamespace(chat_id=2, is_private=False, is_channel=False), 1)
        == "group"
    )
    assert await worker._acquire_account_lock(1)
    await worker._release_account_lock(1)


async def test_message_match_deletes_and_records(monkeypatch: pytest.MonkeyPatch) -> None:
    user = await User.objects.acreate_user("message-user", password="long-password-123")
    runner = worker.AccountRunner({"id": 1, "user_id": user.pk, "encrypted_session": "unused"})
    runner.user = user
    runner.own_id = 999
    event = DummyEvent("caption SECRET", media=True, private=False)
    recorded: list[tuple[Any, ...]] = []

    async def load_rules(_user: User, _direction: str) -> list[tuple[int, str, str]]:
        return [(9, "secret", ForbiddenRule.Mode.ENFORCE)]

    async def no_mini_apps(_event: Any, _text: str) -> bool:
        return False

    async def record(*args: Any) -> None:
        recorded.append(args)

    monkeypatch.setattr(worker, "_load_rules", load_rules)
    monkeypatch.setattr(worker, "_record_event", record)
    monkeypatch.setattr(runner, "_handle_mini_app_message", no_mini_apps)
    await runner._handle_message(event)
    assert event.deleted == 1
    assert event.revoke_values == [True]
    assert recorded[0][1:6] == (
        [9],
        FilterEvent.Direction.OUTGOING,
        "caption",
        "group",
        FilterEvent.Result.DELETED_ALL,
    )


async def test_message_failure_is_audited(monkeypatch: pytest.MonkeyPatch) -> None:
    user = await User.objects.acreate_user("failure-user", password="long-password-123")
    runner = worker.AccountRunner({"id": 1, "user_id": user.pk, "encrypted_session": "unused"})
    runner.user = user
    runner.own_id = 1
    event = DummyEvent("blocked", chat_id=1)
    recorded: list[tuple[Any, ...]] = []

    async def load_rules(_user: User, _direction: str) -> list[tuple[int, str, str]]:
        return [(2, "blocked", ForbiddenRule.Mode.ENFORCE)]

    async def fail(_event: Any, _direction: str, _chat_type: str) -> str:
        raise RuntimeError("without-sensitive-data")

    async def record(*args: Any) -> None:
        recorded.append(args)

    async def no_mini_apps(_event: Any, _text: str) -> bool:
        return False

    monkeypatch.setattr(worker, "_load_rules", load_rules)
    monkeypatch.setattr(worker, "_record_event", record)
    monkeypatch.setattr(runner, "_delete_matched_message", fail)
    monkeypatch.setattr(runner, "_handle_mini_app_message", no_mini_apps)
    await runner._handle_message(event)
    assert recorded[0][5:] == (FilterEvent.Result.FAILED, "RuntimeError")


async def test_incoming_private_message_is_deleted_only_for_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = await User.objects.acreate_user("incoming-user", password="long-password-123")
    runner = worker.AccountRunner({"id": 1, "user_id": user.pk, "encrypted_session": "unused"})
    runner.user = user
    event = DummyEvent("blocked", outgoing=False)
    recorded: list[tuple[Any, ...]] = []

    async def load_rules(_user: User, direction: str) -> list[tuple[int, str, str]]:
        assert direction == FilterEvent.Direction.INCOMING
        return [(4, "blocked", ForbiddenRule.Mode.ENFORCE)]

    async def record(*args: Any) -> None:
        recorded.append(args)

    monkeypatch.setattr(worker, "_load_rules", load_rules)
    monkeypatch.setattr(worker, "_record_event", record)
    await runner._handle_message(event)
    assert event.revoke_values == [False]
    assert recorded[0][5] == FilterEvent.Result.DELETED_SELF


async def test_incoming_supergroup_requires_global_delete_permission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = await User.objects.acreate_user("group-user", password="long-password-123")
    runner = worker.AccountRunner({"id": 1, "user_id": user.pk, "encrypted_session": "unused"})
    runner.user = user
    event = DummyEvent(
        "blocked",
        private=False,
        channel=True,
        group=True,
        outgoing=False,
    )
    runner.client = SimpleNamespace(
        get_permissions=lambda *_args: None,
    )

    async def permissions(*_args: Any) -> Any:
        return SimpleNamespace(is_creator=False, delete_messages=False)

    runner.client.get_permissions = permissions
    recorded: list[tuple[Any, ...]] = []

    async def load_rules(_user: User, _direction: str) -> list[tuple[int, str, str]]:
        return [(5, "blocked", ForbiddenRule.Mode.ENFORCE)]

    async def record(*args: Any) -> None:
        recorded.append(args)

    monkeypatch.setattr(worker, "_load_rules", load_rules)
    monkeypatch.setattr(worker, "_record_event", record)
    await runner._handle_message(event)
    assert event.deleted == 0
    assert recorded[0][5:] == (FilterEvent.Result.FAILED, "PermissionError")


async def test_observe_and_warn_modes_do_not_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = await User.objects.acreate_user("mode-user", password="long-password-123")
    runner = worker.AccountRunner({"id": 1, "user_id": user.pk, "encrypted_session": "unused"})
    runner.user = user
    recorded: list[tuple[Any, ...]] = []
    warnings: list[list[int]] = []

    async def record(*args: Any) -> None:
        recorded.append(args)

    async def warn(rule_ids: list[int]) -> None:
        warnings.append(rule_ids)

    monkeypatch.setattr(worker, "_record_event", record)
    monkeypatch.setattr(runner, "_notify_filter_warning", warn)

    async def observe(_user: User, _direction: str) -> list[tuple[int, str, str]]:
        return [(6, "blocked", ForbiddenRule.Mode.OBSERVE)]

    monkeypatch.setattr(worker, "_load_rules", observe)
    observed = DummyEvent("blocked", outgoing=False)
    await runner._handle_message(observed)
    assert observed.deleted == 0
    assert recorded[-1][5] == FilterEvent.Result.DETECTED

    async def warning(_user: User, _direction: str) -> list[tuple[int, str, str]]:
        return [(7, "blocked", ForbiddenRule.Mode.WARN)]

    monkeypatch.setattr(worker, "_load_rules", warning)
    warned = DummyEvent("blocked", outgoing=False)
    await runner._handle_message(warned)
    assert warned.deleted == 0
    assert recorded[-1][5] == FilterEvent.Result.WARNED
    assert warnings == [[7]]


async def test_rule_scope_only_matches_selected_dialog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = await User.objects.acreate_user(
        "dialog-scope-user", password="long-password-123"
    )
    runner = worker.AccountRunner(
        {"id": 42, "user_id": user.pk, "encrypted_session": "unused"}
    )
    runner.user = user
    selected_fingerprint = worker.peer_fingerprint(42, 100)

    async def load_rules(_user: User, _direction: str) -> list[worker.RuleSpec]:
        return [
            worker.RuleSpec(
                id=8,
                phrases=("blocked",),
                mode=ForbiddenRule.Mode.ENFORCE,
                revision=1,
                dialog_fingerprints=frozenset({selected_fingerprint}),
            )
        ]

    monkeypatch.setattr(worker, "_load_rules", load_rules)
    outside = DummyEvent("blocked", chat_id=200, outgoing=False)
    selected = DummyEvent("blocked", chat_id=100, outgoing=False)

    await runner._handle_message(outside)
    await runner._handle_message(selected)

    assert outside.deleted == 0
    assert selected.deleted == 1


class HistoryMessage:
    def __init__(self, message_id: int, text: str, *, outgoing: bool = False) -> None:
        self.id = message_id
        self.raw_text = text
        self.out = outgoing
        self.entities: list[Any] = []
        self.media = None
        self.deleted = False
        self.revoke: bool | None = None

    async def delete(self, *, revoke: bool) -> None:
        self.deleted = True
        self.revoke = revoke


class HistoryClient:
    def __init__(self) -> None:
        self.private_messages = [
            HistoryMessage(9, "ordinary"),
            HistoryMessage(8, "contains blocked marker"),
        ]
        self.channel_messages = [HistoryMessage(7, "blocked marker")]
        self.dialogs = [
            SimpleNamespace(
                id=100,
                input_entity="private",
                is_user=True,
                is_channel=False,
                entity=SimpleNamespace(megagroup=False),
            ),
            SimpleNamespace(
                id=-200,
                input_entity="channel",
                is_user=False,
                is_channel=True,
                entity=SimpleNamespace(megagroup=False),
            ),
        ]
        self.offsets: list[tuple[str, int]] = []

    async def iter_dialogs(self) -> Any:
        for dialog in self.dialogs:
            yield dialog

    async def iter_messages(self, entity: str, *, offset_id: int) -> Any:
        self.offsets.append((entity, offset_id))
        messages = (
            self.private_messages if entity == "private" else self.channel_messages
        )
        for message in messages:
            if not offset_id or message.id < offset_id:
                yield message


async def test_full_history_preview_then_safe_enforcement(
    monkeypatch: pytest.MonkeyPatch, settings: Any
) -> None:
    settings.HISTORY_SCAN_BATCH_SIZE = 1
    settings.HISTORY_SCAN_YIELD_SECONDS = 0
    user = await User.objects.acreate_user(
        "history-worker", password="long-password-123"
    )
    account = await TelegramAccount.objects.acreate(
        user=user, encrypted_session="encrypted"
    )
    await worker.sync_to_async(create_rule)(user, "blocked marker")
    scan = await HistoryScan.objects.acreate(
        account=account,
        phase=HistoryScan.Phase.PREVIEW,
    )
    runner = worker.AccountRunner(
        {"id": account.pk, "user_id": user.pk, "encrypted_session": "unused"}
    )
    runner.user = user
    runner.own_id = 999
    preview_client = HistoryClient()
    runner.client = preview_client  # type: ignore[assignment]

    claimed = await worker._claim_history_scan(account.pk)
    assert claimed is not None
    await runner._scan_history(claimed)
    await scan.arefresh_from_db()
    assert scan.status == HistoryScan.Status.AWAITING_CONFIRMATION
    assert scan.dialogs_scanned == 2
    assert scan.messages_scanned == 3
    assert scan.matches_found == 2
    assert not any(message.deleted for message in preview_client.private_messages)

    scan.preview_matches = scan.matches_found
    scan.phase = HistoryScan.Phase.ENFORCE
    scan.status = HistoryScan.Status.QUEUED
    scan.dialogs_scanned = 0
    scan.message_offset_id = 0
    scan.messages_scanned = 0
    scan.matches_found = 0
    await scan.asave()
    enforce_client = HistoryClient()
    runner.client = enforce_client  # type: ignore[assignment]

    claimed = await worker._claim_history_scan(account.pk)
    assert claimed is not None
    await runner._scan_history(claimed)
    await scan.arefresh_from_db()
    assert scan.status == HistoryScan.Status.COMPLETED
    assert scan.preview_matches == 2
    assert scan.matches_found == 2
    assert scan.deleted_self == 1
    assert scan.skipped_global == 1
    matched_private = enforce_client.private_messages[1]
    assert matched_private.deleted
    assert matched_private.revoke is False
    assert not enforce_client.channel_messages[0].deleted


async def test_history_scan_resumes_from_sanitized_cursor(settings: Any) -> None:
    settings.HISTORY_SCAN_BATCH_SIZE = 10
    settings.HISTORY_SCAN_YIELD_SECONDS = 0
    user = await User.objects.acreate_user(
        "history-resume", password="long-password-123"
    )
    account = await TelegramAccount.objects.acreate(
        user=user, encrypted_session="encrypted"
    )
    await worker.sync_to_async(create_rule)(user, "blocked marker")
    scan = await HistoryScan.objects.acreate(
        account=account,
        phase=HistoryScan.Phase.PREVIEW,
        status=HistoryScan.Status.RUNNING,
        dialogs_scanned=1,
        message_offset_id=8,
    )
    runner = worker.AccountRunner(
        {"id": account.pk, "user_id": user.pk, "encrypted_session": "unused"}
    )
    runner.user = user
    runner.own_id = 999
    history_client = HistoryClient()
    runner.client = history_client  # type: ignore[assignment]

    claimed = await worker._claim_history_scan(account.pk)
    assert claimed is not None
    await runner._scan_history(claimed)
    await scan.arefresh_from_db()
    assert history_client.offsets == [("channel", 8)]
    assert scan.messages_scanned == 1
    assert scan.matches_found == 1


async def test_history_scan_honours_background_cancellation(
    monkeypatch: pytest.MonkeyPatch, settings: Any
) -> None:
    settings.HISTORY_SCAN_BATCH_SIZE = 1
    settings.HISTORY_SCAN_YIELD_SECONDS = 0
    user = await User.objects.acreate_user(
        "history-stop", password="long-password-123"
    )
    account = await TelegramAccount.objects.acreate(
        user=user, encrypted_session="encrypted"
    )
    await worker.sync_to_async(create_rule)(user, "blocked marker")
    scan = await HistoryScan.objects.acreate(
        account=account,
        phase=HistoryScan.Phase.PREVIEW,
    )
    runner = worker.AccountRunner(
        {"id": account.pk, "user_id": user.pk, "encrypted_session": "unused"}
    )
    runner.user = user
    runner.client = HistoryClient()  # type: ignore[assignment]

    async def cancelled(_scan_id: int) -> bool:
        return True

    monkeypatch.setattr(worker, "_history_scan_cancel_requested", cancelled)
    claimed = await worker._claim_history_scan(account.pk)
    assert claimed is not None
    await runner._scan_history(claimed)
    await scan.arefresh_from_db()
    assert scan.status == HistoryScan.Status.CANCELLED
    assert scan.messages_scanned == 1


async def test_status_command_is_ephemeral_and_other_messages_are_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = await User.objects.acreate_user("status-user", password="long-password-123")
    runner = worker.AccountRunner({"id": 1, "user_id": user.pk, "encrypted_session": "unused"})
    runner.user = user
    runner.own_id = 100

    async def no_rules(_user: User, _direction: str) -> list[tuple[int, str, str]]:
        return []

    async def instant_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(worker, "_load_rules", no_rules)
    monkeypatch.setattr(worker.asyncio, "sleep", instant_sleep)
    event = DummyEvent("/mc_status")
    await runner._handle_message(event)
    assert event.edited == "✅ Фильтр активен"
    assert event.deleted == 1
    assert runner.service_messages == set()

    runner.user = None
    await runner._handle_message(DummyEvent("anything"))


async def test_delete_retries_connection_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = worker.AccountRunner({"id": 1, "user_id": 1, "encrypted_session": "unused"})
    calls = 0

    class FlakyEvent:
        async def delete(self, revoke: bool) -> None:
            nonlocal calls
            calls += 1
            if calls < 3:
                raise ConnectionError

    async def instant_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(worker.asyncio, "sleep", instant_sleep)
    await runner._delete_with_retry(FlakyEvent())
    assert calls == 3


async def test_account_runner_handles_lock_auth_error_and_revoke(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    states: list[str] = []

    async def no_lock(_account_id: int) -> bool:
        return False

    runner = worker.AccountRunner({"id": 1, "user_id": 1, "encrypted_session": "unused"})
    monkeypatch.setattr(worker, "_acquire_account_lock", no_lock)
    await runner.run()

    async def lock(_account_id: int) -> bool:
        return True

    async def release(_account_id: int) -> None:
        return None

    async def set_state(_account_id: int, state: str, _error: str = "") -> None:
        states.append(state)

    async def auth_error() -> None:
        raise AuthKeyUnregisteredError(None)

    monkeypatch.setattr(worker, "_acquire_account_lock", lock)
    monkeypatch.setattr(worker, "_release_account_lock", release)
    monkeypatch.setattr(worker, "_set_account_state", set_state)
    monkeypatch.setattr(runner, "_run_locked", auth_error)
    await runner.run()
    assert TelegramAccount.Status.DISCONNECTED in states

    class FakeClient:
        logged_out = False

        async def log_out(self) -> None:
            self.logged_out = True

    async def clear(_account_id: int) -> None:
        states.append("cleared")

    async def no_op() -> None:
        return None

    runner.client = FakeClient()
    runner.request_revoke()
    monkeypatch.setattr(runner, "_run_locked", no_op)
    monkeypatch.setattr(worker, "_clear_account_session", clear)
    await runner.run()
    assert runner.client.logged_out
    assert "cleared" in states


class FakeSession:
    def save(self) -> str:
        return "authorized-session"


class FakeQr:
    url = "tg://login?token=test"

    async def wait(self, timeout: int) -> None:
        assert timeout == 240


class FakeClient:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.session = FakeSession()
        self.disconnected = _DoneAwaitable()
        self.handlers: list[Any] = []
        self.authorized = True
        self.connected = False

    async def connect(self) -> None:
        self.connected = True

    async def disconnect(self) -> None:
        self.connected = False

    async def log_out(self) -> None:
        self.connected = False

    async def is_user_authorized(self) -> bool:
        return self.authorized

    async def get_me(self) -> Any:
        return SimpleNamespace(id=777, username="test-user")

    async def qr_login(self) -> FakeQr:
        return FakeQr()

    async def send_code_request(self, phone: str) -> Any:
        assert phone == "+70000000000"
        return SimpleNamespace(phone_code_hash="hash")

    async def sign_in(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def add_event_handler(self, *args: Any) -> None:
        self.handlers.append(args)

    def is_connected(self) -> bool:
        return False


class _DoneAwaitable:
    def __await__(self) -> Any:
        async def done() -> None:
            return None

        return done().__await__()


async def test_qr_auth_flow_saves_encrypted_session(monkeypatch: pytest.MonkeyPatch) -> None:
    user = await User.objects.acreate_user("qr-user", password="long-password-123")
    flow = await TelegramAuthFlow.objects.acreate(
        user=user,
        kind=TelegramAuthFlow.Kind.QR,
        expires_at=timezone.now() + timezone.timedelta(minutes=5),
    )
    monkeypatch.setattr(worker, "TelegramClient", FakeClient)
    await worker.process_auth_flow(flow.pk)
    await flow.arefresh_from_db()
    account = await TelegramAccount.objects.aget(user=user)
    assert flow.state == TelegramAuthFlow.State.COMPLETE
    assert "authorized-session" not in account.encrypted_session
    assert account.telegram_user_fingerprint


async def test_phone_auth_with_2fa(monkeypatch: pytest.MonkeyPatch) -> None:
    user = await User.objects.acreate_user("phone-user", password="long-password-123")
    flow = await TelegramAuthFlow.objects.acreate(
        user=user,
        kind=TelegramAuthFlow.Kind.PHONE,
        encrypted_payload=await worker._encrypt(user, "+70000000000"),
        expires_at=timezone.now() + timezone.timedelta(minutes=5),
    )
    fake = FakeClient()
    calls = 0

    async def sign_in(*_args: Any, **kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        if "password" not in kwargs:
            raise SessionPasswordNeededError(None)

    secrets = iter(["12345", "two-factor-password"])

    async def next_secret(_flow_id: int, _deadline: Any) -> str:
        return next(secrets)

    fake.sign_in = sign_in
    monkeypatch.setattr(worker, "TelegramClient", lambda *_args, **_kwargs: fake)
    monkeypatch.setattr(worker, "_wait_for_secret", next_secret)
    await worker.process_auth_flow(flow.pk)
    await flow.arefresh_from_db()
    assert flow.state == TelegramAuthFlow.State.COMPLETE
    assert calls == 2


async def test_auth_timeout_and_generic_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    user = await User.objects.acreate_user("error-user", password="long-password-123")
    flow = await TelegramAuthFlow.objects.acreate(
        user=user,
        kind=TelegramAuthFlow.Kind.QR,
        expires_at=timezone.now() + timezone.timedelta(minutes=5),
    )

    class TimeoutClient(FakeClient):
        async def qr_login(self) -> Any:
            raise TimeoutError

    monkeypatch.setattr(worker, "TelegramClient", TimeoutClient)
    await worker.process_auth_flow(flow.pk)
    await flow.arefresh_from_db()
    assert flow.state == TelegramAuthFlow.State.EXPIRED

    flow.state = TelegramAuthFlow.State.QUEUED
    await flow.asave(update_fields=["state"])

    class BrokenClient(FakeClient):
        async def connect(self) -> None:
            raise ValueError("not logged")

    monkeypatch.setattr(worker, "TelegramClient", BrokenClient)
    await worker.process_auth_flow(flow.pk)
    await flow.arefresh_from_db()
    assert flow.state == TelegramAuthFlow.State.FAILED
    assert flow.error_code == "ValueError"


async def test_supervisor_syncs_accounts_and_auth_tasks(monkeypatch: pytest.MonkeyPatch) -> None:
    supervisor = worker.TelegramSupervisor()

    async def snapshots() -> list[dict[str, Any]]:
        return [{"id": 4, "user_id": 9, "encrypted_session": "x"}]

    async def runner_run(_self: worker.AccountRunner) -> None:
        return None

    monkeypatch.setattr(worker, "_account_snapshot", snapshots)
    monkeypatch.setattr(worker.AccountRunner, "run", runner_run)
    await supervisor._sync_accounts()
    assert 4 in supervisor.runners
    await supervisor.runners[4][1]
    await supervisor._sync_accounts()

    async def flow_ids() -> list[int]:
        return [8]

    async def process(_flow_id: int) -> None:
        return None

    monkeypatch.setattr(worker, "_pending_auth_flows", flow_ids)
    monkeypatch.setattr(worker, "process_auth_flow", process)
    await supervisor._sync_auth_flows()
    assert 8 in supervisor.auth_tasks
    await supervisor.auth_tasks[8]
    await supervisor._sync_auth_flows()


async def test_supervisor_stops_cancelled_auth_and_expires_orphans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = await User.objects.acreate_user("cancel-user", password="long-password-123")
    orphan = await TelegramAuthFlow.objects.acreate(
        user=user,
        kind=TelegramAuthFlow.Kind.QR,
        state=TelegramAuthFlow.State.VERIFYING,
        encrypted_payload=await worker._encrypt(user, "transient-secret"),
        expires_at=timezone.now() + timezone.timedelta(minutes=5),
    )
    cancelled = await TelegramAuthFlow.objects.acreate(
        user=user,
        kind=TelegramAuthFlow.Kind.QR,
        state=TelegramAuthFlow.State.CANCELLED,
        expires_at=timezone.now() + timezone.timedelta(minutes=5),
    )
    supervisor = worker.TelegramSupervisor()
    task = asyncio.create_task(asyncio.sleep(60))
    supervisor.auth_tasks[cancelled.pk] = task  # type: ignore[assignment]

    async def no_pending() -> list[int]:
        return []

    monkeypatch.setattr(worker, "_pending_auth_flows", no_pending)
    await supervisor._sync_auth_flows()
    await asyncio.sleep(0)
    await orphan.arefresh_from_db()

    assert task.cancelled()
    assert cancelled.pk not in supervisor.auth_tasks
    assert orphan.state == TelegramAuthFlow.State.EXPIRED
    assert orphan.encrypted_payload == ""
