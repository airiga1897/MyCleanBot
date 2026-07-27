from __future__ import annotations

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
    TelegramAccount,
    TelegramAuthFlow,
    WorkerHeartbeat,
)
from core.services import telegram_worker as worker
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
        media: bool = False,
        entities: list[Any] | None = None,
    ) -> None:
        self.chat_id = chat_id
        self.raw_text = text
        self.is_private = private
        self.is_channel = channel
        self.message = SimpleNamespace(id=5, entities=entities or [], media=media)
        self.deleted = 0
        self.edited = ""

    async def delete(self, revoke: bool) -> None:
        assert revoke
        self.deleted += 1

    async def edit(self, text: str) -> None:
        self.edited = text


async def test_database_helpers_encrypt_and_record() -> None:
    user = await User.objects.acreate_user("helper-user", password="long-password-123")
    encrypted = await worker._encrypt(user, "secret")
    assert await worker._decrypt(user, encrypted) == "secret"
    rule = await worker.sync_to_async(create_rule)(user, "phrase")
    assert await worker._load_rules(user) == [(rule.pk, "phrase")]

    account = await TelegramAccount.objects.acreate(user=user, encrypted_session=encrypted)
    assert (await worker._account_snapshot())[0]["id"] == account.pk
    await worker._set_account_state(account.pk, TelegramAccount.Status.ACTIVE, "x" * 100)
    await worker._record_event(
        user.pk,
        [rule.pk],
        "body",
        "private",
        FilterEvent.Result.DELETED,
    )
    await worker._heartbeat()
    assert await FilterEvent.objects.filter(user=user).acount() == 1
    assert await WorkerHeartbeat.objects.filter(name="telegram-supervisor").aexists()

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

    async def load_rules(_user: User) -> list[tuple[int, str]]:
        return [(9, "secret")]

    async def record(*args: Any) -> None:
        recorded.append(args)

    monkeypatch.setattr(worker, "_load_rules", load_rules)
    monkeypatch.setattr(worker, "_record_event", record)
    await runner._handle_message(event)
    assert event.deleted == 1
    assert recorded[0][1:5] == ([9], "caption", "group", FilterEvent.Result.DELETED)


async def test_message_failure_is_audited(monkeypatch: pytest.MonkeyPatch) -> None:
    user = await User.objects.acreate_user("failure-user", password="long-password-123")
    runner = worker.AccountRunner({"id": 1, "user_id": user.pk, "encrypted_session": "unused"})
    runner.user = user
    runner.own_id = 1
    event = DummyEvent("blocked", chat_id=1)
    recorded: list[tuple[Any, ...]] = []

    async def load_rules(_user: User) -> list[tuple[int, str]]:
        return [(2, "blocked")]

    async def fail(_event: Any) -> None:
        raise RuntimeError("without-sensitive-data")

    async def record(*args: Any) -> None:
        recorded.append(args)

    monkeypatch.setattr(worker, "_load_rules", load_rules)
    monkeypatch.setattr(worker, "_record_event", record)
    monkeypatch.setattr(runner, "_delete_with_retry", fail)
    await runner._handle_message(event)
    assert recorded[0][4:] == (FilterEvent.Result.FAILED, "RuntimeError")


async def test_status_command_is_ephemeral_and_other_messages_are_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = await User.objects.acreate_user("status-user", password="long-password-123")
    runner = worker.AccountRunner({"id": 1, "user_id": user.pk, "encrypted_session": "unused"})
    runner.user = user
    runner.own_id = 100

    async def no_rules(_user: User) -> list[tuple[int, str]]:
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
