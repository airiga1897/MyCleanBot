from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, cast

from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.db import IntegrityError, close_old_connections, connection
from django.utils import timezone
from telethon import TelegramClient, events
from telethon.errors import AuthKeyUnregisteredError, FloodWaitError, SessionPasswordNeededError
from telethon.sessions import StringSession
from telethon.tl import functions, types

from core.models import (
    FilterEvent,
    MiniAppAuditEvent,
    MiniAppPolicy,
    TelegramAccount,
    TelegramAuthFlow,
    WorkerHeartbeat,
)
from core.services.crypto import decrypt_for_user, encrypt_for_user, fingerprint
from core.services.matcher import TextCandidate, extract_candidates, find_matches, is_status_command
from core.services.miniapps import (
    MiniAppRuleDecision,
    MiniAppRuleSpec,
    MiniAppTarget,
    decide_mini_app_rule,
    extract_bot_usernames,
    load_mini_app_rules,
)
from core.services.rules import decrypted_rules

logger = logging.getLogger(__name__)
MINI_APP_WARNING_PREFIX = "⚠️ MyCleanBot:"
_BARE_BOT_COMMAND = "/"


def _lock_key(account_id: int) -> int:
    return 0x4D430000 + account_id


@sync_to_async(thread_sensitive=True)
def _acquire_account_lock(account_id: int) -> bool:
    close_old_connections()
    if connection.vendor != "postgresql":
        return True
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s)", [_lock_key(account_id)])
        return bool(cursor.fetchone()[0])


@sync_to_async(thread_sensitive=True)
def _release_account_lock(account_id: int) -> None:
    if connection.vendor != "postgresql":
        return
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_unlock(%s)", [_lock_key(account_id)])


@sync_to_async
def _account_snapshot() -> list[dict[str, Any]]:
    values = (
        TelegramAccount.objects.filter(desired_enabled=True)
        .exclude(encrypted_session="")
        .values("id", "user_id", "encrypted_session")
    )
    return cast(list[dict[str, Any]], list(values)[: settings.MAX_TELEGRAM_ACCOUNTS])


@sync_to_async
def _set_account_state(account_id: int, status: str, error_code: str = "") -> None:
    TelegramAccount.objects.filter(pk=account_id).update(
        status=status,
        last_error_code=error_code[:64],
        last_heartbeat_at=timezone.now(),
    )


@sync_to_async
def _clear_account_session(account_id: int) -> None:
    TelegramAccount.objects.filter(pk=account_id).update(
        encrypted_session="",
        encrypted_identity="",
        telegram_user_fingerprint=None,
        status=TelegramAccount.Status.DISCONNECTED,
        last_error_code="",
        last_heartbeat_at=timezone.now(),
    )


@sync_to_async
def _load_user(user_id: int) -> User:
    return User.objects.get(pk=user_id)


@sync_to_async
def _load_rules(user: User) -> list[tuple[int, str]]:
    return decrypted_rules(user)


@sync_to_async
def _encrypt(user: User, value: str) -> str:
    return encrypt_for_user(user, value)


@sync_to_async
def _decrypt(user: User, value: str) -> str:
    return decrypt_for_user(user, value)


@sync_to_async
def _record_event(
    user_id: int,
    rule_ids: list[int],
    source: str,
    chat_type: str,
    result: str,
    error_code: str = "",
) -> None:
    FilterEvent.objects.create(
        user_id=user_id,
        rule_ids=rule_ids,
        source=source,
        chat_type=chat_type,
        result=result,
        error_code=error_code[:64],
    )


@sync_to_async
def _load_mini_app_state(
    account_id: int,
) -> tuple[dict[str, Any], list[MiniAppRuleSpec]]:
    account = TelegramAccount.objects.select_related("user").get(pk=account_id)
    policy, _ = MiniAppPolicy.objects.get_or_create(account=account)
    return (
        {
            "mode": policy.mode,
            "block_bot": policy.block_bot,
            "notify_user": policy.notify_user,
            "notify_admin": policy.notify_admin,
        },
        load_mini_app_rules(account),
    )


@sync_to_async
def _record_mini_app_event(
    account_id: int,
    rule_id: int | None,
    event_type: str,
    result: str,
    *,
    bot_id: int | None = None,
    bot_username: str = "",
    error_code: str = "",
) -> None:
    MiniAppAuditEvent.objects.create(
        account_id=account_id,
        rule_id=rule_id,
        event_type=event_type,
        bot_id=bot_id,
        bot_username=bot_username[:64],
        result=result,
        error_code=error_code[:64],
    )


@sync_to_async
def _notify_mini_app_admin(
    account_id: int,
    rule_id: int | None,
    event_type: str,
    bot_id: int | None,
    bot_username: str,
) -> bool:
    recipients = [email for _name, email in settings.ADMINS]
    if not recipients:
        return False
    return bool(
        send_mail(
            "MyCleanBot: Mini App policy event",
            (
                f"account={account_id} rule={rule_id or '-'} event={event_type} "
                f"bot_id={bot_id or '-'} username={bot_username or '-'}"
            ),
            settings.SERVER_EMAIL,
            recipients,
            fail_silently=True,
        )
    )


@sync_to_async
def _heartbeat() -> None:
    WorkerHeartbeat.objects.update_or_create(
        name="telegram-supervisor", defaults={"state": "running"}
    )


def _chat_type(event: Any, own_id: int) -> str:
    if event.chat_id == own_id:
        return "saved"
    if event.is_private:
        return "private"
    if event.is_channel:
        return "channel"
    return "group"


class AccountRunner:
    def __init__(self, account: dict[str, Any]) -> None:
        self.account = account
        self.user: User | None = None
        self.client: TelegramClient | None = None
        self.own_id = 0
        self.service_messages: set[tuple[int, int]] = set()
        self.revoke_on_stop = False
        self.mini_app_reconcile_lock = asyncio.Lock()
        self.next_mini_app_reconcile_at = 0.0
        self.warned_mini_app_bot_ids: set[int] = set()

    def request_revoke(self) -> None:
        self.revoke_on_stop = True

    async def run(self) -> None:
        account_id = int(self.account["id"])
        if not await _acquire_account_lock(account_id):
            logger.warning("telegram_account_lock_busy account_id=%s", account_id)
            return
        try:
            await self._run_locked()
        except asyncio.CancelledError:
            raise
        except AuthKeyUnregisteredError:
            await _set_account_state(account_id, TelegramAccount.Status.DISCONNECTED)
        except Exception as exc:
            logger.exception(
                "telegram_account_runner_failed account_id=%s error=%s",
                account_id,
                exc.__class__.__name__,
            )
            await _set_account_state(
                account_id,
                TelegramAccount.Status.ERROR,
                exc.__class__.__name__,
            )
        finally:
            if self.client:
                if self.revoke_on_stop:
                    try:
                        await self.client.log_out()
                    finally:
                        await _clear_account_session(account_id)
                else:
                    await self.client.disconnect()
            await _release_account_lock(account_id)

    async def _run_locked(self) -> None:
        self.user = await _load_user(int(self.account["user_id"]))
        session = await _decrypt(self.user, str(self.account["encrypted_session"]))
        self.client = TelegramClient(
            StringSession(session),
            settings.TELEGRAM_API_ID,
            settings.TELEGRAM_API_HASH,
            use_ipv6=settings.TELEGRAM_USE_IPV6,
        )
        await _set_account_state(int(self.account["id"]), TelegramAccount.Status.CONNECTING)
        await self.client.connect()
        if not await self.client.is_user_authorized():
            await _set_account_state(int(self.account["id"]), TelegramAccount.Status.DISCONNECTED)
            return
        me = await self.client.get_me()
        self.own_id = int(me.id)
        self.client.add_event_handler(self._handle_message, events.NewMessage(outgoing=True))
        self.client.add_event_handler(self._handle_message, events.MessageEdited(outgoing=True))
        self.client.add_event_handler(
            self._handle_attach_menu_update,
            events.Raw(types.UpdateAttachMenuBots),
        )
        await _set_account_state(int(self.account["id"]), TelegramAccount.Status.ACTIVE)
        while self.client.is_connected():
            await _set_account_state(int(self.account["id"]), TelegramAccount.Status.ACTIVE)
            await self._maybe_reconcile_mini_apps()
            try:
                await asyncio.wait_for(
                    asyncio.shield(self.client.disconnected),
                    timeout=settings.WORKER_HEARTBEAT_SECONDS,
                )
            except TimeoutError:
                continue

    async def _handle_message(self, event: Any) -> None:
        if not self.user:
            return
        message_key = (int(event.chat_id or 0), int(event.message.id))
        if message_key in self.service_messages:
            return
        text = event.raw_text or ""
        if text.startswith(MINI_APP_WARNING_PREFIX):
            return
        saved = int(event.chat_id or 0) == self.own_id
        if is_status_command(text, saved):
            await self._show_status(event, message_key)
            return
        if await self._handle_mini_app_message(event, text):
            return
        candidates = extract_candidates(text, event.message.entities)
        if event.message.media:
            candidates = [
                TextCandidate("caption" if item.source == "body" else item.source, item.value)
                for item in candidates
            ]
        matches = find_matches(candidates, await _load_rules(self.user))
        if not matches:
            return
        rule_ids = sorted({match.rule_id for match in matches})
        source = (
            "link_target"
            if any(item.source == "link_target" for item in matches)
            else matches[0].source
        )
        chat_type = _chat_type(event, self.own_id)
        try:
            await self._delete_with_retry(event)
        except Exception as exc:
            await _record_event(
                self.user.pk,
                rule_ids,
                source,
                chat_type,
                FilterEvent.Result.FAILED,
                exc.__class__.__name__,
            )
            logger.warning(
                "message_delete_failed user_id=%s error=%s",
                self.user.pk,
                exc.__class__.__name__,
            )
        else:
            await _record_event(
                self.user.pk, rule_ids, source, chat_type, FilterEvent.Result.DELETED
            )

    async def _handle_attach_menu_update(self, _update: Any) -> None:
        await self._maybe_reconcile_mini_apps(force=True)

    async def _maybe_reconcile_mini_apps(self, *, force: bool = False) -> None:
        if not self.client:
            return
        now = asyncio.get_running_loop().time()
        if not force and now < self.next_mini_app_reconcile_at:
            return
        if self.mini_app_reconcile_lock.locked():
            return
        async with self.mini_app_reconcile_lock:
            self.next_mini_app_reconcile_at = (
                now + settings.MINI_APP_RECONCILE_SECONDS
            )
            try:
                await self._reconcile_mini_apps()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "mini_app_reconcile_failed account_id=%s error=%s",
                    self.account["id"],
                    exc.__class__.__name__,
                )

    async def _reconcile_mini_apps(self) -> None:
        if not self.client:
            return
        policy, rules = await _load_mini_app_state(int(self.account["id"]))
        response = await self.client(functions.messages.GetAttachMenuBotsRequest(hash=0))
        users = {int(user.id): user for user in getattr(response, "users", [])}
        installed_ids: set[int] = set()
        for app in getattr(response, "bots", []):
            if getattr(app, "inactive", False):
                continue
            bot_id = int(app.bot_id)
            installed_ids.add(bot_id)
            user = users.get(bot_id)
            username = str(getattr(user, "username", "") or "").casefold()
            target = MiniAppTarget(
                bot_id=bot_id,
                username=username,
                title=str(getattr(app, "short_name", "") or ""),
            )
            decision = decide_mini_app_rule(rules, target)
            if not decision.denied or not decision.rule:
                continue
            await self._record_mini_app_detection(
                policy,
                decision,
                MiniAppAuditEvent.EventType.MENU_DETECTED,
                target,
            )
            if policy["mode"] == MiniAppPolicy.Mode.ENFORCE and user is not None:
                await self._disable_mini_app(policy, decision, target, user)
        self.warned_mini_app_bot_ids.intersection_update(installed_ids)

    async def _disable_mini_app(
        self,
        policy: dict[str, Any],
        decision: MiniAppRuleDecision,
        target: MiniAppTarget,
        user: Any,
    ) -> None:
        if not self.client or not decision.rule:
            return
        try:
            await self.client(
                functions.messages.ToggleBotInAttachMenuRequest(
                    bot=user,
                    enabled=False,
                )
            )
        except Exception as exc:
            await _record_mini_app_event(
                int(self.account["id"]),
                decision.rule.id,
                MiniAppAuditEvent.EventType.MENU_DISABLED,
                MiniAppAuditEvent.Result.FAILED,
                bot_id=target.bot_id,
                bot_username=target.username,
                error_code=exc.__class__.__name__,
            )
        else:
            await _record_mini_app_event(
                int(self.account["id"]),
                decision.rule.id,
                MiniAppAuditEvent.EventType.MENU_DISABLED,
                MiniAppAuditEvent.Result.SUCCEEDED,
                bot_id=target.bot_id,
                bot_username=target.username,
            )
        if policy["block_bot"]:
            await self._block_bot(decision, target, user)

    async def _block_bot(
        self,
        decision: MiniAppRuleDecision,
        target: MiniAppTarget,
        entity: Any,
    ) -> None:
        if not self.client or not decision.rule:
            return
        try:
            await self.client(functions.contacts.BlockRequest(id=entity))
        except Exception as exc:
            await _record_mini_app_event(
                int(self.account["id"]),
                decision.rule.id,
                MiniAppAuditEvent.EventType.BOT_BLOCKED,
                MiniAppAuditEvent.Result.FAILED,
                bot_id=target.bot_id,
                bot_username=target.username,
                error_code=exc.__class__.__name__,
            )
        else:
            await _record_mini_app_event(
                int(self.account["id"]),
                decision.rule.id,
                MiniAppAuditEvent.EventType.BOT_BLOCKED,
                MiniAppAuditEvent.Result.SUCCEEDED,
                bot_id=target.bot_id,
                bot_username=target.username,
            )

    async def _handle_mini_app_message(self, event: Any, text: str) -> bool:
        if not self.client:
            return False
        policy, rules = await _load_mini_app_state(int(self.account["id"]))
        if not rules:
            return False
        targets: list[tuple[MiniAppTarget, Any | None]] = []
        for username in sorted(extract_bot_usernames(text)):
            entity: Any | None = None
            bot_id: int | None = None
            try:
                entity = await self.client.get_entity(username)
                bot_id = int(entity.id)
            except Exception:
                pass
            if entity is not None and not bool(getattr(entity, "bot", False)):
                continue
            targets.append((MiniAppTarget(bot_id=bot_id, username=username), entity))
        if (
            text.lstrip().startswith(_BARE_BOT_COMMAND)
            and "@" not in text.split(maxsplit=1)[0]
            and bool(getattr(event, "is_private", False))
            and hasattr(event, "get_chat")
        ):
            try:
                chat = await event.get_chat()
            except Exception:
                chat = None
            if chat is not None and bool(getattr(chat, "bot", False)):
                targets.append(
                    (
                        MiniAppTarget(
                            bot_id=int(chat.id),
                            username=str(getattr(chat, "username", "") or "").casefold(),
                        ),
                        chat,
                    )
                )
        targets.append((MiniAppTarget(), None))
        for target, entity in targets:
            decision = decide_mini_app_rule(rules, target, text)
            if not decision.denied or not decision.rule:
                continue
            await self._record_mini_app_detection(
                policy,
                decision,
                MiniAppAuditEvent.EventType.OUTGOING_DETECTED,
                target,
            )
            if policy["mode"] != MiniAppPolicy.Mode.ENFORCE:
                return False
            try:
                await self._delete_with_retry(event)
            except Exception as exc:
                await _record_mini_app_event(
                    int(self.account["id"]),
                    decision.rule.id,
                    MiniAppAuditEvent.EventType.MESSAGE_DELETED,
                    MiniAppAuditEvent.Result.FAILED,
                    bot_id=target.bot_id,
                    bot_username=target.username,
                    error_code=exc.__class__.__name__,
                )
            else:
                await _record_mini_app_event(
                    int(self.account["id"]),
                    decision.rule.id,
                    MiniAppAuditEvent.EventType.MESSAGE_DELETED,
                    MiniAppAuditEvent.Result.SUCCEEDED,
                    bot_id=target.bot_id,
                    bot_username=target.username,
                )
            if policy["block_bot"] and entity is not None:
                await self._block_bot(decision, target, entity)
            return True
        return False

    async def _record_mini_app_detection(
        self,
        policy: dict[str, Any],
        decision: MiniAppRuleDecision,
        event_type: str,
        target: MiniAppTarget,
    ) -> None:
        if not decision.rule:
            return
        mode = str(policy["mode"])
        result = (
            MiniAppAuditEvent.Result.OBSERVED
            if mode == MiniAppPolicy.Mode.OBSERVE
            else MiniAppAuditEvent.Result.WARNED
            if mode == MiniAppPolicy.Mode.WARN
            else MiniAppAuditEvent.Result.SUCCEEDED
        )
        await _record_mini_app_event(
            int(self.account["id"]),
            decision.rule.id,
            event_type,
            result,
            bot_id=target.bot_id,
            bot_username=target.username,
        )
        if mode == MiniAppPolicy.Mode.OBSERVE:
            return
        if policy["notify_user"] and target.bot_id not in self.warned_mini_app_bot_ids:
            await self._notify_user(decision, target)
            if target.bot_id is not None:
                self.warned_mini_app_bot_ids.add(target.bot_id)
        if policy["notify_admin"]:
            notified = await _notify_mini_app_admin(
                int(self.account["id"]),
                decision.rule.id,
                event_type,
                target.bot_id,
                target.username,
            )
            await _record_mini_app_event(
                int(self.account["id"]),
                decision.rule.id,
                MiniAppAuditEvent.EventType.ADMIN_NOTIFIED,
                (
                    MiniAppAuditEvent.Result.SUCCEEDED
                    if notified
                    else MiniAppAuditEvent.Result.SKIPPED
                ),
                bot_id=target.bot_id,
                bot_username=target.username,
            )

    async def _notify_user(
        self, decision: MiniAppRuleDecision, target: MiniAppTarget
    ) -> None:
        if not self.client or not decision.rule:
            return
        identifier = f"@{target.username}" if target.username else f"bot_id={target.bot_id or '-'}"
        try:
            warning = (
                f"{MINI_APP_WARNING_PREFIX} сработало правило "
                f"#{decision.rule.id} для {identifier}."
            )
            await self.client.send_message(
                "me",
                warning,
            )
        except Exception as exc:
            await _record_mini_app_event(
                int(self.account["id"]),
                decision.rule.id,
                MiniAppAuditEvent.EventType.USER_WARNED,
                MiniAppAuditEvent.Result.FAILED,
                bot_id=target.bot_id,
                bot_username=target.username,
                error_code=exc.__class__.__name__,
            )
        else:
            await _record_mini_app_event(
                int(self.account["id"]),
                decision.rule.id,
                MiniAppAuditEvent.EventType.USER_WARNED,
                MiniAppAuditEvent.Result.SUCCEEDED,
                bot_id=target.bot_id,
                bot_username=target.username,
            )

    async def _delete_with_retry(self, event: Any) -> None:
        for attempt in range(3):
            try:
                await event.delete(revoke=True)
                return
            except FloodWaitError as exc:
                if exc.seconds > 5 or attempt == 2:
                    raise
                await asyncio.sleep(exc.seconds)
            except (ConnectionError, TimeoutError):
                if attempt == 2:
                    raise
                await asyncio.sleep(0.25 * (2**attempt))

    async def _show_status(self, event: Any, message_key: tuple[int, int]) -> None:
        self.service_messages.add(message_key)
        try:
            await event.edit("✅ Фильтр активен")
            await asyncio.sleep(settings.STATUS_MESSAGE_TTL_SECONDS)
            await event.delete(revoke=True)
        finally:
            self.service_messages.discard(message_key)


@sync_to_async
def _pending_auth_flows() -> list[int]:
    return list(
        TelegramAuthFlow.objects.filter(state=TelegramAuthFlow.State.QUEUED)
        .filter(expires_at__gt=timezone.now())
        .values_list("id", flat=True)[: settings.MAX_TELEGRAM_ACCOUNTS]
    )


@sync_to_async
def _get_flow(flow_id: int) -> TelegramAuthFlow:
    return TelegramAuthFlow.objects.select_related("user").get(pk=flow_id)


@sync_to_async
def _update_flow(flow_id: int, state: str, payload: str = "", error_code: str = "") -> None:
    TelegramAuthFlow.objects.filter(pk=flow_id).update(
        state=state,
        encrypted_payload=payload,
        error_code=error_code[:64],
        updated_at=timezone.now(),
    )


@sync_to_async
def _consume_secret(flow_id: int) -> str:
    flow = TelegramAuthFlow.objects.select_related("user").get(pk=flow_id)
    if not flow.encrypted_payload:
        return ""
    secret = decrypt_for_user(flow.user, flow.encrypted_payload)
    flow.encrypted_payload = ""
    flow.save(update_fields=["encrypted_payload", "updated_at"])
    return secret


@sync_to_async
def _save_authorized_account(flow_id: int, client: TelegramClient, me: Any) -> None:
    flow = TelegramAuthFlow.objects.select_related("user").get(pk=flow_id)
    identity = json.dumps({"id": int(me.id), "username": me.username or ""})
    account, _ = TelegramAccount.objects.get_or_create(user=flow.user)
    account.encrypted_session = encrypt_for_user(flow.user, client.session.save())
    account.telegram_user_fingerprint = fingerprint(f"telegram:{int(me.id)}")
    account.encrypted_identity = encrypt_for_user(flow.user, identity)
    account.status = TelegramAccount.Status.CONNECTING
    account.desired_enabled = True
    account.last_error_code = ""
    account.save()
    flow.state = TelegramAuthFlow.State.COMPLETE
    flow.encrypted_payload = ""
    flow.save(update_fields=["state", "encrypted_payload", "updated_at"])


async def _wait_for_secret(flow_id: int, deadline: datetime) -> str:
    while timezone.now() < deadline:
        secret = await _consume_secret(flow_id)
        if secret:
            return secret
        await asyncio.sleep(1)
    raise TimeoutError("Authentication input expired")


async def process_auth_flow(flow_id: int) -> None:
    flow = await _get_flow(flow_id)
    client = TelegramClient(
        StringSession(),
        settings.TELEGRAM_API_ID,
        settings.TELEGRAM_API_HASH,
        use_ipv6=settings.TELEGRAM_USE_IPV6,
    )
    try:
        await client.connect()
        if flow.kind == TelegramAuthFlow.Kind.QR:
            qr = await client.qr_login()
            await _update_flow(
                flow_id,
                TelegramAuthFlow.State.QR_READY,
                await _encrypt(flow.user, qr.url),
            )
            try:
                await qr.wait(timeout=240)
            except SessionPasswordNeededError:
                await _update_flow(flow_id, TelegramAuthFlow.State.PASSWORD_REQUIRED)
                password = await _wait_for_secret(flow_id, flow.expires_at)
                await client.sign_in(password=password)
        else:
            phone = await _decrypt(flow.user, flow.encrypted_payload)
            sent = await client.send_code_request(phone)
            await _update_flow(flow_id, TelegramAuthFlow.State.CODE_REQUIRED)
            code = await _wait_for_secret(flow_id, flow.expires_at)
            try:
                await client.sign_in(phone, code, phone_code_hash=sent.phone_code_hash)
            except SessionPasswordNeededError:
                await _update_flow(flow_id, TelegramAuthFlow.State.PASSWORD_REQUIRED)
                password = await _wait_for_secret(flow_id, flow.expires_at)
                await client.sign_in(password=password)
        me = await client.get_me()
        await _save_authorized_account(flow_id, client, me)
    except TimeoutError:
        await _update_flow(flow_id, TelegramAuthFlow.State.EXPIRED)
    except IntegrityError:
        await _update_flow(
            flow_id,
            TelegramAuthFlow.State.FAILED,
            error_code="account_already_bound",
        )
    except Exception as exc:
        logger.warning("telegram_auth_failed flow_id=%s error=%s", flow_id, exc.__class__.__name__)
        await _update_flow(
            flow_id,
            TelegramAuthFlow.State.FAILED,
            error_code=exc.__class__.__name__,
        )
    finally:
        await client.disconnect()


class TelegramSupervisor:
    def __init__(self) -> None:
        self.runners: dict[int, tuple[AccountRunner, asyncio.Task[None]]] = {}
        self.auth_tasks: dict[int, asyncio.Task[None]] = {}

    async def run(self) -> None:
        if not settings.TELEGRAM_API_ID or not settings.TELEGRAM_API_HASH:
            raise RuntimeError("TELEGRAM_API_ID and TELEGRAM_API_HASH are required")
        while True:
            await _heartbeat()
            await self._sync_accounts()
            await self._sync_auth_flows()
            await asyncio.sleep(settings.WORKER_HEARTBEAT_SECONDS)

    async def _sync_accounts(self) -> None:
        snapshots = await _account_snapshot()
        desired_ids = {int(item["id"]) for item in snapshots}
        for account_id, (runner, task) in list(self.runners.items()):
            if task.done() or account_id not in desired_ids:
                if not task.done():
                    runner.request_revoke()
                    task.cancel()
                self.runners.pop(account_id, None)
        for account in snapshots:
            account_id = int(account["id"])
            if account_id not in self.runners:
                runner = AccountRunner(account)
                self.runners[account_id] = (runner, asyncio.create_task(runner.run()))

    async def _sync_auth_flows(self) -> None:
        for flow_id, task in list(self.auth_tasks.items()):
            if task.done():
                self.auth_tasks.pop(flow_id, None)
        for flow_id in await _pending_auth_flows():
            if flow_id not in self.auth_tasks:
                self.auth_tasks[flow_id] = asyncio.create_task(process_auth_flow(flow_id))
