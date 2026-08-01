from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from datetime import datetime
from typing import Any, cast

from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth.models import User
from django.db import IntegrityError, close_old_connections, connection, transaction
from django.utils import timezone
from telethon import TelegramClient, events
from telethon.errors import AuthKeyUnregisteredError, FloodWaitError, SessionPasswordNeededError
from telethon.sessions import StringSession
from telethon.tl import functions, types

from core.models import (
    FilterEvent,
    ForbiddenRule,
    HistoryScan,
    MiniAppAuditEvent,
    MiniAppPolicy,
    OperatorNotification,
    TelegramAccount,
    TelegramAuthFlow,
    TelegramDialog,
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
from core.services.rules import RuleSpec, decrypted_rules, peer_fingerprint

logger = logging.getLogger(__name__)
MINI_APP_WARNING_PREFIX = "⚠️ MyCleanBot:"
FILTER_WARNING_PREFIX = "⚠️ MyCleanBot: правило текста"
_BARE_BOT_COMMAND = "/"


class AuthFlowCancelled(Exception):
    pass


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
        TelegramAccount.objects.filter(desired_enabled=True, user__is_active=True)
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
def _load_rules(user: User, direction: str) -> list[RuleSpec]:
    return decrypted_rules(user, direction)


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
    direction: str,
    source: str,
    chat_type: str,
    result: str,
    error_code: str = "",
) -> None:
    FilterEvent.objects.create(
        user_id=user_id,
        rule_ids=rule_ids,
        direction=direction,
        source=source,
        chat_type=chat_type,
        result=result,
        error_code=error_code[:64],
    )


@sync_to_async
def _record_account_update(account_id: int, direction: str, result: str) -> None:
    TelegramAccount.objects.filter(pk=account_id).update(
        last_update_at=timezone.now(),
        last_update_direction=direction,
        last_update_result=result[:32],
    )


@sync_to_async
@transaction.atomic
def _sync_dialog_catalog(account_id: int, entries: list[dict[str, Any]]) -> None:
    account = TelegramAccount.objects.select_related("user").get(pk=account_id)
    now = timezone.now()
    seen: set[str] = set()
    for entry in entries:
        dialog_key = peer_fingerprint(account_id, int(entry["peer_id"]))
        seen.add(dialog_key)
        TelegramDialog.objects.update_or_create(
            account=account,
            peer_fingerprint=dialog_key,
            defaults={
                "encrypted_label": encrypt_for_user(
                    account.user, str(entry["label"])[:256]
                ),
                "kind": str(entry["kind"]),
                "available": True,
                "last_seen_at": now,
            },
        )
    TelegramDialog.objects.filter(account=account).exclude(
        peer_fingerprint__in=seen
    ).update(available=False)


@sync_to_async(thread_sensitive=True)
@transaction.atomic
def _claim_history_scan(account_id: int) -> dict[str, Any] | None:
    scans = HistoryScan.objects.select_for_update().filter(account_id=account_id)
    scan = scans.filter(status=HistoryScan.Status.RUNNING).first()
    if scan is None:
        scan = scans.filter(status=HistoryScan.Status.QUEUED).order_by("created_at").first()
    if scan is None:
        return None
    if scan.status == HistoryScan.Status.QUEUED:
        scan.status = HistoryScan.Status.RUNNING
        scan.started_at = scan.started_at or timezone.now()
        scan.last_error_code = ""
        scan.save(
            update_fields=["status", "started_at", "last_error_code", "updated_at"]
        )
    return {
        "id": scan.pk,
        "phase": scan.phase,
        "rule_id": scan.rule_id,
        "rule_revision": scan.rule_revision,
        "dialogs_scanned": scan.dialogs_scanned,
        "message_offset_id": scan.message_offset_id,
        "messages_scanned": scan.messages_scanned,
        "matches_found": scan.matches_found,
        "deleted_self": scan.deleted_self,
        "skipped_global": scan.skipped_global,
        "failed_actions": scan.failed_actions,
    }


@sync_to_async
def _history_scan_cancel_requested(scan_id: int) -> bool:
    return bool(
        HistoryScan.objects.filter(pk=scan_id).values_list(
            "cancel_requested", flat=True
        ).get()
    )


@sync_to_async
def _update_history_scan_progress(
    scan_id: int,
    *,
    dialogs_scanned: int,
    message_offset_id: int,
    messages_scanned: int,
    matches_found: int,
    deleted_self: int,
    skipped_global: int,
    failed_actions: int,
    last_error_code: str = "",
) -> None:
    HistoryScan.objects.filter(pk=scan_id, status=HistoryScan.Status.RUNNING).update(
        dialogs_scanned=dialogs_scanned,
        message_offset_id=message_offset_id,
        messages_scanned=messages_scanned,
        matches_found=matches_found,
        deleted_self=deleted_self,
        skipped_global=skipped_global,
        failed_actions=failed_actions,
        last_error_code=last_error_code[:64],
        updated_at=timezone.now(),
    )


@sync_to_async
def _finish_history_scan(scan_id: int, status: str, error_code: str = "") -> None:
    HistoryScan.objects.filter(pk=scan_id).update(
        status=status,
        cancel_requested=False,
        message_offset_id=0,
        last_error_code=error_code[:64],
        completed_at=timezone.now()
        if status
        in {
            HistoryScan.Status.COMPLETED,
            HistoryScan.Status.CANCELLED,
            HistoryScan.Status.FAILED,
        }
        else None,
        updated_at=timezone.now(),
    )


@sync_to_async
def _load_mini_app_state(
    account_id: int,
) -> tuple[dict[str, Any], list[MiniAppRuleSpec]]:
    account = TelegramAccount.objects.select_related("user").get(pk=account_id)
    policy, created = MiniAppPolicy.objects.get_or_create(
        account=account,
        defaults={
            "mode": MiniAppPolicy.Mode.ENFORCE,
            "block_bot": True,
            "notify_user": False,
            "notify_admin": False,
            "notify_operator": False,
        },
    )
    hard_values = {
        "mode": MiniAppPolicy.Mode.ENFORCE,
        "block_bot": True,
        "notify_user": False,
        "notify_admin": False,
        "notify_operator": False,
    }
    if not created and any(getattr(policy, key) != value for key, value in hard_values.items()):
        MiniAppPolicy.objects.filter(pk=policy.pk).update(**hard_values)
        for key, value in hard_values.items():
            setattr(policy, key, value)
    return (
        {
            "mode": policy.mode,
            "block_bot": policy.block_bot,
            "notify_user": policy.notify_user,
            "notify_operator": policy.notify_operator,
        },
        load_mini_app_rules(account),
    )


@sync_to_async
def _record_mini_app_event(
    account_id: int,
    rule: MiniAppRuleSpec | None,
    event_type: str,
    result: str,
    *,
    bot_id: int | None = None,
    bot_username: str = "",
    error_code: str = "",
) -> None:
    MiniAppAuditEvent.objects.create(
        account_id=account_id,
        rule_id=rule.id if rule else None,
        protection_rule_id=rule.protection_rule_id if rule else None,
        event_type=event_type,
        bot_id=bot_id,
        bot_username=bot_username[:64],
        result=result,
        error_code=error_code[:64],
    )


@sync_to_async
@transaction.atomic
def _notify_mini_app_operator(
    account_id: int,
    rule_id: int | None,
    event_type: str,
    bot_id: int | None,
    bot_username: str,
    result: str,
) -> bool:
    now = timezone.now()
    username = bot_username[:64].casefold()
    dedup_key = fingerprint(
        f"operator-miniapp:{account_id}:{rule_id or 0}:{event_type}:"
        f"{bot_id or 0}:{username}:{result}"
    )
    notification = (
        OperatorNotification.objects.select_for_update()
        .filter(dedup_key=dedup_key, processed_at__isnull=True)
        .first()
    )
    if notification is None:
        OperatorNotification.objects.create(
            account_id=account_id,
            rule_id=rule_id,
            event_type=event_type,
            bot_id=bot_id,
            bot_username=username,
            result=result,
            dedup_key=dedup_key,
            first_seen_at=now,
            last_seen_at=now,
        )
    else:
        notification.last_seen_at = now
        notification.repeat_count += 1
        notification.save(update_fields=["last_seen_at", "repeat_count"])
    return True


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
    if event.is_channel and bool(getattr(event, "is_group", False)):
        return "supergroup"
    if event.is_channel:
        return "channel"
    return "group"


def _rule_specs(items: list[Any]) -> list[RuleSpec]:
    specs: list[RuleSpec] = []
    for item in items:
        if isinstance(item, RuleSpec):
            specs.append(item)
        else:
            rule_id, phrase, mode = item
            specs.append(
                RuleSpec(
                    id=int(rule_id),
                    phrases=(str(phrase),),
                    mode=str(mode),
                    revision=1,
                    dialog_fingerprints=None,
                )
            )
    return specs


def _applicable_mini_app_rules(
    rules: list[MiniAppRuleSpec],
    direction: str,
    dialog_fingerprint: str,
    *,
    protection_rule_id: int = 0,
) -> list[MiniAppRuleSpec]:
    return [
        rule
        for rule in rules
        if rule.direction in {direction, ForbiddenRule.Direction.BOTH}
        and (
            rule.dialog_fingerprints is None
            or dialog_fingerprint in rule.dialog_fingerprints
        )
        and (
            not protection_rule_id
            or rule.protection_rule_id == protection_rule_id
        )
    ]


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
        self.next_dialog_sync_at = 0.0
        self.warned_mini_app_bot_ids: set[int] = set()
        self.history_scan_task: asyncio.Task[None] | None = None

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
            if self.history_scan_task and not self.history_scan_task.done():
                self.history_scan_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self.history_scan_task
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
        self.client.add_event_handler(self._handle_message, events.NewMessage())
        self.client.add_event_handler(self._handle_message, events.MessageEdited())
        self.client.add_event_handler(
            self._handle_attach_menu_update,
            events.Raw(types.UpdateAttachMenuBots),
        )
        await _set_account_state(int(self.account["id"]), TelegramAccount.Status.ACTIVE)
        while self.client.is_connected():
            await _set_account_state(int(self.account["id"]), TelegramAccount.Status.ACTIVE)
            await self._maybe_sync_dialogs()
            await self._sync_history_scan()
            await self._maybe_reconcile_mini_apps()
            try:
                await asyncio.wait_for(
                    asyncio.shield(self.client.disconnected),
                    timeout=settings.WORKER_HEARTBEAT_SECONDS,
                )
            except TimeoutError:
                continue

    async def _maybe_sync_dialogs(self) -> None:
        if not self.client:
            return
        now = asyncio.get_running_loop().time()
        if now < self.next_dialog_sync_at:
            return
        self.next_dialog_sync_at = now + settings.TELEGRAM_DIALOG_SYNC_SECONDS
        entries: list[dict[str, Any]] = []
        try:
            async for dialog in self.client.iter_dialogs():
                kind = self._history_chat_type(dialog)
                entries.append(
                    {
                        "peer_id": int(getattr(dialog, "id", 0)),
                        "label": (
                            "Избранное"
                            if kind == TelegramDialog.Kind.SAVED
                            else str(
                                getattr(dialog, "name", "")
                                or f"Диалог {len(entries) + 1}"
                            )
                        ),
                        "kind": kind,
                    }
                )
            await _sync_dialog_catalog(int(self.account["id"]), entries)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "telegram_dialog_sync_failed account_id=%s error=%s",
                self.account["id"],
                exc.__class__.__name__,
            )

    async def _sync_history_scan(self) -> None:
        if self.history_scan_task is not None:
            if not self.history_scan_task.done():
                return
            await self.history_scan_task
            self.history_scan_task = None
        scan = await _claim_history_scan(int(self.account["id"]))
        if scan is not None:
            self.history_scan_task = asyncio.create_task(
                self._run_history_scan(scan),
                name=f"history-scan-{scan['id']}",
            )

    async def _run_history_scan(self, scan: dict[str, Any]) -> None:
        scan_id = int(scan["id"])
        try:
            await self._scan_history(scan)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "history_scan_failed account_id=%s scan_id=%s error=%s",
                self.account["id"],
                scan_id,
                exc.__class__.__name__,
            )
            await _finish_history_scan(
                scan_id,
                HistoryScan.Status.FAILED,
                exc.__class__.__name__,
            )

    async def _scan_history(self, scan: dict[str, Any]) -> None:
        if not self.client or not self.user:
            raise RuntimeError("client_unavailable")
        scan_id = int(scan["id"])
        phase = str(scan["phase"])
        dialog_cursor = int(scan["dialogs_scanned"])
        message_offset_id = int(scan["message_offset_id"])
        messages_scanned = int(scan["messages_scanned"])
        matches_found = int(scan["matches_found"])
        deleted_self = int(scan["deleted_self"])
        skipped_global = int(scan["skipped_global"])
        failed_actions = int(scan["failed_actions"])
        rules_by_direction = {
            FilterEvent.Direction.INCOMING: _rule_specs(
                await _load_rules(self.user, FilterEvent.Direction.INCOMING)
            ),
            FilterEvent.Direction.OUTGOING: _rule_specs(
                await _load_rules(self.user, FilterEvent.Direction.OUTGOING)
            ),
        }
        _mini_app_policy, mini_app_rules = await _load_mini_app_state(
            int(self.account["id"])
        )
        # Unified protection rules are evaluated by the regular history matcher
        # below. Keep only unlinked legacy Mini App rules here to avoid duplicate
        # matches and to preserve preview semantics.
        mini_app_rules = [
            rule for rule in mini_app_rules if rule.protection_rule_id is None
        ]
        target_rule_id = int(scan.get("rule_id") or 0)
        target_revision = int(scan.get("rule_revision") or 0)
        if target_rule_id:
            current = next(
                (
                    item
                    for items in rules_by_direction.values()
                    for item in items
                    if item.id == target_rule_id and item.revision == target_revision
                ),
                None,
            )
            if current is None:
                await _finish_history_scan(scan_id, HistoryScan.Status.CANCELLED)
                return
        batch_count = 0
        dialog_index = 0
        async for dialog in self.client.iter_dialogs():
            if dialog_index < dialog_cursor:
                dialog_index += 1
                continue
            current_offset = message_offset_id if dialog_index == dialog_cursor else 0
            chat_type = self._history_chat_type(dialog)
            dialog_fingerprint = peer_fingerprint(
                int(self.account["id"]), int(getattr(dialog, "id", 0))
            )
            async for message in self.client.iter_messages(
                dialog.input_entity,
                offset_id=current_offset,
            ):
                messages_scanned += 1
                batch_count += 1
                direction = (
                    FilterEvent.Direction.OUTGOING
                    if bool(getattr(message, "out", False))
                    else FilterEvent.Direction.INCOMING
                )
                text = str(getattr(message, "raw_text", "") or "")
                if not text.startswith((MINI_APP_WARNING_PREFIX, FILTER_WARNING_PREFIX)):
                    mini_app_text = "\n".join(
                        candidate.value
                        for candidate in extract_candidates(
                            text, list(getattr(message, "entities", None) or [])
                        )
                    )
                    applicable_mini_app_rules = _applicable_mini_app_rules(
                        mini_app_rules,
                        direction,
                        dialog_fingerprint,
                        protection_rule_id=target_rule_id,
                    )
                    mini_app_matched = await self._enforce_mini_app_text(
                        message,
                        mini_app_text,
                        applicable_mini_app_rules,
                        source_entity=getattr(dialog, "entity", None),
                        is_outgoing=bool(getattr(message, "out", False)),
                    )
                    if mini_app_matched:
                        matches_found += 1
                        text = ""
                    candidates = extract_candidates(
                        text,
                        list(getattr(message, "entities", None) or []),
                    )
                    if getattr(message, "media", None):
                        candidates = [
                            TextCandidate(
                                "caption" if item.source == "body" else item.source,
                                item.value,
                            )
                            for item in candidates
                        ]
                    rules = [
                        rule
                        for rule in rules_by_direction[direction]
                        if (not target_rule_id or rule.id == target_rule_id)
                        and (
                            rule.dialog_fingerprints is None
                            or dialog_fingerprint in rule.dialog_fingerprints
                        )
                    ]
                    modes = {rule.id: rule.mode for rule in rules}
                    matched = find_matches(
                        candidates,
                        [
                            (rule.id, phrase)
                            for rule in rules
                            for phrase in rule.phrases
                        ],
                    )
                    if matched:
                        matches_found += 1
                        matched_modes = {
                            modes[item.rule_id]
                            for item in matched
                        }
                        if (
                            phase == HistoryScan.Phase.ENFORCE
                            and ForbiddenRule.Mode.ENFORCE in matched_modes
                        ):
                            if chat_type in {"channel", "supergroup"}:
                                skipped_global += 1
                            else:
                                try:
                                    await self._delete_with_retry(
                                        message, revoke=False
                                    )
                                except Exception as exc:
                                    failed_actions += 1
                                    scan["last_error_code"] = exc.__class__.__name__
                                else:
                                    deleted_self += 1
                current_offset = int(message.id)
                if batch_count >= settings.HISTORY_SCAN_BATCH_SIZE:
                    await _update_history_scan_progress(
                        scan_id,
                        dialogs_scanned=dialog_index,
                        message_offset_id=current_offset,
                        messages_scanned=messages_scanned,
                        matches_found=matches_found,
                        deleted_self=deleted_self,
                        skipped_global=skipped_global,
                        failed_actions=failed_actions,
                        last_error_code=str(scan.get("last_error_code", "")),
                    )
                    if await _history_scan_cancel_requested(scan_id):
                        await _finish_history_scan(
                            scan_id, HistoryScan.Status.CANCELLED
                        )
                        return
                    batch_count = 0
                    await asyncio.sleep(settings.HISTORY_SCAN_YIELD_SECONDS)
            dialog_index += 1
            message_offset_id = 0
            await _update_history_scan_progress(
                scan_id,
                dialogs_scanned=dialog_index,
                message_offset_id=0,
                messages_scanned=messages_scanned,
                matches_found=matches_found,
                deleted_self=deleted_self,
                skipped_global=skipped_global,
                failed_actions=failed_actions,
                last_error_code=str(scan.get("last_error_code", "")),
            )
            if await _history_scan_cancel_requested(scan_id):
                await _finish_history_scan(scan_id, HistoryScan.Status.CANCELLED)
                return
            await asyncio.sleep(settings.HISTORY_SCAN_YIELD_SECONDS)
        final_status = (
            HistoryScan.Status.AWAITING_CONFIRMATION
            if phase == HistoryScan.Phase.PREVIEW
            else HistoryScan.Status.COMPLETED
        )
        await _finish_history_scan(scan_id, final_status)

    def _history_chat_type(self, dialog: Any) -> str:
        if int(getattr(dialog, "id", 0)) == self.own_id:
            return "saved"
        if bool(getattr(dialog, "is_user", False)):
            return "private"
        if bool(getattr(dialog, "is_channel", False)):
            entity = getattr(dialog, "entity", None)
            return "supergroup" if bool(getattr(entity, "megagroup", False)) else "channel"
        return "group"

    async def _handle_message(self, event: Any) -> None:
        if not self.user:
            return
        is_outgoing = bool(
            getattr(event, "out", getattr(event.message, "out", False))
        )
        direction = (
            FilterEvent.Direction.OUTGOING
            if is_outgoing
            else FilterEvent.Direction.INCOMING
        )
        await _record_account_update(int(self.account["id"]), direction, "received")
        message_key = (int(event.chat_id or 0), int(event.message.id))
        if message_key in self.service_messages:
            return
        text = event.raw_text or ""
        if text.startswith((MINI_APP_WARNING_PREFIX, FILTER_WARNING_PREFIX)):
            return
        saved = int(event.chat_id or 0) == self.own_id
        if direction == FilterEvent.Direction.OUTGOING and is_status_command(text, saved):
            await self._show_status(event, message_key)
            return
        mini_app_text = "\n".join(
            candidate.value
            for candidate in extract_candidates(text, event.message.entities)
        )
        if await self._handle_mini_app_message(event, mini_app_text):
            return
        candidates = extract_candidates(text, event.message.entities)
        if event.message.media:
            candidates = [
                TextCandidate("caption" if item.source == "body" else item.source, item.value)
                for item in candidates
            ]
        chat_fingerprint = peer_fingerprint(
            int(self.account["id"]), int(event.chat_id or 0)
        )
        rules = [
            rule
            for rule in _rule_specs(await _load_rules(self.user, direction))
            if rule.dialog_fingerprints is None
            or chat_fingerprint in rule.dialog_fingerprints
        ]
        rule_modes = {rule.id: rule.mode for rule in rules}
        matches = find_matches(
            candidates,
            [(rule.id, phrase) for rule in rules for phrase in rule.phrases],
        )
        if not matches:
            await _record_account_update(int(self.account["id"]), direction, "no_match")
            return
        rule_ids = sorted({match.rule_id for match in matches})
        source = (
            "link_target"
            if any(item.source == "link_target" for item in matches)
            else matches[0].source
        )
        chat_type = _chat_type(event, self.own_id)
        modes = {rule_modes[rule_id] for rule_id in rule_ids}
        if ForbiddenRule.Mode.ENFORCE not in modes:
            result: str = (
                FilterEvent.Result.WARNED
                if ForbiddenRule.Mode.WARN in modes
                else FilterEvent.Result.DETECTED
            )
            await _record_event(
                self.user.pk,
                rule_ids,
                direction,
                source,
                chat_type,
                result,
            )
            await _record_account_update(int(self.account["id"]), direction, result)
            if result == FilterEvent.Result.WARNED:
                await self._notify_filter_warning(rule_ids)
            return
        try:
            result = await self._delete_matched_message(event, direction, chat_type)
        except Exception as exc:
            await _record_event(
                self.user.pk,
                rule_ids,
                direction,
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
            await _record_account_update(
                int(self.account["id"]), direction, FilterEvent.Result.FAILED
            )
        else:
            await _record_event(
                self.user.pk,
                rule_ids,
                direction,
                source,
                chat_type,
                result,
            )
            await _record_account_update(int(self.account["id"]), direction, result)

    async def _delete_matched_message(
        self, event: Any, direction: str, chat_type: str
    ) -> str:
        if direction == FilterEvent.Direction.OUTGOING:
            await self._delete_with_retry(event, revoke=True)
            return FilterEvent.Result.DELETED_ALL
        if chat_type not in {"channel", "supergroup"}:
            await self._delete_with_retry(event, revoke=False)
            return FilterEvent.Result.DELETED_SELF
        if not self.client:
            raise RuntimeError("client_unavailable")
        permissions = await self.client.get_permissions(event.chat_id, "me")
        if not (
            bool(getattr(permissions, "is_creator", False))
            or bool(getattr(permissions, "delete_messages", False))
        ):
            raise PermissionError("insufficient_delete_rights")
        await self._delete_with_retry(event, revoke=True)
        return FilterEvent.Result.DELETED_ALL

    async def _notify_filter_warning(self, rule_ids: list[int]) -> None:
        if not self.client:
            return
        ids = ", ".join(f"#{rule_id}" for rule_id in rule_ids)
        await self.client.send_message(
            "me", f"{FILTER_WARNING_PREFIX} {ids}: обнаружено совпадение."
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
            if user is not None:
                await self._disable_mini_app(policy, decision, target, user)
        await self._reconcile_forbidden_dialogs(rules)
        self.warned_mini_app_bot_ids.intersection_update(installed_ids)

    async def _reconcile_forbidden_dialogs(
        self, rules: list[MiniAppRuleSpec]
    ) -> None:
        if not self.client or not rules:
            return
        dialogs: list[Any] = [dialog async for dialog in self.client.iter_dialogs()]
        for dialog in dialogs:
            entity = getattr(dialog, "entity", None)
            if entity is None or int(getattr(dialog, "id", 0)) == self.own_id:
                continue
            is_bot = bool(getattr(entity, "bot", False))
            is_group_or_channel = bool(
                getattr(dialog, "is_group", False) or getattr(dialog, "is_channel", False)
            )
            if not is_bot and not is_group_or_channel:
                continue
            username = str(getattr(entity, "username", "") or "").casefold()
            title = str(
                getattr(dialog, "name", "")
                or getattr(entity, "title", "")
                or getattr(entity, "first_name", "")
                or ""
            )
            about = await self._entity_about(entity) if is_bot else ""
            target = MiniAppTarget(
                bot_id=int(getattr(entity, "id", 0)) or None,
                username=username,
                title=title,
            )
            decision = decide_mini_app_rule(rules, target, about)
            if not decision.denied or not decision.rule:
                continue
            await self._record_mini_app_detection(
                {}, decision, MiniAppAuditEvent.EventType.PROFILE_DETECTED, target
            )
            if is_bot:
                await self._block_bot(decision, target, entity)
            await self._delete_forbidden_dialog(decision, target, entity)
            if is_bot and about:
                await self._enforce_matching_profile_links(rules, about, entity)

    async def _enforce_matching_profile_links(
        self,
        rules: list[MiniAppRuleSpec],
        about: str,
        source_entity: Any,
    ) -> None:
        if not self.client:
            return
        source_id = int(getattr(source_entity, "id", 0))
        for username in sorted(extract_bot_usernames(about)):
            try:
                entity = await self.client.get_entity(username)
            except Exception:
                continue
            if not bool(getattr(entity, "bot", False)):
                continue
            target = MiniAppTarget(
                bot_id=int(getattr(entity, "id", 0)) or None,
                username=str(getattr(entity, "username", "") or username).casefold(),
                title=str(getattr(entity, "first_name", "") or ""),
            )
            if target.bot_id == source_id:
                continue
            decision = decide_mini_app_rule(rules, target)
            if not decision.denied or not decision.rule:
                continue
            await self._record_mini_app_detection(
                {}, decision, MiniAppAuditEvent.EventType.PROFILE_DETECTED, target
            )
            await self._disable_mini_app({}, decision, target, entity)

    async def _entity_about(self, entity: Any) -> str:
        if not self.client or not bool(getattr(entity, "bot", False)):
            return ""
        try:
            result = await self.client(functions.users.GetFullUserRequest(id=entity))
        except Exception:
            return ""
        return str(getattr(getattr(result, "full_user", None), "about", "") or "")

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
                decision.rule,
                MiniAppAuditEvent.EventType.MENU_DISABLED,
                MiniAppAuditEvent.Result.FAILED,
                bot_id=target.bot_id,
                bot_username=target.username,
                error_code=exc.__class__.__name__,
            )
        else:
            await _record_mini_app_event(
                int(self.account["id"]),
                decision.rule,
                MiniAppAuditEvent.EventType.MENU_DISABLED,
                MiniAppAuditEvent.Result.SUCCEEDED,
                bot_id=target.bot_id,
                bot_username=target.username,
            )
        await self._block_bot(decision, target, user)
        await self._delete_forbidden_dialog(decision, target, user)

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
                decision.rule,
                MiniAppAuditEvent.EventType.BOT_BLOCKED,
                MiniAppAuditEvent.Result.FAILED,
                bot_id=target.bot_id,
                bot_username=target.username,
                error_code=exc.__class__.__name__,
            )
        else:
            await _record_mini_app_event(
                int(self.account["id"]),
                decision.rule,
                MiniAppAuditEvent.EventType.BOT_BLOCKED,
                MiniAppAuditEvent.Result.SUCCEEDED,
                bot_id=target.bot_id,
                bot_username=target.username,
            )

    async def _delete_forbidden_dialog(
        self,
        decision: MiniAppRuleDecision,
        target: MiniAppTarget,
        entity: Any,
    ) -> None:
        if not self.client or not decision.rule:
            return
        try:
            await self.client.delete_dialog(entity, revoke=False)
        except Exception as exc:
            await _record_mini_app_event(
                int(self.account["id"]),
                decision.rule,
                MiniAppAuditEvent.EventType.DIALOG_DELETED,
                MiniAppAuditEvent.Result.FAILED,
                bot_id=target.bot_id,
                bot_username=target.username,
                error_code=exc.__class__.__name__,
            )
        else:
            await _record_mini_app_event(
                int(self.account["id"]),
                decision.rule,
                MiniAppAuditEvent.EventType.DIALOG_DELETED,
                MiniAppAuditEvent.Result.SUCCEEDED,
                bot_id=target.bot_id,
                bot_username=target.username,
            )

    async def _handle_mini_app_message(
        self, event: Any, text: str, is_outgoing: bool | None = None
    ) -> bool:
        if not self.client:
            return False
        if is_outgoing is None:
            is_outgoing = bool(
                getattr(event, "out", getattr(getattr(event, "message", None), "out", False))
            )
        try:
            _policy, rules = await _load_mini_app_state(int(self.account["id"]))
        except TelegramAccount.DoesNotExist:
            return False
        if not rules:
            return False
        direction = (
            ForbiddenRule.Direction.OUTGOING
            if is_outgoing
            else ForbiddenRule.Direction.INCOMING
        )
        chat_fingerprint = peer_fingerprint(
            int(self.account["id"]), int(getattr(event, "chat_id", 0) or 0)
        )
        rules = _applicable_mini_app_rules(rules, direction, chat_fingerprint)
        if not rules:
            return False
        source_entity: Any | None = None
        if not is_outgoing and bool(getattr(event, "is_private", False)):
            try:
                candidate = await event.get_chat()
            except Exception:
                candidate = None
            if candidate is not None and bool(getattr(candidate, "bot", False)):
                source_entity = candidate
        return await self._enforce_mini_app_text(
            event,
            text,
            rules,
            source_entity=source_entity,
            is_outgoing=is_outgoing,
        )

    async def _enforce_mini_app_text(
        self,
        message: Any,
        text: str,
        rules: list[MiniAppRuleSpec],
        *,
        source_entity: Any | None,
        is_outgoing: bool,
    ) -> bool:
        if not self.client or not rules:
            return False
        targets: list[tuple[MiniAppTarget, Any | None]] = []
        if source_entity is not None and bool(getattr(source_entity, "bot", False)):
            targets.append(
                (
                    MiniAppTarget(
                        bot_id=int(getattr(source_entity, "id", 0)) or None,
                        username=str(
                            getattr(source_entity, "username", "") or ""
                        ).casefold(),
                        title=str(getattr(source_entity, "first_name", "") or ""),
                    ),
                    source_entity,
                )
            )
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
            and bool(getattr(message, "is_private", False))
            and hasattr(message, "get_chat")
        ):
            try:
                chat = await message.get_chat()
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
        matches: list[tuple[MiniAppTarget, Any | None, MiniAppRuleDecision]] = []
        for target, entity in targets:
            decision = decide_mini_app_rule(rules, target, text)
            if not decision.denied or not decision.rule:
                continue
            matches.append((target, entity, decision))
        legacy_rules = [rule for rule in rules if rule.protection_rule_id is None]
        if legacy_rules:
            legacy_decision = decide_mini_app_rule(
                legacy_rules, MiniAppTarget(), text
            )
            if legacy_decision.denied and legacy_decision.rule:
                matches.append((MiniAppTarget(), None, legacy_decision))
        if not matches:
            return False
        if source_entity is not None and bool(getattr(source_entity, "bot", False)):
            source_id = int(getattr(source_entity, "id", 0))
            if not any(
                int(getattr(entity, "id", 0)) == source_id
                for _target, entity, _decision in matches
                if entity is not None
            ):
                source_target = MiniAppTarget(
                    bot_id=source_id or None,
                    username=str(
                        getattr(source_entity, "username", "") or ""
                    ).casefold(),
                    title=str(getattr(source_entity, "first_name", "") or ""),
                )
                matches.insert(0, (source_target, source_entity, matches[0][2]))
        for target, _entity, decision in matches:
            await self._record_mini_app_detection(
                {},
                decision,
                MiniAppAuditEvent.EventType.OUTGOING_DETECTED
                if is_outgoing
                else MiniAppAuditEvent.EventType.INCOMING_DETECTED,
                target,
            )
        primary_target, _primary_entity, primary_decision = matches[0]
        primary_rule = primary_decision.rule
        if primary_rule is None:
            return False
        try:
            await self._delete_with_retry(message, revoke=is_outgoing)
        except Exception as exc:
            await _record_mini_app_event(
                int(self.account["id"]),
                primary_rule,
                MiniAppAuditEvent.EventType.MESSAGE_DELETED,
                MiniAppAuditEvent.Result.FAILED,
                bot_id=primary_target.bot_id,
                bot_username=primary_target.username,
                error_code=exc.__class__.__name__,
            )
        else:
            await _record_mini_app_event(
                int(self.account["id"]),
                primary_rule,
                MiniAppAuditEvent.EventType.MESSAGE_DELETED,
                MiniAppAuditEvent.Result.SUCCEEDED,
                bot_id=primary_target.bot_id,
                bot_username=primary_target.username,
            )
        handled_entities: set[int] = set()
        for target, entity, decision in matches:
            entity_id = int(getattr(entity, "id", 0)) if entity is not None else 0
            if entity is not None and entity_id not in handled_entities:
                handled_entities.add(entity_id)
                await self._block_bot(decision, target, entity)
                await self._delete_forbidden_dialog(decision, target, entity)
        return True

    async def _record_mini_app_detection(
        self,
        _policy: dict[str, Any],
        decision: MiniAppRuleDecision,
        event_type: str,
        target: MiniAppTarget,
    ) -> None:
        if not decision.rule:
            return
        result = MiniAppAuditEvent.Result.SUCCEEDED
        await _record_mini_app_event(
            int(self.account["id"]),
            decision.rule,
            event_type,
            result,
            bot_id=target.bot_id,
            bot_username=target.username,
        )

    async def _delete_with_retry(self, event: Any, *, revoke: bool = True) -> None:
        for attempt in range(3):
            try:
                await event.delete(revoke=revoke)
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
def _auth_flow_states(flow_ids: list[int]) -> dict[int, str]:
    return dict(
        TelegramAuthFlow.objects.filter(pk__in=flow_ids).values_list("id", "state")
    )


@sync_to_async
def _expire_orphaned_auth_flows(active_flow_ids: list[int]) -> None:
    query = TelegramAuthFlow.objects.filter(
        state__in=[
            TelegramAuthFlow.State.QR_READY,
            TelegramAuthFlow.State.CODE_REQUIRED,
            TelegramAuthFlow.State.PASSWORD_REQUIRED,
            TelegramAuthFlow.State.VERIFYING,
        ]
    )
    if active_flow_ids:
        query = query.exclude(pk__in=active_flow_ids)
    query.update(
        state=TelegramAuthFlow.State.EXPIRED,
        encrypted_payload="",
        error_code="worker_restarted",
        updated_at=timezone.now(),
    )


@sync_to_async
def _get_flow(flow_id: int) -> TelegramAuthFlow:
    return TelegramAuthFlow.objects.select_related("user").get(pk=flow_id)


@sync_to_async
def _update_flow(flow_id: int, state: str, payload: str = "", error_code: str = "") -> None:
    TelegramAuthFlow.objects.filter(pk=flow_id).exclude(
        state__in=[
            TelegramAuthFlow.State.COMPLETE,
            TelegramAuthFlow.State.FAILED,
            TelegramAuthFlow.State.EXPIRED,
            TelegramAuthFlow.State.CANCELLED,
        ]
    ).update(
        state=state,
        encrypted_payload=payload,
        error_code=error_code[:64],
        updated_at=timezone.now(),
    )


@sync_to_async
def _consume_secret(flow_id: int) -> str:
    flow = TelegramAuthFlow.objects.select_related("user").get(pk=flow_id)
    if flow.state in {
        TelegramAuthFlow.State.COMPLETE,
        TelegramAuthFlow.State.FAILED,
        TelegramAuthFlow.State.EXPIRED,
        TelegramAuthFlow.State.CANCELLED,
    }:
        raise AuthFlowCancelled
    if not flow.encrypted_payload:
        return ""
    secret = decrypt_for_user(flow.user, flow.encrypted_payload)
    flow.encrypted_payload = ""
    flow.save(update_fields=["encrypted_payload", "updated_at"])
    return secret


@sync_to_async
def _assert_flow_active(flow_id: int) -> None:
    state = TelegramAuthFlow.objects.values_list("state", flat=True).get(pk=flow_id)
    if state in {
        TelegramAuthFlow.State.COMPLETE,
        TelegramAuthFlow.State.FAILED,
        TelegramAuthFlow.State.EXPIRED,
        TelegramAuthFlow.State.CANCELLED,
    }:
        raise AuthFlowCancelled


@sync_to_async
def _save_authorized_account(flow_id: int, client: TelegramClient, me: Any) -> None:
    flow = TelegramAuthFlow.objects.select_related("user").get(pk=flow_id)
    if flow.state in {
        TelegramAuthFlow.State.COMPLETE,
        TelegramAuthFlow.State.FAILED,
        TelegramAuthFlow.State.EXPIRED,
        TelegramAuthFlow.State.CANCELLED,
    }:
        raise AuthFlowCancelled
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
                await _assert_flow_active(flow_id)
            except SessionPasswordNeededError:
                await _assert_flow_active(flow_id)
                await _update_flow(flow_id, TelegramAuthFlow.State.PASSWORD_REQUIRED)
                password = await _wait_for_secret(flow_id, flow.expires_at)
                await client.sign_in(password=password)
        else:
            phone = await _decrypt(flow.user, flow.encrypted_payload)
            await _assert_flow_active(flow_id)
            sent = await client.send_code_request(phone)
            await _update_flow(flow_id, TelegramAuthFlow.State.CODE_REQUIRED)
            code = await _wait_for_secret(flow_id, flow.expires_at)
            try:
                await client.sign_in(phone, code, phone_code_hash=sent.phone_code_hash)
            except SessionPasswordNeededError:
                await _update_flow(flow_id, TelegramAuthFlow.State.PASSWORD_REQUIRED)
                password = await _wait_for_secret(flow_id, flow.expires_at)
                await client.sign_in(password=password)
        await _assert_flow_active(flow_id)
        me = await client.get_me()
        await _save_authorized_account(flow_id, client, me)
    except AuthFlowCancelled:
        pass
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
        states = await _auth_flow_states(list(self.auth_tasks))
        for flow_id, task in list(self.auth_tasks.items()):
            if task.done() or states.get(flow_id) in {
                TelegramAuthFlow.State.COMPLETE,
                TelegramAuthFlow.State.FAILED,
                TelegramAuthFlow.State.EXPIRED,
                TelegramAuthFlow.State.CANCELLED,
            }:
                if not task.done():
                    task.cancel()
                self.auth_tasks.pop(flow_id, None)
        await _expire_orphaned_auth_flows(list(self.auth_tasks))
        for flow_id in await _pending_auth_flows():
            if flow_id not in self.auth_tasks:
                self.auth_tasks[flow_id] = asyncio.create_task(process_auth_flow(flow_id))
