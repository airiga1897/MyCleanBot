from __future__ import annotations

from datetime import timedelta
from functools import lru_cache
from typing import Any

from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db.models import Count, F, Q, Window
from django.db.models.functions import RowNumber
from django.utils import timezone

from core.models import FilterEvent, MiniAppAuditEvent, TelegramAccount


def _dashboard_key(user_id: int) -> str:
    return f"dashboard:v1:user:{user_id}"


def invalidate_dashboard(user_id: int) -> None:
    cache.delete(_dashboard_key(user_id))


@lru_cache(maxsize=128)
def user_id_for_account(account_id: int) -> int | None:
    return TelegramAccount.objects.filter(pk=account_id).values_list(
        "user_id", flat=True
    ).first()


def invalidate_account_dashboard(account_id: int) -> None:
    user_id = user_id_for_account(account_id)
    if user_id is not None:
        invalidate_dashboard(user_id)


def _filter_events(user: User, since: Any) -> tuple[list[dict[str, Any]], dict[str, int]]:
    queryset = user.filter_events.annotate(
        stat_total=Window(Count("id", filter=Q(created_at__gte=since))),
        stat_successful=Window(
            Count(
                "id",
                filter=Q(
                    created_at__gte=since,
                    result__in=[
                        FilterEvent.Result.DELETED_SELF,
                        FilterEvent.Result.DELETED_ALL,
                        FilterEvent.Result.DELETED,
                    ],
                ),
            )
        ),
        stat_failed=Window(
            Count(
                "id",
                filter=Q(created_at__gte=since, result=FilterEvent.Result.FAILED),
            )
        ),
    )[:50]
    rows = list(queryset)
    stats = {
        "total": int(rows[0].stat_total) if rows else 0,
        "successful": int(rows[0].stat_successful) if rows else 0,
        "failed": int(rows[0].stat_failed) if rows else 0,
    }
    return [
        {
            "created_at": event.created_at.isoformat(),
            "rule_ids": event.rule_ids,
            "direction": event.get_direction_display(),
            "source": event.get_source_display(),
            "chat_type": event.get_chat_type_display(),
            "result": event.get_result_display(),
        }
        for event in rows
    ], stats


def _mini_app_events(
    account: TelegramAccount, since: Any
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    queryset = account.mini_app_events.annotate(
        stat_total=Window(Count("id", filter=Q(created_at__gte=since))),
        stat_successful=Window(
            Count(
                "id",
                filter=Q(
                    created_at__gte=since,
                    result=MiniAppAuditEvent.Result.SUCCEEDED,
                ),
            )
        ),
        stat_failed=Window(
            Count(
                "id",
                filter=Q(
                    created_at__gte=since,
                    result=MiniAppAuditEvent.Result.FAILED,
                ),
            )
        ),
    )[:100]
    rows = list(queryset)
    stats = {
        "total": int(rows[0].stat_total) if rows else 0,
        "successful": int(rows[0].stat_successful) if rows else 0,
        "failed": int(rows[0].stat_failed) if rows else 0,
    }
    return [
        {
            "created_at": event.created_at.isoformat(),
            "rule_id": event.protection_rule_id,
            "legacy_rule_id": event.rule_id,
            "event_type": event.get_event_type_display(),
            "bot_id": event.bot_id,
            "bot_username": event.bot_username,
            "result": event.get_result_display(),
        }
        for event in rows
    ], stats


def dashboard_snapshot(user: User) -> dict[str, Any]:
    key = _dashboard_key(user.pk)
    cached = cache.get(key)
    if isinstance(cached, dict):
        return cached

    account, _created = TelegramAccount.objects.get_or_create(user=user)
    since = timezone.now() - timedelta(hours=24)
    events, stats = _filter_events(user, since)
    mini_events, mini_stats = _mini_app_events(account, since)
    history_scan = account.history_scans.first()
    latest_rule_scans = account.history_scans.filter(rule_id__isnull=False).annotate(
        latest_rank=Window(
            expression=RowNumber(),
            partition_by=[F("rule_id")],
            order_by=F("created_at").desc(),
        )
    ).filter(latest_rank=1)
    snapshot: dict[str, Any] = {
        "account": {
            "status": account.get_status_display(),
            "heartbeat": account.last_heartbeat_at.isoformat()
            if account.last_heartbeat_at
            else None,
            "last_update": account.last_update_at.isoformat()
            if account.last_update_at
            else None,
            "last_update_direction": account.last_update_direction,
            "last_update_result": account.last_update_result,
        },
        "stats": stats,
        "mini_app_stats": mini_stats,
        "history_scan": _scan_payload(history_scan, include_phase=True),
        "rule_scans": {
            str(scan.rule_id): _scan_payload(scan, include_phase=False)
            for scan in latest_rule_scans
            if scan.rule_id is not None
        },
        "events": events,
        "mini_app_events": mini_events,
    }
    cache.set(key, snapshot, timeout=settings.DASHBOARD_CACHE_TTL_SECONDS)
    return snapshot


def _scan_payload(scan: Any, *, include_phase: bool) -> dict[str, Any] | None:
    if scan is None:
        return None
    payload: dict[str, Any] = {
        "id": scan.pk,
        "status": scan.get_status_display(),
        "status_code": scan.status,
        "dialogs_scanned": scan.dialogs_scanned,
        "messages_scanned": scan.messages_scanned,
        "matches_found": scan.matches_found,
        "preview_matches": scan.preview_matches,
        "deleted_self": scan.deleted_self,
        "skipped_global": scan.skipped_global,
        "failed_actions": scan.failed_actions,
    }
    if include_phase:
        payload["phase"] = scan.get_phase_display()
    return payload
