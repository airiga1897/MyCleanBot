from collections.abc import Callable

from django.core.cache import cache
from django.db.models.signals import post_delete, post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone

from core.models import (
    FilterEvent,
    ForbiddenRule,
    HistoryScan,
    MiniAppAuditEvent,
    MiniAppRule,
    OperatorNotification,
    TelegramAccount,
)
from core.services.dashboard_cache import (
    invalidate_account_dashboard,
    invalidate_dashboard,
)


def _after_commit(callback: Callable[[], None]) -> None:
    # Invalidating before a surrounding transaction commits is safe: a rollback
    # merely causes one extra cache miss, while readers can never retain stale data.
    callback()


def _delete_operator_notification_count() -> None:
    cache.delete("operator-notifications:v1:open-count")


@receiver([post_save, post_delete], sender=FilterEvent)
def invalidate_filter_event_dashboard(
    sender: type[FilterEvent], instance: FilterEvent, **_kwargs: object
) -> None:
    del sender
    _after_commit(lambda: invalidate_dashboard(instance.user_id))


@receiver([post_save, post_delete], sender=MiniAppAuditEvent)
def invalidate_mini_app_dashboard(
    sender: type[MiniAppAuditEvent], instance: MiniAppAuditEvent, **_kwargs: object
) -> None:
    del sender
    _after_commit(lambda: invalidate_account_dashboard(instance.account_id))


@receiver([post_save, post_delete], sender=HistoryScan)
def invalidate_history_dashboard(
    sender: type[HistoryScan], instance: HistoryScan, **_kwargs: object
) -> None:
    del sender
    _after_commit(lambda: invalidate_account_dashboard(instance.account_id))


@receiver([post_save, post_delete], sender=TelegramAccount)
def invalidate_account_status_dashboard(
    sender: type[TelegramAccount], instance: TelegramAccount, **_kwargs: object
) -> None:
    del sender
    _after_commit(lambda: invalidate_dashboard(instance.user_id))


@receiver([post_save, post_delete], sender=OperatorNotification)
def invalidate_operator_notification_count(
    sender: type[OperatorNotification],
    instance: OperatorNotification,
    **_kwargs: object,
) -> None:
    del sender, instance
    _after_commit(_delete_operator_notification_count)


@receiver(pre_delete, sender=ForbiddenRule)
def cancel_rule_history_before_delete(
    sender: type[ForbiddenRule],
    instance: ForbiddenRule,
    **_kwargs: object,
) -> None:
    del sender
    instance.history_scans.filter(
        status__in=[
            HistoryScan.Status.QUEUED,
            HistoryScan.Status.RUNNING,
            HistoryScan.Status.AWAITING_CONFIRMATION,
        ]
    ).update(
        status=HistoryScan.Status.CANCELLED,
        cancel_requested=True,
        completed_at=timezone.now(),
        last_error_code="rule_deleted",
    )
    MiniAppRule.objects.filter(protection_rule=instance).update(active=False)
