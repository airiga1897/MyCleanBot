from django.db.models.signals import pre_delete
from django.dispatch import receiver
from django.utils import timezone

from core.models import ForbiddenRule, HistoryScan, MiniAppRule


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
