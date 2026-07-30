from __future__ import annotations

from django.http import HttpRequest

from core.models import OperatorNotification


def operator_notification_count(request: HttpRequest) -> dict[str, int]:
    user = request.user
    if not user.is_authenticated or not user.is_staff:
        return {"operator_notification_count": 0}
    return {
        "operator_notification_count": OperatorNotification.objects.filter(
            processed_at__isnull=True
        ).count()
    }
