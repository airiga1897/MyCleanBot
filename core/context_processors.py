from __future__ import annotations

from django.core.cache import cache
from django.http import HttpRequest

from core.models import OperatorNotification


def operator_notification_count(request: HttpRequest) -> dict[str, int]:
    user = request.user
    if not user.is_authenticated or not user.is_staff:
        return {"operator_notification_count": 0}
    key = "operator-notifications:v1:open-count"
    count = cache.get(key)
    if not isinstance(count, int):
        count = OperatorNotification.objects.filter(processed_at__isnull=True).count()
        cache.set(key, count, timeout=15)
    return {"operator_notification_count": count}
