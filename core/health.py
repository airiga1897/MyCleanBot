from __future__ import annotations

from datetime import timedelta

from django.db import connection
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_GET

from core.models import WorkerHeartbeat


@require_GET
def livez(_request: object) -> JsonResponse:
    return JsonResponse({"status": "ok"})


@require_GET
def healthz(_request: object) -> JsonResponse:
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        heartbeat = WorkerHeartbeat.objects.filter(name="telegram-supervisor").first()
        worker_ok = bool(
            heartbeat and heartbeat.updated_at >= timezone.now() - timedelta(seconds=45)
        )
    except Exception:
        return JsonResponse({"status": "unhealthy"}, status=503)
    status = 200 if worker_ok else 503
    return JsonResponse({"status": "ok" if worker_ok else "degraded"}, status=status)
