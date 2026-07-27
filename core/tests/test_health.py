import pytest
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from core.models import WorkerHeartbeat

pytestmark = pytest.mark.django_db


def test_liveness_does_not_depend_on_worker(client: Client) -> None:
    assert client.get(reverse("livez")).status_code == 200


def test_health_requires_recent_worker_heartbeat(client: Client) -> None:
    assert client.get(reverse("healthz")).status_code == 503
    WorkerHeartbeat.objects.create(name="telegram-supervisor", state="running")
    assert client.get(reverse("healthz")).status_code == 200


def test_health_rejects_stale_worker_heartbeat(client: Client) -> None:
    heartbeat = WorkerHeartbeat.objects.create(name="telegram-supervisor", state="running")
    WorkerHeartbeat.objects.filter(pk=heartbeat.pk).update(
        updated_at=timezone.now() - timezone.timedelta(minutes=2)
    )
    assert client.get(reverse("healthz")).status_code == 503
