from __future__ import annotations

import base64
import hashlib
from io import BytesIO
from typing import cast

import qrcode
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import transaction
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST
from django_ratelimit.decorators import ratelimit

from core.forms import AuthSecretForm, InviteRegistrationForm, PhoneAuthForm, RuleForm
from core.models import (
    DisconnectRequest,
    ForbiddenRule,
    Invitation,
    RuleRemovalRequest,
    TelegramAccount,
    TelegramAuthFlow,
)
from core.services.crypto import decrypt_for_user, encrypt_for_user
from core.services.rules import DuplicateRuleError, create_rule, display_rules


def _authenticated_user(request: HttpRequest) -> User:
    return cast(User, request.user)


@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    account, _ = TelegramAccount.objects.get_or_create(user=user)
    events = user.filter_events.all()[:50]
    pending_disconnect = user.disconnect_requests.filter(
        status=DisconnectRequest.Status.PENDING
    ).exists()
    return render(
        request,
        "core/dashboard.html",
        {
            "account": account,
            "rules": display_rules(user),
            "events": events,
            "pending_disconnect": pending_disconnect,
        },
    )


@ratelimit(key="ip", rate="5/h", block=True)
@transaction.atomic
def register_invite(request: HttpRequest, token: str) -> HttpResponse:
    digest = hashlib.sha256(token.encode()).hexdigest()
    invitation = get_object_or_404(Invitation.objects.select_for_update(), token_hash=digest)
    if not invitation.is_valid():
        raise Http404("Invitation is invalid or expired")
    if User.objects.filter(is_staff=False).count() >= 10:
        raise Http404("User limit reached")
    form = InviteRegistrationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        invitation.consumed_at = timezone.now()
        invitation.consumed_by = user
        invitation.save(update_fields=["consumed_at", "consumed_by"])
        TelegramAccount.objects.create(user=user)
        login(request, user)
        return redirect("dashboard")
    return render(request, "core/register.html", {"form": form})


@login_required
@require_http_methods(["GET", "POST"])
def add_rule(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    form = RuleForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            create_rule(user, form.cleaned_data["phrase"])
        except DuplicateRuleError:
            form.add_error("phrase", "Такое правило уже существует.")
        else:
            messages.success(request, "Правило добавлено и сразу активно.")
            return redirect("dashboard")
    return render(request, "core/rule_form.html", {"form": form})


@login_required
@require_POST
def request_rule_removal(request: HttpRequest, rule_id: int) -> HttpResponse:
    user = _authenticated_user(request)
    rule = get_object_or_404(ForbiddenRule, pk=rule_id, user=user)
    RuleRemovalRequest.objects.get_or_create(
        user=user, rule=rule, status=RuleRemovalRequest.Status.PENDING
    )
    messages.success(request, "Запрос на удаление отправлен администратору.")
    return redirect("dashboard")


@login_required
@require_POST
def request_disconnect(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    DisconnectRequest.objects.get_or_create(user=user, status=DisconnectRequest.Status.PENDING)
    messages.success(request, "Запрос на отключение отправлен администратору.")
    return redirect("dashboard")


@login_required
@require_POST
def start_qr_auth(request: HttpRequest) -> HttpResponse:
    TelegramAuthFlow.new(_authenticated_user(request), TelegramAuthFlow.Kind.QR)
    return redirect("telegram_auth")


@login_required
@require_http_methods(["GET", "POST"])
@ratelimit(key="user_or_ip", rate="5/h", block=True)
def start_phone_auth(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    form = PhoneAuthForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        payload = encrypt_for_user(user, form.cleaned_data["phone"])
        TelegramAuthFlow.new(user, TelegramAuthFlow.Kind.PHONE, payload)
        return redirect("telegram_auth")
    return render(request, "core/phone_auth.html", {"form": form})


@login_required
def telegram_auth(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    flow = user.telegram_auth_flows.order_by("-created_at").first()
    qr_data = ""
    if flow and flow.state == TelegramAuthFlow.State.QR_READY and flow.encrypted_payload:
        qr_url = decrypt_for_user(user, flow.encrypted_payload)
        image = qrcode.make(qr_url)
        output = BytesIO()
        image.save(output, format="PNG")
        qr_data = base64.b64encode(output.getvalue()).decode()
    secret_form = AuthSecretForm()
    return render(
        request,
        "core/telegram_auth.html",
        {"flow": flow, "qr_data": qr_data, "secret_form": secret_form},
    )


@login_required
@require_POST
@ratelimit(key="user_or_ip", rate="10/h", block=True)
def submit_auth_secret(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    flow = get_object_or_404(
        TelegramAuthFlow,
        user=user,
        state__in=[
            TelegramAuthFlow.State.CODE_REQUIRED,
            TelegramAuthFlow.State.PASSWORD_REQUIRED,
        ],
    )
    form = AuthSecretForm(request.POST)
    if form.is_valid():
        flow.encrypted_payload = encrypt_for_user(user, form.cleaned_data["secret"])
        flow.save(update_fields=["encrypted_payload", "updated_at"])
    return redirect("telegram_auth")


@staff_member_required
@require_http_methods(["GET", "POST"])
def create_invitation(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    invite_url = ""
    if request.method == "POST":
        connected_users = TelegramAccount.objects.exclude(
            status=TelegramAccount.Status.DISCONNECTED
        ).count()
        if connected_users >= 10:
            messages.error(request, "Достигнут лимит в 10 пользователей.")
        else:
            _invitation, token = Invitation.issue(user)
            invite_url = request.build_absolute_uri(
                reverse("register_invite", kwargs={"token": token})
            )
    return render(request, "core/create_invitation.html", {"invite_url": invite_url})
