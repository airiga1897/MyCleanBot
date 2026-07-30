from __future__ import annotations

import base64
import hashlib
from datetime import timedelta
from io import BytesIO
from typing import cast

import qrcode
from django.conf import settings
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Q
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST
from django_ratelimit.decorators import ratelimit

from core.forms import (
    AuthSecretForm,
    InviteRegistrationForm,
    MiniAppPolicyForm,
    MiniAppRuleForm,
    PhoneAuthForm,
    RuleForm,
    RuleTestForm,
)
from core.models import (
    DisconnectRequest,
    FilterEvent,
    ForbiddenRule,
    HistoryScan,
    Invitation,
    MiniAppPolicy,
    MiniAppRule,
    OperatorNotification,
    RuleChangeRequest,
    RuleRemovalRequest,
    TelegramAccount,
    TelegramAuthFlow,
)
from core.services.crypto import decrypt_for_user, encrypt_for_user
from core.services.matcher import normalize_text
from core.services.miniapps import (
    DuplicateMiniAppRuleError,
    create_mini_app_rule,
    display_mini_app_rules,
)
from core.services.rules import (
    DuplicateRuleError,
    PendingRuleChangeError,
    create_rule,
    queue_history_scan,
    resolve_rule_change,
    rule_form_initial,
    rule_label,
    update_rule,
)


def _authenticated_user(request: HttpRequest) -> User:
    return cast(User, request.user)


@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    account, _ = TelegramAccount.objects.get_or_create(user=user)
    rules = user.forbidden_rules.prefetch_related(
        "patterns", "dialog_scopes", "history_scans"
    ).all()
    rules_page = Paginator(rules, 20).get_page(request.GET.get("page"))
    rule_rows = [
        {
            "rule": rule,
            "label": rule_label(rule),
            "pattern_count": rule.patterns.count() or 1,
            "scope_count": rule.dialog_scopes.count(),
            "scan": rule.history_scans.first(),
        }
        for rule in rules_page.object_list
    ]
    pending_rule_requests = {
        item.rule_id: item.pk
        for item in user.rule_removal_requests.filter(
            status=RuleRemovalRequest.Status.PENDING,
            rule_id__isnull=False,
        )
    }
    history_scan = account.history_scans.first()
    events = user.filter_events.all()[:50]
    since = timezone.now() - timedelta(hours=24)
    event_stats = user.filter_events.filter(created_at__gte=since).aggregate(
        total=Count("id"),
        successful=Count(
            "id",
            filter=Q(
                result__in=[
                    FilterEvent.Result.DELETED_SELF,
                    FilterEvent.Result.DELETED_ALL,
                    FilterEvent.Result.DELETED,
                ]
            ),
        ),
        failed=Count("id", filter=Q(result=FilterEvent.Result.FAILED)),
    )
    pending_disconnect = user.disconnect_requests.filter(
        status=DisconnectRequest.Status.PENDING
    ).exists()
    return render(
        request,
        "core/dashboard.html",
        {
            "account": account,
            "rules_page": rules_page,
            "rule_rows": rule_rows,
            "pending_rule_ids": set(pending_rule_requests),
            "pending_rule_change_ids": set(
                user.rule_change_requests.filter(
                    status=RuleChangeRequest.Status.PENDING
                ).values_list("rule_id", flat=True)
            ),
            "history_scan": history_scan,
            "can_start_history_scan": bool(account.encrypted_session)
            and (
                history_scan is None
                or history_scan.status
                in {
                    HistoryScan.Status.COMPLETED,
                    HistoryScan.Status.CANCELLED,
                    HistoryScan.Status.FAILED,
                }
            ),
            "events": events,
            "event_stats": event_stats,
            "pending_disconnect": pending_disconnect,
        },
    )


@login_required
def dashboard_status(request: HttpRequest) -> JsonResponse:
    user = _authenticated_user(request)
    account, _ = TelegramAccount.objects.get_or_create(user=user)
    since = timezone.now() - timedelta(hours=24)
    events = list(user.filter_events.all()[:50])
    stats = user.filter_events.filter(created_at__gte=since).aggregate(
        total=Count("id"),
        successful=Count(
            "id",
            filter=Q(
                result__in=[
                    FilterEvent.Result.DELETED_SELF,
                    FilterEvent.Result.DELETED_ALL,
                    FilterEvent.Result.DELETED,
                ]
            ),
        ),
        failed=Count("id", filter=Q(result=FilterEvent.Result.FAILED)),
    )
    history_scan = account.history_scans.first()
    rule_scans: dict[int, HistoryScan] = {}
    for scan in account.history_scans.filter(rule_id__isnull=False):
        if scan.rule_id is not None:
            rule_scans.setdefault(scan.rule_id, scan)
    return JsonResponse(
        {
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
            "history_scan": (
                {
                    "id": history_scan.pk,
                    "phase": history_scan.get_phase_display(),
                    "status": history_scan.get_status_display(),
                    "status_code": history_scan.status,
                    "dialogs_scanned": history_scan.dialogs_scanned,
                    "messages_scanned": history_scan.messages_scanned,
                    "matches_found": history_scan.matches_found,
                    "preview_matches": history_scan.preview_matches,
                    "deleted_self": history_scan.deleted_self,
                    "skipped_global": history_scan.skipped_global,
                    "failed_actions": history_scan.failed_actions,
                }
                if history_scan
                else None
            ),
            "rule_scans": {
                str(rule_id): {
                    "status": scan.get_status_display(),
                    "status_code": scan.status,
                    "messages_scanned": scan.messages_scanned,
                    "matches_found": scan.matches_found,
                    "deleted_self": scan.deleted_self,
                    "failed_actions": scan.failed_actions,
                }
                for rule_id, scan in rule_scans.items()
            },
            "events": [
                {
                    "created_at": event.created_at.isoformat(),
                    "rule_ids": event.rule_ids,
                    "direction": event.get_direction_display(),
                    "source": event.get_source_display(),
                    "chat_type": event.get_chat_type_display(),
                    "result": event.get_result_display(),
                }
                for event in events
            ],
        }
    )


@ratelimit(key="ip", rate="5/h", block=True)
@transaction.atomic
def register_invite(request: HttpRequest, token: str) -> HttpResponse:
    digest = hashlib.sha256(token.encode()).hexdigest()
    invitation = get_object_or_404(Invitation.objects.select_for_update(), token_hash=digest)
    if not invitation.is_valid():
        raise Http404("Invitation is invalid or expired")
    if User.objects.filter(is_active=True).count() >= settings.MAX_TELEGRAM_ACCOUNTS:
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
    form = RuleForm(request.POST or None, user=user)
    if request.method == "POST" and form.is_valid():
        try:
            create_rule(
                user,
                form.cleaned_data["phrases"],
                label=form.cleaned_data["label"],
                direction=form.cleaned_data["direction"],
                mode=form.cleaned_data["mode"],
                is_locked=form.cleaned_data["is_locked"],
                dialog_ids=[
                    item.pk for item in form.cleaned_data["dialogs"]
                ],
                queue_history=True,
            )
        except DuplicateRuleError:
            form.add_error("phrases", "Такое правило уже существует.")
        else:
            messages.success(request, "Правило добавлено и сразу активно.")
            return redirect("dashboard")
    response = render(
        request,
        "core/rule_form.html",
        {"form": form, "heading": "Новое правило", "submit_label": "Сохранить и применить"},
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@login_required
@require_http_methods(["GET", "POST"])
def edit_rule(request: HttpRequest, rule_id: int) -> HttpResponse:
    user = _authenticated_user(request)
    rule = get_object_or_404(
        ForbiddenRule.objects.prefetch_related("patterns", "dialog_scopes"),
        pk=rule_id,
        user=user,
    )
    form = RuleForm(
        request.POST or None,
        user=user,
        initial=rule_form_initial(rule),
    )
    if request.method == "POST" and form.is_valid():
        try:
            _rule, change = update_rule(
                rule,
                label=form.cleaned_data["label"],
                phrases=form.cleaned_data["phrases"],
                direction=form.cleaned_data["direction"],
                mode=form.cleaned_data["mode"],
                is_locked=form.cleaned_data["is_locked"],
                dialog_ids=[item.pk for item in form.cleaned_data["dialogs"]],
            )
        except PendingRuleChangeError:
            form.add_error(None, "Сначала отмените или дождитесь решения по текущему запросу.")
        else:
            if change:
                messages.success(
                    request,
                    "Ослабление защищённого правила отправлено оператору. "
                    "Текущая версия продолжает действовать.",
                )
            else:
                messages.success(
                    request,
                    "Правило сохранено. Фоновая очистка его области поставлена в очередь.",
                )
            return redirect("dashboard")
    response = render(
        request,
        "core/rule_form.html",
        {
            "form": form,
            "heading": f"Редактирование правила #{rule.pk}",
            "submit_label": "Сохранить и применить",
        },
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@login_required
@require_POST
def cancel_rule_change(request: HttpRequest, rule_id: int) -> HttpResponse:
    user = _authenticated_user(request)
    change = get_object_or_404(
        RuleChangeRequest,
        rule_id=rule_id,
        user=user,
        status=RuleChangeRequest.Status.PENDING,
    )
    change.status = RuleChangeRequest.Status.CANCELLED
    change.resolved_at = timezone.now()
    change.save(update_fields=["status", "resolved_at"])
    messages.success(request, "Запрос на изменение правила отменён.")
    return redirect("dashboard")


@login_required
@require_POST
def request_rule_removal(request: HttpRequest, rule_id: int) -> HttpResponse:
    user = _authenticated_user(request)
    rule = get_object_or_404(ForbiddenRule, pk=rule_id, user=user)
    if rule.is_locked:
        RuleRemovalRequest.objects.get_or_create(
            user=user, rule=rule, status=RuleRemovalRequest.Status.PENDING
        )
        messages.success(request, "Запрос на удаление отправлен оператору.")
    else:
        rule.delete()
        messages.success(request, "Правило удалено.")
    return redirect("dashboard")


@login_required
@require_POST
def cancel_rule_removal(request: HttpRequest, rule_id: int) -> HttpResponse:
    user = _authenticated_user(request)
    removal = get_object_or_404(
        RuleRemovalRequest,
        user=user,
        rule_id=rule_id,
        status=RuleRemovalRequest.Status.PENDING,
    )
    removal.status = RuleRemovalRequest.Status.CANCELLED
    removal.resolved_at = timezone.now()
    removal.resolved_by = None
    removal.save(update_fields=["status", "resolved_at", "resolved_by"])
    messages.success(request, "Запрос на удаление правила отменён.")
    return redirect("dashboard")


@login_required
@require_POST
@transaction.atomic
def start_history_scan(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    account = get_object_or_404(
        TelegramAccount.objects.select_for_update(),
        user=user,
    )
    if not account.encrypted_session:
        messages.error(request, "Сначала подключите Telegram.")
        return redirect("dashboard")
    active = account.history_scans.filter(
        status__in=[
            HistoryScan.Status.QUEUED,
            HistoryScan.Status.RUNNING,
            HistoryScan.Status.AWAITING_CONFIRMATION,
        ]
    ).exists()
    if active:
        messages.error(request, "Проверка истории уже выполняется.")
        return redirect("dashboard")
    HistoryScan.objects.create(account=account, phase=HistoryScan.Phase.ENFORCE)
    messages.success(request, "Полная проверка истории поставлена в очередь.")
    return redirect("dashboard")


@login_required
@require_POST
@transaction.atomic
def confirm_history_scan(request: HttpRequest, scan_id: int) -> HttpResponse:
    user = _authenticated_user(request)
    scan = get_object_or_404(
        HistoryScan.objects.select_for_update(),
        pk=scan_id,
        account__user=user,
        phase=HistoryScan.Phase.PREVIEW,
        status=HistoryScan.Status.AWAITING_CONFIRMATION,
    )
    scan.preview_matches = scan.matches_found
    scan.phase = HistoryScan.Phase.ENFORCE
    scan.status = HistoryScan.Status.QUEUED
    scan.cancel_requested = False
    scan.dialogs_scanned = 0
    scan.message_offset_id = 0
    scan.messages_scanned = 0
    scan.matches_found = 0
    scan.deleted_self = 0
    scan.skipped_global = 0
    scan.failed_actions = 0
    scan.last_error_code = ""
    scan.confirmed_at = timezone.now()
    scan.started_at = None
    scan.completed_at = None
    scan.save()
    messages.success(request, "Удаление найденных совпадений поставлено в очередь.")
    return redirect("dashboard")


@login_required
@require_POST
@transaction.atomic
def cancel_history_scan(request: HttpRequest, scan_id: int) -> HttpResponse:
    user = _authenticated_user(request)
    scan = get_object_or_404(
        HistoryScan.objects.select_for_update(),
        pk=scan_id,
        account__user=user,
        status__in=[
            HistoryScan.Status.QUEUED,
            HistoryScan.Status.RUNNING,
            HistoryScan.Status.AWAITING_CONFIRMATION,
        ],
    )
    scan.cancel_requested = True
    if scan.status != HistoryScan.Status.RUNNING:
        scan.status = HistoryScan.Status.CANCELLED
        scan.completed_at = timezone.now()
    scan.save(update_fields=["cancel_requested", "status", "completed_at", "updated_at"])
    messages.success(request, "Остановка фоновой проверки запрошена.")
    return redirect("dashboard")


@login_required
@require_POST
def reveal_rule(request: HttpRequest, rule_id: int) -> JsonResponse:
    user = _authenticated_user(request)
    rule = get_object_or_404(
        ForbiddenRule.objects.prefetch_related("patterns"), pk=rule_id, user=user
    )
    patterns = list(rule.patterns.all())
    phrases = [
        decrypt_for_user(user, item.encrypted_phrase) for item in patterns
    ] or [decrypt_for_user(user, rule.encrypted_phrase)]
    response = JsonResponse({"phrase": "\n".join(phrases), "phrases": phrases})
    response.headers["Cache-Control"] = "no-store"
    return response


@login_required
@require_POST
def test_rule(request: HttpRequest, rule_id: int) -> JsonResponse:
    user = _authenticated_user(request)
    rule = get_object_or_404(
        ForbiddenRule.objects.prefetch_related("patterns"), pk=rule_id, user=user
    )
    form = RuleTestForm(request.POST)
    if not form.is_valid():
        return JsonResponse({"error": "Некорректный тестовый текст."}, status=400)
    patterns = list(rule.patterns.all())
    phrases = [
        normalize_text(decrypt_for_user(user, item.encrypted_phrase))
        for item in patterns
    ] or [normalize_text(decrypt_for_user(user, rule.encrypted_phrase))]
    normalized_text = normalize_text(form.cleaned_data["text"])
    matched = any(phrase in normalized_text for phrase in phrases)
    response = JsonResponse({"matched": matched})
    response.headers["Cache-Control"] = "no-store"
    return response


@login_required
@require_POST
def rerun_rule_history(request: HttpRequest, rule_id: int) -> HttpResponse:
    user = _authenticated_user(request)
    rule = get_object_or_404(ForbiddenRule, pk=rule_id, user=user, active=True)
    if rule.mode != ForbiddenRule.Mode.ENFORCE:
        messages.error(request, "Очистка истории доступна только для режима удаления.")
        return redirect("dashboard")
    queue_history_scan(rule)
    messages.success(request, "Повторная очистка истории поставлена в очередь.")
    return redirect("dashboard")


@login_required
@require_POST
def request_disconnect(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    DisconnectRequest.objects.get_or_create(user=user, status=DisconnectRequest.Status.PENDING)
    messages.success(request, "Запрос на отключение отправлен администратору.")
    return redirect("dashboard")


@login_required
@require_http_methods(["GET", "POST"])
def mini_app_settings(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    account, _ = TelegramAccount.objects.get_or_create(user=user)
    policy, _ = MiniAppPolicy.objects.get_or_create(account=account)
    policy_form = MiniAppPolicyForm(request.POST or None, instance=policy)
    if request.method == "POST" and policy_form.is_valid():
        policy_form.save()
        messages.success(request, "Политика Mini Apps обновлена.")
        return redirect("mini_app_settings")
    return render(
        request,
        "core/mini_app_settings.html",
        {
            "account": account,
            "policy": policy,
            "policy_form": policy_form,
            "rule_form": MiniAppRuleForm(),
            "mini_app_rules": display_mini_app_rules(account),
            "mini_app_events": account.mini_app_events.select_related("rule")[:100],
        },
    )


@login_required
@require_POST
def add_mini_app_rule(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    account, _ = TelegramAccount.objects.get_or_create(user=user)
    form = MiniAppRuleForm(request.POST)
    if form.is_valid():
        try:
            create_mini_app_rule(
                account,
                form.cleaned_data["list_type"],
                form.cleaned_data["match_type"],
                form.cleaned_data["value"],
            )
        except DuplicateMiniAppRuleError:
            messages.error(request, "Такое правило уже существует.")
        else:
            messages.success(request, "Правило Mini Apps добавлено.")
    else:
        messages.error(request, "Правило не добавлено: проверьте тип и значение.")
    return redirect("mini_app_settings")


@login_required
@require_POST
def delete_mini_app_rule(request: HttpRequest, rule_id: int) -> HttpResponse:
    user = _authenticated_user(request)
    rule = get_object_or_404(MiniAppRule, pk=rule_id, account__user=user)
    rule.delete()
    messages.success(request, "Правило Mini Apps удалено.")
    return redirect("mini_app_settings")


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
    if flow and flow.state == TelegramAuthFlow.State.COMPLETE:
        messages.success(request, "Telegram успешно подключён.")
        return redirect("dashboard")
    qr_data = ""
    if flow and flow.state == TelegramAuthFlow.State.QR_READY and flow.encrypted_payload:
        qr_url = decrypt_for_user(user, flow.encrypted_payload)
        image = qrcode.make(qr_url)
        output = BytesIO()
        image.save(output, format="PNG")
        qr_data = base64.b64encode(output.getvalue()).decode()
    secret_form = AuthSecretForm()
    error_messages = {
        "PhoneNumberInvalidError": "Номер телефона указан неверно.",
        "PhoneCodeInvalidError": "Одноразовый код неверен.",
        "PhoneCodeExpiredError": "Одноразовый код истёк.",
        "PasswordHashInvalidError": "Пароль 2FA неверен.",
        "account_already_bound": "Этот Telegram уже подключён к другому пользователю.",
    }
    response = render(
        request,
        "core/telegram_auth.html",
        {
            "flow": flow,
            "qr_data": qr_data,
            "secret_form": secret_form,
            "auth_error": error_messages.get(
                flow.error_code if flow else "", "Не удалось завершить подключение."
            ),
        },
    )
    if flow and (
        flow.state
        in {
            TelegramAuthFlow.State.QUEUED,
            TelegramAuthFlow.State.QR_READY,
            TelegramAuthFlow.State.VERIFYING,
        }
        or (
            flow.state
            in {
                TelegramAuthFlow.State.CODE_REQUIRED,
                TelegramAuthFlow.State.PASSWORD_REQUIRED,
            }
            and bool(flow.encrypted_payload)
        )
    ):
        response.headers["Refresh"] = "2"
    return response


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
        flow.state = TelegramAuthFlow.State.VERIFYING
        flow.save(update_fields=["encrypted_payload", "state", "updated_at"])
    return redirect("telegram_auth")


@login_required
@require_POST
def cancel_telegram_auth(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    user.telegram_auth_flows.exclude(
        state__in=[
            TelegramAuthFlow.State.COMPLETE,
            TelegramAuthFlow.State.FAILED,
            TelegramAuthFlow.State.EXPIRED,
            TelegramAuthFlow.State.CANCELLED,
        ]
    ).update(
        state=TelegramAuthFlow.State.CANCELLED,
        encrypted_payload="",
        updated_at=timezone.now(),
    )
    messages.success(request, "Попытка подключения отменена.")
    return redirect("telegram_auth")


@staff_member_required
def operator_dashboard(request: HttpRequest) -> HttpResponse:
    now = timezone.now()
    users = User.objects.select_related(
        "telegram_account", "invitation"
    ).order_by("username")
    invitations = Invitation.objects.select_related("created_by", "consumed_by").order_by(
        "-created_at"
    )[:50]
    active_invites = Invitation.objects.filter(
        consumed_at__isnull=True,
        revoked_at__isnull=True,
        expires_at__gt=now,
    ).count()
    occupied = users.filter(is_active=True).count()
    notifications = list(
        OperatorNotification.objects.filter(processed_at__isnull=True)
        .select_related("account__user", "rule")[:50]
    )
    return render(
        request,
        "core/operator_dashboard.html",
        {
            "users": users,
            "invitations": invitations,
            "occupied": occupied,
            "available": max(
                settings.MAX_TELEGRAM_ACCOUNTS - occupied - active_invites, 0
            ),
            "rule_requests": RuleRemovalRequest.objects.filter(
                status=RuleRemovalRequest.Status.PENDING
            ).select_related("user", "rule"),
            "rule_change_requests": RuleChangeRequest.objects.filter(
                status=RuleChangeRequest.Status.PENDING
            ).select_related("user", "rule"),
            "operator_notifications": notifications,
            "operator_notification_ids": ",".join(
                str(item.pk) for item in notifications
            ),
            "disconnect_requests": DisconnectRequest.objects.filter(
                status=DisconnectRequest.Status.PENDING
            ).select_related("user"),
            "now": now,
        },
    )


@staff_member_required
@require_http_methods(["GET", "POST"])
@transaction.atomic
def create_invitation(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    invite_url = ""
    invitation_id: int | None = None
    if request.method == "POST":
        now = timezone.now()
        occupied = len(
            list(
                User.objects.select_for_update()
                .filter(is_active=True)
                .values_list("id", flat=True)
            )
        )
        reserved = Invitation.objects.select_for_update().filter(
            consumed_at__isnull=True,
            revoked_at__isnull=True,
            expires_at__gt=now,
        ).count()
        if occupied + reserved >= settings.MAX_TELEGRAM_ACCOUNTS:
            messages.error(request, "Свободных мест и приглашений нет.")
        else:
            invitation, token = Invitation.issue(user)
            invitation_id = invitation.pk
            invite_url = request.build_absolute_uri(
                reverse("register_invite", kwargs={"token": token})
            )
    return render(
        request,
        "core/create_invitation.html",
        {"invite_url": invite_url, "invitation_id": invitation_id},
    )


@staff_member_required
@require_POST
def revoke_invitation(request: HttpRequest, invitation_id: int) -> HttpResponse:
    invitation = get_object_or_404(
        Invitation,
        pk=invitation_id,
        consumed_at__isnull=True,
    )
    if invitation.revoked_at is None:
        invitation.revoked_at = timezone.now()
        invitation.save(update_fields=["revoked_at"])
    messages.success(
        request,
        f"Приглашение #{invitation_id} отозвано. "
        "Выполните отдельную платформенную команду revoke VPN.",
    )
    return redirect("operator_dashboard")


@staff_member_required
@require_POST
def resolve_rule_change_request(
    request: HttpRequest, request_id: int, decision: str
) -> HttpResponse:
    change = get_object_or_404(
        RuleChangeRequest,
        pk=request_id,
        status=RuleChangeRequest.Status.PENDING,
    )
    if decision not in {"approve", "reject"}:
        raise Http404
    resolve_rule_change(
        change, _authenticated_user(request), decision == "approve"
    )
    messages.success(request, "Запрос изменения правила обработан.")
    return redirect("operator_dashboard")


@staff_member_required
@require_POST
def process_operator_notification(
    request: HttpRequest, notification_id: int
) -> HttpResponse:
    notification = get_object_or_404(
        OperatorNotification, pk=notification_id, processed_at__isnull=True
    )
    notification.processed_at = timezone.now()
    notification.processed_by = _authenticated_user(request)
    notification.save(update_fields=["processed_at", "processed_by"])
    return redirect("operator_dashboard")


@staff_member_required
@require_POST
def process_visible_notifications(request: HttpRequest) -> HttpResponse:
    raw_ids = request.POST.get("notification_ids", "")
    ids = [int(value) for value in raw_ids.split(",") if value.isdigit()][:50]
    OperatorNotification.objects.filter(
        pk__in=ids, processed_at__isnull=True
    ).update(
        processed_at=timezone.now(),
        processed_by=_authenticated_user(request),
    )
    messages.success(request, "Видимые оповещения отмечены обработанными.")
    return redirect("operator_dashboard")


@staff_member_required
@require_POST
@transaction.atomic
def block_user(request: HttpRequest, user_id: int) -> HttpResponse:
    user = get_object_or_404(
        User.objects.select_for_update(), pk=user_id, is_staff=False
    )
    user.is_active = False
    user.save(update_fields=["is_active"])
    TelegramAccount.objects.filter(user=user).update(desired_enabled=False)
    user.telegram_auth_flows.exclude(
        state__in=[
            TelegramAuthFlow.State.COMPLETE,
            TelegramAuthFlow.State.FAILED,
            TelegramAuthFlow.State.EXPIRED,
            TelegramAuthFlow.State.CANCELLED,
        ]
    ).update(
        state=TelegramAuthFlow.State.CANCELLED,
        encrypted_payload="",
        updated_at=timezone.now(),
    )
    HistoryScan.objects.filter(
        account__user=user,
        status__in=[HistoryScan.Status.QUEUED, HistoryScan.Status.RUNNING],
    ).update(cancel_requested=True)
    invitation_id = getattr(getattr(user, "invitation", None), "pk", None)
    suffix = f" для Invitation ID {invitation_id}" if invitation_id else ""
    messages.success(
        request,
        f"Пользователь заблокирован. Выполните отдельную платформенную команду revoke VPN{suffix}.",
    )
    return redirect("operator_dashboard")


@staff_member_required
@require_POST
@transaction.atomic
def resolve_rule_removal(request: HttpRequest, request_id: int, decision: str) -> HttpResponse:
    removal = get_object_or_404(
        RuleRemovalRequest.objects.select_for_update(),
        pk=request_id,
        status=RuleRemovalRequest.Status.PENDING,
    )
    if decision == "approve":
        if removal.rule is not None:
            removal.rule.delete()
            removal.rule = None
        removal.status = RuleRemovalRequest.Status.APPROVED
    elif decision == "reject":
        removal.status = RuleRemovalRequest.Status.REJECTED
    else:
        raise Http404
    removal.resolved_at = timezone.now()
    removal.resolved_by = _authenticated_user(request)
    removal.save(
        update_fields=["rule", "status", "resolved_at", "resolved_by"]
    )
    messages.success(request, "Запрос обработан.")
    return redirect("operator_dashboard")


@staff_member_required
@require_POST
@transaction.atomic
def resolve_disconnect(request: HttpRequest, request_id: int, decision: str) -> HttpResponse:
    item = get_object_or_404(
        DisconnectRequest.objects.select_for_update(),
        pk=request_id,
        status=DisconnectRequest.Status.PENDING,
    )
    if decision == "approve":
        TelegramAccount.objects.filter(user=item.user).update(desired_enabled=False)
        item.status = DisconnectRequest.Status.APPROVED
    elif decision == "reject":
        item.status = DisconnectRequest.Status.REJECTED
    else:
        raise Http404
    item.resolved_at = timezone.now()
    item.resolved_by = _authenticated_user(request)
    item.save(update_fields=["status", "resolved_at", "resolved_by"])
    messages.success(request, "Запрос обработан.")
    return redirect("operator_dashboard")
