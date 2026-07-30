from django.urls import path

from core import health, views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("dashboard/status/", views.dashboard_status, name="dashboard_status"),
    path("invite/<str:token>/", views.register_invite, name="register_invite"),
    path("rules/add/", views.add_rule, name="add_rule"),
    path(
        "rules/<int:rule_id>/remove-request/",
        views.request_rule_removal,
        name="request_rule_removal",
    ),
    path(
        "rules/<int:rule_id>/remove-request/cancel/",
        views.cancel_rule_removal,
        name="cancel_rule_removal",
    ),
    path("rules/<int:rule_id>/reveal/", views.reveal_rule, name="reveal_rule"),
    path("rules/<int:rule_id>/test/", views.test_rule, name="test_rule"),
    path("history/start/", views.start_history_scan, name="start_history_scan"),
    path(
        "history/<int:scan_id>/confirm/",
        views.confirm_history_scan,
        name="confirm_history_scan",
    ),
    path(
        "history/<int:scan_id>/cancel/",
        views.cancel_history_scan,
        name="cancel_history_scan",
    ),
    path("account/disconnect-request/", views.request_disconnect, name="request_disconnect"),
    path("mini-apps/", views.mini_app_settings, name="mini_app_settings"),
    path("mini-apps/rules/add/", views.add_mini_app_rule, name="add_mini_app_rule"),
    path(
        "mini-apps/rules/<int:rule_id>/delete/",
        views.delete_mini_app_rule,
        name="delete_mini_app_rule",
    ),
    path("telegram/auth/", views.telegram_auth, name="telegram_auth"),
    path("telegram/auth/qr/", views.start_qr_auth, name="start_qr_auth"),
    path("telegram/auth/phone/", views.start_phone_auth, name="start_phone_auth"),
    path("telegram/auth/secret/", views.submit_auth_secret, name="submit_auth_secret"),
    path("telegram/auth/cancel/", views.cancel_telegram_auth, name="cancel_telegram_auth"),
    path("operator/", views.operator_dashboard, name="operator_dashboard"),
    path("operator/invitations/new/", views.create_invitation, name="create_invitation"),
    path(
        "operator/invitations/<int:invitation_id>/revoke/",
        views.revoke_invitation,
        name="revoke_invitation",
    ),
    path(
        "operator/rule-removals/<int:request_id>/<str:decision>/",
        views.resolve_rule_removal,
        name="resolve_rule_removal",
    ),
    path(
        "operator/disconnects/<int:request_id>/<str:decision>/",
        views.resolve_disconnect,
        name="resolve_disconnect",
    ),
    path("livez", health.livez, name="livez"),
    path("healthz", health.healthz, name="healthz"),
]
