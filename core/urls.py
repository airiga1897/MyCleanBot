from django.urls import path

from core import health, views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("invite/<str:token>/", views.register_invite, name="register_invite"),
    path("rules/add/", views.add_rule, name="add_rule"),
    path(
        "rules/<int:rule_id>/remove-request/",
        views.request_rule_removal,
        name="request_rule_removal",
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
    path("operator/invitations/new/", views.create_invitation, name="create_invitation"),
    path("livez", health.livez, name="livez"),
    path("healthz", health.healthz, name="healthz"),
]
