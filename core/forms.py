from __future__ import annotations

from typing import Any

from django import forms
from django.conf import settings
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from core.models import ForbiddenRule, MiniAppPolicy, MiniAppRule
from core.services.miniapps import normalize_rule_value


class InviteRegistrationForm(UserCreationForm):  # type: ignore[type-arg]
    class Meta:
        model = User
        fields = ("username",)


class RuleForm(forms.Form):
    phrase = forms.CharField(
        label="Запрещённая фраза",
        max_length=500,
        strip=True,
        widget=forms.Textarea(attrs={"rows": 3}),
    )
    direction = forms.ChoiceField(
        label="Применять к сообщениям",
        choices=ForbiddenRule.Direction.choices,
        initial=ForbiddenRule.Direction.BOTH,
    )
    mode = forms.ChoiceField(
        label="Режим",
        choices=ForbiddenRule.Mode.choices,
        initial=ForbiddenRule.Mode.ENFORCE,
    )
    is_locked = forms.BooleanField(
        required=False,
        initial=True,
        label="Защитить правило: удаление потребует подтверждения оператора",
    )


class RuleTestForm(forms.Form):
    text = forms.CharField(label="Тестовый текст", max_length=2000, strip=False)


class PhoneAuthForm(forms.Form):
    phone = forms.CharField(label="Телефон", max_length=32)


class AuthSecretForm(forms.Form):
    secret = forms.CharField(
        label="Код или пароль 2FA",
        max_length=256,
        widget=forms.PasswordInput(attrs={"autocomplete": "one-time-code"}),
    )


class MiniAppPolicyForm(forms.ModelForm):  # type: ignore[type-arg]
    confirm_enforce = forms.BooleanField(
        required=False,
        label=(
            "Я понимаю ограничения Telegram API и подтверждаю включение режима ограничения"
        ),
    )

    class Meta:
        model = MiniAppPolicy
        fields = ("mode", "block_bot", "notify_user", "notify_admin")
        labels = {
            "mode": "Режим",
            "block_bot": "Блокировать связанного бота в режиме ограничения",
            "notify_user": "Уведомлять пользователя в «Избранном»",
            "notify_admin": "Уведомлять администратора минимальным email-событием",
        }

    def clean(self) -> dict[str, Any]:
        cleaned = super().clean() or {}
        if (
            cleaned.get("mode") == MiniAppPolicy.Mode.ENFORCE
            and not cleaned.get("confirm_enforce")
        ):
            self.add_error("confirm_enforce", "Нужно отдельное явное подтверждение.")
        if (
            cleaned.get("mode") == MiniAppPolicy.Mode.WARN
            and not cleaned.get("notify_user")
            and not cleaned.get("notify_admin")
        ):
            self.add_error("mode", "Для режима предупреждения выберите канал уведомления.")
        if cleaned.get("notify_admin") and not settings.ADMINS:
            self.add_error(
                "notify_admin",
                "Сначала оператор должен настроить MINI_APP_ADMIN_EMAILS.",
            )
        return cleaned


class MiniAppRuleForm(forms.Form):
    list_type = forms.ChoiceField(label="Список", choices=MiniAppRule.ListType.choices)
    match_type = forms.ChoiceField(label="Тип совпадения", choices=MiniAppRule.MatchType.choices)
    value = forms.CharField(label="Значение", max_length=200, strip=True)

    def clean_value(self) -> str:
        value = str(self.cleaned_data["value"])
        match_type = self.cleaned_data.get("match_type")
        if match_type:
            normalize_rule_value(match_type, value)
        return value
