from __future__ import annotations

from typing import Any

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from core.models import ForbiddenRule, MiniAppRule, TelegramDialog
from core.services.crypto import decrypt_for_user
from core.services.miniapps import normalize_rule_value


class InviteRegistrationForm(UserCreationForm):  # type: ignore[type-arg]
    class Meta:
        model = User
        fields = ("username",)


class TelegramDialogChoiceField(forms.ModelMultipleChoiceField):  # type: ignore[type-arg]
    def label_from_instance(self, obj: TelegramDialog) -> str:
        label = decrypt_for_user(obj.account.user, obj.encrypted_label)
        return f"{label} · {obj.get_kind_display()}"


class RuleForm(forms.Form):
    label = forms.CharField(
        label="Название правила",
        max_length=120,
        required=False,
    )
    phrases = forms.CharField(
        label="Запрещённые фразы — по одной на строку",
        max_length=4000,
        strip=True,
        widget=forms.Textarea(attrs={"rows": 6}),
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
    dialogs = TelegramDialogChoiceField(
        label="Чаты и каналы",
        queryset=TelegramDialog.objects.none(),
        required=False,
        help_text="Если ничего не выбрано, правило действует во всех чатах.",
        widget=forms.SelectMultiple(attrs={"size": 10}),
    )

    def __init__(self, *args: Any, user: User, **kwargs: Any) -> None:
        if args and args[0] is not None and "phrases" not in args[0] and "phrase" in args[0]:
            data = args[0].copy()
            data["phrases"] = args[0]["phrase"]
            args = (data, *args[1:])
        super().__init__(*args, **kwargs)
        dialogs_field = self.fields["dialogs"]
        if not isinstance(dialogs_field, forms.ModelMultipleChoiceField):
            raise TypeError("dialogs field is not a ModelMultipleChoiceField")
        dialogs_field.queryset = TelegramDialog.objects.filter(
            account__user=user,
            available=True,
        )

    def clean_phrases(self) -> str:
        phrases = [
            value.strip()
            for value in str(self.cleaned_data["phrases"]).splitlines()
            if value.strip()
        ]
        if not phrases:
            raise forms.ValidationError("Добавьте хотя бы одну фразу.")
        if len(phrases) > 50:
            raise forms.ValidationError("В одном правиле допускается не более 50 фраз.")
        if any(len(value) > 500 for value in phrases):
            raise forms.ValidationError("Одна фраза не должна превышать 500 символов.")
        return "\n".join(phrases)


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


class MiniAppRuleForm(forms.Form):
    value = forms.CharField(
        label="Запрещённые фразы — по одной в строке",
        max_length=2000,
        strip=True,
        widget=forms.Textarea(attrs={"rows": 5}),
    )

    def clean_value(self) -> str:
        values = list(
            dict.fromkeys(
                line.strip()
                for line in str(self.cleaned_data["value"]).splitlines()
                if line.strip()
            )
        )
        if not values:
            raise forms.ValidationError("Добавьте хотя бы одну фразу.")
        if len(values) > 20:
            raise forms.ValidationError("В одном правиле можно указать не более 20 фраз.")
        for value in values:
            normalize_rule_value(MiniAppRule.MatchType.KEYWORD, value)
        return "\n".join(values)
