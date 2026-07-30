from __future__ import annotations

from typing import Any

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from core.models import ForbiddenRule, MiniAppPolicy, MiniAppRule, TelegramDialog
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


class MiniAppPolicyForm(forms.ModelForm):  # type: ignore[type-arg]
    confirm_enforce = forms.BooleanField(
        required=False,
        label=(
            "Я понимаю ограничения Telegram API и подтверждаю включение режима ограничения"
        ),
    )

    class Meta:
        model = MiniAppPolicy
        fields = ("mode", "block_bot", "notify_user", "notify_operator")
        labels = {
            "mode": "Режим",
            "block_bot": "Блокировать связанного бота в режиме ограничения",
            "notify_user": "Уведомлять пользователя в «Избранном»",
            "notify_operator": "Уведомлять оператора в кабинете",
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
            and not cleaned.get("notify_operator")
        ):
            self.add_error("mode", "Для режима предупреждения выберите канал уведомления.")
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
