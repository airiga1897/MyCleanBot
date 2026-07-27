from __future__ import annotations

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


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
    confirm_locked = forms.BooleanField(
        label="Я понимаю, что удаление правила потребует подтверждения администратора"
    )


class PhoneAuthForm(forms.Form):
    phone = forms.CharField(label="Телефон", max_length=32)


class AuthSecretForm(forms.Form):
    secret = forms.CharField(label="Код или пароль 2FA", max_length=256)
