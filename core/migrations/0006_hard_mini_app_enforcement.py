import django.db.models.deletion
from django.db import migrations, models


def enable_hard_enforcement(apps, schema_editor):
    MiniAppPolicy = apps.get_model("core", "MiniAppPolicy")
    MiniAppRule = apps.get_model("core", "MiniAppRule")
    MiniAppRulePattern = apps.get_model("core", "MiniAppRulePattern")
    MiniAppPolicy.objects.update(
        mode="enforce",
        block_bot=True,
        notify_user=False,
        notify_admin=False,
        notify_operator=False,
    )
    MiniAppRulePattern.objects.bulk_create(
        [
            MiniAppRulePattern(
                rule_id=rule.id,
                encrypted_pattern=rule.encrypted_pattern,
                pattern_fingerprint=rule.pattern_fingerprint,
            )
            for rule in MiniAppRule.objects.exclude(encrypted_pattern="").iterator()
        ],
        ignore_conflicts=True,
    )


class Migration(migrations.Migration):
    dependencies = [("core", "0005_scoped_rules_operator_notifications")]

    operations = [
        migrations.CreateModel(
            name="MiniAppRulePattern",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("encrypted_pattern", models.TextField()),
                ("pattern_fingerprint", models.CharField(max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "rule",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="patterns",
                        to="core.miniapprule",
                    ),
                ),
            ],
            options={
                "ordering": ["id"],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("rule", "pattern_fingerprint"),
                        name="unique_mini_app_rule_pattern",
                    )
                ],
            },
        ),
        migrations.AlterField(
            model_name="miniapppolicy",
            name="mode",
            field=models.CharField(
                choices=[
                    ("observe", "Наблюдение"),
                    ("warn", "Предупреждение"),
                    ("enforce", "Ограничение"),
                ],
                default="enforce",
                max_length=16,
            ),
        ),
        migrations.AlterField(
            model_name="miniapppolicy",
            name="block_bot",
            field=models.BooleanField(default=True),
        ),
        migrations.AlterField(
            model_name="miniapppolicy",
            name="notify_user",
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name="miniappauditevent",
            name="event_type",
            field=models.CharField(
                choices=[
                    ("menu_detected", "Mini App обнаружено в меню"),
                    ("outgoing_detected", "Исходящее сообщение обнаружено"),
                    ("incoming_detected", "Входящее сообщение обнаружено"),
                    ("profile_detected", "Профиль или диалог обнаружен"),
                    ("menu_disabled", "Mini App отключено в меню"),
                    ("bot_blocked", "Бот заблокирован"),
                    ("message_deleted", "Сообщение удалено"),
                    ("dialog_deleted", "Диалог или история удалены"),
                    ("user_warned", "Пользователь предупреждён"),
                    ("admin_notified", "Администратор уведомлён"),
                ],
                max_length=32,
            ),
        ),
        migrations.AlterField(
            model_name="operatornotification",
            name="event_type",
            field=models.CharField(
                choices=[
                    ("menu_detected", "Mini App обнаружено в меню"),
                    ("outgoing_detected", "Исходящее сообщение обнаружено"),
                    ("incoming_detected", "Входящее сообщение обнаружено"),
                    ("profile_detected", "Профиль или диалог обнаружен"),
                    ("menu_disabled", "Mini App отключено в меню"),
                    ("bot_blocked", "Бот заблокирован"),
                    ("message_deleted", "Сообщение удалено"),
                    ("dialog_deleted", "Диалог или история удалены"),
                    ("user_warned", "Пользователь предупреждён"),
                    ("admin_notified", "Администратор уведомлён"),
                ],
                max_length=32,
            ),
        ),
        migrations.RunPython(enable_hard_enforcement, migrations.RunPython.noop),
    ]
