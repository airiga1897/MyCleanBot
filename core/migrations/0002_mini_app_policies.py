from django.db import migrations, models
import django.db.models.deletion


def create_observe_policies(apps, schema_editor):
    TelegramAccount = apps.get_model("core", "TelegramAccount")
    MiniAppPolicy = apps.get_model("core", "MiniAppPolicy")
    MiniAppPolicy.objects.bulk_create(
        [
            MiniAppPolicy(account_id=account_id, mode="observe")
            for account_id in TelegramAccount.objects.values_list("id", flat=True)
        ],
        ignore_conflicts=True,
    )


class Migration(migrations.Migration):
    dependencies = [("core", "0001_initial")]

    operations = [
        migrations.CreateModel(
            name="MiniAppPolicy",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                (
                    "mode",
                    models.CharField(
                        choices=[
                            ("observe", "Наблюдение"),
                            ("warn", "Предупреждение"),
                            ("enforce", "Ограничение"),
                        ],
                        default="observe",
                        max_length=16,
                    ),
                ),
                ("block_bot", models.BooleanField(default=False)),
                ("notify_user", models.BooleanField(default=True)),
                ("notify_admin", models.BooleanField(default=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "account",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="mini_app_policy",
                        to="core.telegramaccount",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="MiniAppRule",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                (
                    "list_type",
                    models.CharField(
                        choices=[("allow", "Белый список"), ("deny", "Чёрный список")],
                        max_length=8,
                    ),
                ),
                (
                    "match_type",
                    models.CharField(
                        choices=[
                            ("bot_id", "Bot ID"),
                            ("username", "Username бота"),
                            ("title", "Название Mini App"),
                            ("keyword", "Ключевое слово"),
                            ("regex", "Регулярное выражение"),
                        ],
                        max_length=16,
                    ),
                ),
                ("bot_id", models.BigIntegerField(blank=True, null=True)),
                ("encrypted_pattern", models.TextField(blank=True)),
                ("pattern_fingerprint", models.CharField(max_length=64)),
                ("active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "account",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="mini_app_rules",
                        to="core.telegramaccount",
                    ),
                ),
            ],
            options={"ordering": ["list_type", "match_type", "-created_at"]},
        ),
        migrations.CreateModel(
            name="MiniAppAuditEvent",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                (
                    "event_type",
                    models.CharField(
                        choices=[
                            ("menu_detected", "Mini App обнаружено в меню"),
                            ("outgoing_detected", "Исходящее сообщение обнаружено"),
                            ("menu_disabled", "Mini App отключено в меню"),
                            ("bot_blocked", "Бот заблокирован"),
                            ("message_deleted", "Сообщение удалено"),
                            ("user_warned", "Пользователь предупреждён"),
                            ("admin_notified", "Администратор уведомлён"),
                        ],
                        max_length=32,
                    ),
                ),
                ("bot_id", models.BigIntegerField(blank=True, null=True)),
                ("bot_username", models.CharField(blank=True, max_length=64)),
                (
                    "result",
                    models.CharField(
                        choices=[
                            ("observed", "Обнаружено"),
                            ("warned", "Предупреждено"),
                            ("succeeded", "Выполнено"),
                            ("failed", "Ошибка"),
                            ("skipped", "Пропущено"),
                        ],
                        max_length=16,
                    ),
                ),
                ("error_code", models.CharField(blank=True, max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "account",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="mini_app_events",
                        to="core.telegramaccount",
                    ),
                ),
                (
                    "rule",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="events",
                        to="core.miniapprule",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddConstraint(
            model_name="miniapprule",
            constraint=models.UniqueConstraint(
                fields=("account", "list_type", "match_type", "pattern_fingerprint"),
                name="unique_account_mini_app_rule",
            ),
        ),
        migrations.AddIndex(
            model_name="miniappauditevent",
            index=models.Index(
                fields=["account", "-created_at"], name="miniapp_event_account_time"
            ),
        ),
        migrations.RunPython(create_observe_policies, migrations.RunPython.noop),
    ]
