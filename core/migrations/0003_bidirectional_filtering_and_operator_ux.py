from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0002_mini_app_policies")]

    operations = [
        migrations.AddField(
            model_name="invitation",
            name="revoked_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="telegramaccount",
            name="last_update_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="telegramaccount",
            name="last_update_direction",
            field=models.CharField(blank=True, max_length=16),
        ),
        migrations.AddField(
            model_name="telegramaccount",
            name="last_update_result",
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.AddField(
            model_name="forbiddenrule",
            name="direction",
            field=models.CharField(
                choices=[
                    ("incoming", "Входящие"),
                    ("outgoing", "Исходящие"),
                    ("both", "Входящие и исходящие"),
                ],
                default="both",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="forbiddenrule",
            name="mode",
            field=models.CharField(
                choices=[
                    ("observe", "Наблюдение"),
                    ("warn", "Предупреждение"),
                    ("enforce", "Удаление"),
                ],
                default="enforce",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="forbiddenrule",
            name="is_locked",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="filterevent",
            name="direction",
            field=models.CharField(
                choices=[("incoming", "Входящее"), ("outgoing", "Исходящее")],
                default="outgoing",
                max_length=16,
            ),
        ),
        migrations.AlterField(
            model_name="filterevent",
            name="result",
            field=models.CharField(
                choices=[
                    ("detected", "Обнаружено"),
                    ("warned", "Предупреждение"),
                    ("deleted_self", "Удалено для себя"),
                    ("deleted_all", "Удалено для всех"),
                    ("deleted", "Удалено"),
                    ("failed", "Ошибка"),
                ],
                max_length=16,
            ),
        ),
        migrations.AlterField(
            model_name="telegramauthflow",
            name="state",
            field=models.CharField(
                choices=[
                    ("queued", "Ожидает worker"),
                    ("qr_ready", "QR готов"),
                    ("code_required", "Нужен код"),
                    ("password_required", "Нужен 2FA"),
                    ("verifying", "Проверка"),
                    ("complete", "Готово"),
                    ("failed", "Ошибка"),
                    ("expired", "Истёк"),
                    ("cancelled", "Отменено"),
                ],
                default="queued",
                max_length=24,
            ),
        ),
    ]
