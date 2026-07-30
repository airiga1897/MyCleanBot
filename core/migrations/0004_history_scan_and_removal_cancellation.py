from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("core", "0003_bidirectional_filtering_and_operator_ux")]

    operations = [
        migrations.AlterField(
            model_name="ruleremovalrequest",
            name="status",
            field=models.CharField(
                choices=[
                    ("pending", "Ожидает"),
                    ("approved", "Одобрен"),
                    ("rejected", "Отклонён"),
                    ("cancelled", "Отменён пользователем"),
                ],
                default="pending",
                max_length=16,
            ),
        ),
        migrations.CreateModel(
            name="HistoryScan",
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
                (
                    "phase",
                    models.CharField(
                        choices=[
                            ("preview", "Предварительная проверка"),
                            ("enforce", "Удаление"),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "В очереди"),
                            ("running", "Проверяется"),
                            ("awaiting_confirmation", "Ожидает подтверждения"),
                            ("completed", "Завершено"),
                            ("cancelled", "Остановлено"),
                            ("failed", "Ошибка"),
                        ],
                        default="queued",
                        max_length=24,
                    ),
                ),
                ("cancel_requested", models.BooleanField(default=False)),
                ("dialogs_scanned", models.PositiveIntegerField(default=0)),
                ("message_offset_id", models.BigIntegerField(default=0)),
                ("messages_scanned", models.PositiveBigIntegerField(default=0)),
                ("matches_found", models.PositiveBigIntegerField(default=0)),
                ("preview_matches", models.PositiveBigIntegerField(default=0)),
                ("deleted_self", models.PositiveBigIntegerField(default=0)),
                ("skipped_global", models.PositiveBigIntegerField(default=0)),
                ("failed_actions", models.PositiveBigIntegerField(default=0)),
                ("last_error_code", models.CharField(blank=True, max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("confirmed_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "account",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="history_scans",
                        to="core.telegramaccount",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
                "constraints": [
                    models.UniqueConstraint(
                        condition=models.Q(
                            ("status__in", ["queued", "running", "awaiting_confirmation"])
                        ),
                        fields=("account",),
                        name="unique_active_history_scan",
                    )
                ],
            },
        ),
    ]
