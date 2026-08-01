from django.db import migrations, models


EVENT_CHOICES = [
    ("menu_detected", "Mini App обнаружено в меню"),
    ("outgoing_detected", "Исходящее сообщение обнаружено"),
    ("incoming_detected", "Входящее сообщение обнаружено"),
    ("profile_detected", "Профиль или диалог обнаружен"),
    ("app_discovered", "Приложение обнаружено в каталоге Telegram"),
    ("menu_disabled", "Mini App отключено в меню"),
    ("bot_blocked", "Бот заблокирован"),
    ("message_deleted", "Сообщение удалено"),
    ("dialog_deleted", "Диалог или история удалены"),
    ("user_warned", "Пользователь предупреждён"),
    ("admin_notified", "Администратор уведомлён"),
]


class Migration(migrations.Migration):
    dependencies = [("core", "0008_dashboard_indexes")]

    operations = [
        migrations.AlterField(
            model_name="miniappauditevent",
            name="event_type",
            field=models.CharField(choices=EVENT_CHOICES, max_length=32),
        ),
        migrations.AlterField(
            model_name="operatornotification",
            name="event_type",
            field=models.CharField(choices=EVENT_CHOICES, max_length=32),
        ),
    ]
