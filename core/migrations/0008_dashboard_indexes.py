from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0007_unified_protection_rules")]

    operations = [
        migrations.AddIndex(
            model_name="filterevent",
            index=models.Index(
                fields=["user", "-created_at"],
                name="filter_event_user_time",
            ),
        ),
        migrations.AddIndex(
            model_name="historyscan",
            index=models.Index(
                fields=["account", "-created_at"],
                name="history_account_time",
            ),
        ),
    ]
