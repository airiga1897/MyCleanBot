import hashlib

import django.db.models.deletion
from cryptography.fernet import Fernet
from django.conf import settings
from django.db import migrations, models


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _encrypt_for_user(apps, user_id: int, value: str) -> str:
    UserKey = apps.get_model("core", "UserKey")
    master = Fernet(settings.MASTER_ENCRYPTION_KEY.encode("utf-8"))
    key, _created = UserKey.objects.get_or_create(
        user_id=user_id,
        defaults={"encrypted_dek": master.encrypt(Fernet.generate_key()).decode("utf-8")},
    )
    user_key = master.decrypt(key.encrypted_dek.encode("utf-8"))
    return Fernet(user_key).encrypt(value.encode("utf-8")).decode("utf-8")


def unify_rules(apps, schema_editor):
    ForbiddenRule = apps.get_model("core", "ForbiddenRule")
    RulePattern = apps.get_model("core", "RulePattern")
    MiniAppRule = apps.get_model("core", "MiniAppRule")
    MiniAppRulePattern = apps.get_model("core", "MiniAppRulePattern")
    MiniAppAuditEvent = apps.get_model("core", "MiniAppAuditEvent")
    OperatorNotification = apps.get_model("core", "OperatorNotification")

    ForbiddenRule.objects.update(active=True, mode="enforce", is_locked=True)
    for legacy in MiniAppRule.objects.filter(protection_rule__isnull=True).iterator():
        # Legacy allow rules remain an internal rollback-compatible exception.
        # Converting one into a protected deny rule would invert its meaning.
        if legacy.list_type != "deny":
            continue
        encrypted_patterns = list(
            MiniAppRulePattern.objects.filter(rule_id=legacy.pk)
            .order_by("id")
            .values_list("encrypted_pattern", flat=True)
        )
        if not encrypted_patterns and legacy.encrypted_pattern:
            encrypted_patterns = [legacy.encrypted_pattern]
        if not encrypted_patterns:
            if legacy.bot_id is None:
                continue
            encrypted_patterns = [
                _encrypt_for_user(
                    apps,
                    legacy.account.user_id,
                    str(legacy.bot_id),
                )
            ]
        rule = ForbiddenRule.objects.create(
            user_id=legacy.account.user_id,
            encrypted_phrase=encrypted_patterns[0],
            phrase_fingerprint=_digest(f"unified-mini:{legacy.pk}"),
            direction="both",
            mode="enforce",
            is_locked=True,
            active=True,
        )
        RulePattern.objects.bulk_create(
            [
                RulePattern(
                    rule_id=rule.pk,
                    encrypted_phrase=value,
                    phrase_fingerprint=_digest(
                        f"unified-mini-pattern:{legacy.pk}:{index}"
                    ),
                )
                for index, value in enumerate(encrypted_patterns, start=1)
            ]
        )
        legacy.protection_rule_id = rule.pk
        legacy.save(update_fields=["protection_rule"])
        MiniAppAuditEvent.objects.filter(rule_id=legacy.pk).update(
            protection_rule_id=rule.pk
        )
        OperatorNotification.objects.filter(rule_id=legacy.pk).update(
            protection_rule_id=rule.pk
        )


class Migration(migrations.Migration):
    dependencies = [("core", "0006_hard_mini_app_enforcement")]

    operations = [
        migrations.AddField(
            model_name="miniappauditevent",
            name="protection_rule",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="mini_app_events",
                to="core.forbiddenrule",
            ),
        ),
        migrations.AddField(
            model_name="miniapprule",
            name="protection_rule",
            field=models.OneToOneField(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="legacy_mini_app_rule",
                to="core.forbiddenrule",
            ),
        ),
        migrations.AddField(
            model_name="operatornotification",
            name="protection_rule",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="operator_notifications",
                to="core.forbiddenrule",
            ),
        ),
        migrations.RunPython(unify_rules, migrations.RunPython.noop),
    ]
