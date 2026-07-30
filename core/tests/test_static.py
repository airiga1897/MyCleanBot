from django.conf import settings
from django.contrib.staticfiles import finders


def test_production_static_contract_includes_app_and_admin_assets() -> None:
    assert "whitenoise.middleware.WhiteNoiseMiddleware" in settings.MIDDLEWARE
    assert settings.STORAGES["staticfiles"]["BACKEND"] in {
        "django.contrib.staticfiles.storage.StaticFilesStorage",
        "whitenoise.storage.CompressedManifestStaticFilesStorage",
    }
    assert finders.find("app.css")
    assert finders.find("app.js")
    assert finders.find("admin/css/base.css")
