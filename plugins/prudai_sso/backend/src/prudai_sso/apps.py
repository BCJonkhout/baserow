from django.apps import AppConfig


class PrudaiSsoConfig(AppConfig):
    name = "prudai_sso"
    verbose_name = "PrudAI SSO"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        # Import side-effects: monkey-patches into baserow_enterprise live here.
        from prudai_sso import patches  # noqa: F401

        patches.apply()
