"""Monkey-patches applied at Django app ``ready()`` time.

Two concerns:

1. **License bypass.** Baserow Enterprise gates SSO behind a paid license via
   ``baserow_enterprise.sso.utils.is_sso_feature_active``. We're running this
   self-hosted for an internal use case, so force it true.

2. **Silent org-to-workspace provisioning.** On successful OIDC login, read
   the ``organization_id`` + ``organization_name`` claims from the ID token,
   ensure a matching Baserow workspace exists, and add the user to it as a
   member. No invitations, no emails, no notifications beyond Baserow's own
   in-app websocket presence signal.
"""

from __future__ import annotations

import contextvars
import logging
from typing import Any

logger = logging.getLogger("prudai_sso.patches")

# Stashes the decoded ID-token claims for the duration of a single OIDC
# callback request. Populated inside the patched ``get_user_info_from_id_token``
# and consumed by the patched ``get_or_create_user_and_sign_in``.
_current_id_token_claims: contextvars.ContextVar[dict[str, Any] | None] = (
    contextvars.ContextVar("prudai_sso_id_token_claims", default=None)
)


def _always_true() -> bool:
    return True


def _apply_license_bypass() -> None:
    from baserow_enterprise.sso import utils as sso_utils

    sso_utils.is_sso_feature_active = _always_true
    # Also rebind the symbol at every import site so bound references flip too.
    try:
        from baserow_enterprise.api.sso.oauth2 import views as oauth2_views

        oauth2_views.is_sso_feature_active = _always_true
    except ImportError:
        pass
    try:
        from baserow_enterprise.api.sso.saml import views as saml_views

        saml_views.is_sso_feature_active = _always_true
    except ImportError:
        pass
    try:
        from baserow_enterprise.sso.saml import auth_provider_types as saml_providers

        saml_providers.is_sso_feature_active = _always_true
    except ImportError:
        pass
    try:
        from baserow_enterprise.sso.oauth2 import auth_provider_types as oauth2_providers

        oauth2_providers.is_sso_feature_active = _always_true
    except ImportError:
        pass
    logger.info("prudai_sso: license bypass applied")


def _patch_id_token_capture() -> None:
    """Intercept the OIDC id-token decoder so we can read custom claims later.

    The upstream method returns ``(email, name)`` and discards the rest of the
    decoded payload. We wrap it to cache the full payload in a ContextVar so
    the downstream ``get_or_create_user_and_sign_in`` hook can act on the org
    claims without re-decoding or re-fetching anything.
    """
    from baserow_enterprise.sso.oauth2 import auth_provider_types as mod

    original_decode = mod.OpenIdConnectAuthProviderType.get_user_info_from_id_token

    def patched(self, instance, id_token):  # type: ignore[no-untyped-def]
        import jwt

        try:
            key = self._get_verifying_key(instance, id_token)
            decoded = jwt.decode(
                id_token,
                key=key,
                algorithms=["RS256"],
                audience=instance.client_id,
                issuer=self.get_issuer(instance),
            )
            _current_id_token_claims.set(decoded)
        except Exception:  # noqa: BLE001
            # Never let claim-stash failures break login — fall back to upstream.
            logger.exception("prudai_sso: failed to stash id-token claims")
        return original_decode(self, instance, id_token)

    mod.OpenIdConnectAuthProviderType.get_user_info_from_id_token = patched
    logger.info("prudai_sso: id-token claim capture installed")


def _patch_user_sign_in() -> None:
    """Hook the sign-in path to ensure workspace membership from org claims."""
    from baserow.core.auth_provider import auth_provider_types as mod

    original = mod.AuthProviderType.get_or_create_user_and_sign_in

    def patched(self, auth_provider, user_info):  # type: ignore[no-untyped-def]
        user, created = original(self, auth_provider, user_info)
        claims = _current_id_token_claims.get()
        if claims:
            try:
                from prudai_sso.org_sync import ensure_workspace_membership

                ensure_workspace_membership(user, claims)
            except Exception:  # noqa: BLE001
                # Non-fatal: login still succeeds even if provisioning errors.
                logger.exception(
                    "prudai_sso: failed to ensure workspace membership for %s",
                    getattr(user, "email", "<unknown>"),
                )
            finally:
                _current_id_token_claims.set(None)
        return user, created

    mod.AuthProviderType.get_or_create_user_and_sign_in = patched
    logger.info("prudai_sso: workspace provisioning hook installed")


def apply() -> None:
    _apply_license_bypass()
    _patch_id_token_capture()
    _patch_user_sign_in()
