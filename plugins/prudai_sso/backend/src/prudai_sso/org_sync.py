"""Silent workspace ensure + membership add, called after OIDC sign-in."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from django.db import transaction

logger = logging.getLogger("prudai_sso.org_sync")

# Internal system user used to "own" workspaces created by the plugin. Users
# joining later become members, not admins, which keeps the first logger-in
# from gaining special control over shared org workspaces.
_SYSTEM_USER_EMAIL = "prudai-system@prudai.local"
_SYSTEM_USER_CACHE: dict[str, int] = {}


def _get_or_create_system_user():  # type: ignore[no-untyped-def]
    from django.contrib.auth import get_user_model

    User = get_user_model()
    cached_pk = _SYSTEM_USER_CACHE.get("pk")
    if cached_pk is not None:
        try:
            return User.objects.get(pk=cached_pk)
        except User.DoesNotExist:  # cache stale, fall through
            _SYSTEM_USER_CACHE.pop("pk", None)

    user, _ = User.objects.get_or_create(
        email=_SYSTEM_USER_EMAIL,
        defaults={
            "username": _SYSTEM_USER_EMAIL,
            "first_name": "PrudAI",
            "last_name": "System",
            "is_active": False,
        },
    )
    _SYSTEM_USER_CACHE["pk"] = user.pk
    return user


def _coerce_uuid(value: Any) -> uuid.UUID | None:
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    if isinstance(value, str):
        try:
            return uuid.UUID(value)
        except (TypeError, ValueError):
            return None
    return None


@transaction.atomic
def ensure_workspace_membership(user, claims: dict[str, Any]) -> None:
    """Look up or create the workspace for ``org_id`` and make ``user`` a member."""
    from baserow.core.handler import CoreHandler
    from baserow.core.models import Workspace, WorkspaceUser

    from prudai_sso.models import OrgWorkspaceLink

    org_id = _coerce_uuid(claims.get("organization_id"))
    if org_id is None:
        logger.debug("prudai_sso: no organization_id claim; skipping provisioning")
        return

    raw_name = claims.get("organization_name")
    org_name = (
        raw_name.strip()
        if isinstance(raw_name, str) and raw_name.strip()
        else f"Org {org_id}"
    )

    link = OrgWorkspaceLink.objects.select_related("workspace").filter(org_id=org_id).first()
    if link is None:
        system_user = _get_or_create_system_user()
        handler = CoreHandler()
        # ``create_workspace`` returns the WorkspaceUser for the creator (the
        # system user). We pull the workspace off it and drop the system user's
        # membership so only real org members end up in the workspace.
        creator_membership = handler.create_workspace(user=system_user, name=org_name)
        workspace = creator_membership.workspace
        WorkspaceUser.objects.filter(
            workspace=workspace, user=system_user
        ).delete()
        link = OrgWorkspaceLink.objects.create(
            org_id=org_id, workspace=workspace, org_name=org_name
        )
        logger.info(
            "prudai_sso: created workspace %s (%s) for org %s",
            workspace.id,
            org_name,
            org_id,
        )
    else:
        workspace = link.workspace
        if link.org_name != org_name:
            link.org_name = org_name
            link.save(update_fields=["org_name", "updated_at"])
            try:
                Workspace.objects.filter(id=workspace.id).update(name=org_name)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "prudai_sso: failed to rename workspace %s to %s",
                    workspace.id,
                    org_name,
                )

    already_member = WorkspaceUser.objects.filter(
        workspace=workspace, user=user
    ).exists()
    if already_member:
        return

    CoreHandler().add_user_to_workspace(workspace, user)
    logger.info(
        "prudai_sso: added user %s to workspace %s (org %s)",
        getattr(user, "email", user.pk),
        workspace.id,
        org_id,
    )
