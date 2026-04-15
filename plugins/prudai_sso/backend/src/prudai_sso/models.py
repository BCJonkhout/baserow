from __future__ import annotations

import uuid

from django.db import models


class OrgWorkspaceLink(models.Model):
    """Maps a PrudAI organization to the Baserow workspace that represents it.

    Written once per org on first SSO login; subsequent logins look up by
    ``org_id`` and add the user to the existing workspace silently.
    """

    org_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    workspace = models.OneToOneField(
        "core.Workspace",
        on_delete=models.CASCADE,
        related_name="prudai_org_link",
    )
    org_name = models.CharField(max_length=255, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "prudai_sso"
        db_table = "prudai_sso_org_workspace_link"
