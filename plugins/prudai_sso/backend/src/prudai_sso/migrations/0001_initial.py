from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("core", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="OrgWorkspaceLink",
            fields=[
                (
                    "org_id",
                    models.UUIDField(
                        default=__import__("uuid").uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("org_name", models.CharField(default="", max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "workspace",
                    models.OneToOneField(
                        on_delete=models.deletion.CASCADE,
                        related_name="prudai_org_link",
                        to="core.workspace",
                    ),
                ),
            ],
            options={
                "db_table": "prudai_sso_org_workspace_link",
            },
        ),
    ]
