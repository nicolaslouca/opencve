# Generated by Django 4.1 on 2023-03-11 09:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0003_remove_cve_json_alter_cve_cwes_alter_cve_summary_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="cve",
            name="cwes",
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name="cve",
            name="sources",
            field=models.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name="cve",
            name="vendors",
            field=models.JSONField(default=list),
        ),
    ]