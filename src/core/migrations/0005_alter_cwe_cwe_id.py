# Generated by Django 4.1 on 2023-03-15 18:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0004_alter_cve_cwes_alter_cve_sources_alter_cve_vendors"),
    ]

    operations = [
        migrations.AlterField(
            model_name="cwe",
            name="cwe_id",
            field=models.CharField(max_length=16, unique=True),
        ),
    ]
