# Generated by Django 4.1 on 2023-03-15 18:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0006_alter_cwe_name"),
    ]

    operations = [
        migrations.AlterField(
            model_name="cwe",
            name="name",
            field=models.CharField(blank=True, max_length=256, null=True),
        ),
    ]