# Generated by Django 4.0.1 on 2022-08-16 08:58

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='integration',
            name='name',
            field=models.CharField(max_length=256, validators=[django.core.validators.RegexValidator(message='Special characters (except dash and underscore) are not accepted', regex='^[a-zA-Z0-9\\-_ ]+$')]),
        ),
    ]