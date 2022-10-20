# Generated by Django 4.1.1 on 2022-10-20 06:15

import datetime
from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='accountcustom',
            name='account_created',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 20, 6, 15, 6, 930482, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='accountcustom',
            name='account_updated',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 20, 6, 15, 6, 930588, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='accountcustom',
            name='id',
            field=models.UUIDField(default=uuid.UUID('85f63c26-e2c0-47c7-961d-997c2bc7e2cf'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
    ]
