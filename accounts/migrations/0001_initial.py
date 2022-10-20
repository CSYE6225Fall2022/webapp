# Generated by Django 4.1.1 on 2022-10-20 06:15

import datetime
from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AccountCustom',
            fields=[
                ('id', models.UUIDField(default=uuid.UUID('f9d51c3a-c37d-4801-af50-4f70c39a1080'), editable=False, primary_key=True, serialize=False, unique=True)),
                ('first_name', models.CharField(max_length=25)),
                ('last_name', models.CharField(max_length=100)),
                ('password', models.CharField(max_length=150)),
                ('username', models.CharField(max_length=100, unique=True)),
                ('account_created', models.DateTimeField(default=datetime.datetime(2022, 10, 20, 6, 15, 3, 631559, tzinfo=datetime.timezone.utc))),
                ('account_updated', models.DateTimeField(default=datetime.datetime(2022, 10, 20, 6, 15, 3, 631666, tzinfo=datetime.timezone.utc))),
                ('verified', models.BooleanField(default=False)),
            ],
        ),
    ]
