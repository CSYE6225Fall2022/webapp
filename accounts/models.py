import uuid

from django.db import models
from django.utils import timezone


# from django.contrib.auth.models import AbstractUser

# def generate_uuid():
#  return uuid.uuid4().hex

# Create your models here.
class AccountCustom(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    first_name = models.CharField(max_length=25)
    last_name = models.CharField(max_length=100)
    password = models.CharField(max_length=150)
    username = models.CharField(max_length=100, unique=True)
    account_created = models.DateTimeField(default=timezone.now())
    account_updated = models.DateTimeField(default=timezone.now())
    verified = models.BooleanField(default=False)


class DocCustom(models.Model):
    doc_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=100)
    date_created = models.DateTimeField(default=timezone.now())
    user_id = models.CharField(max_length=36)
    s3_bucket_path = models.CharField(max_length=100)
