import uuid

from django.db import models
from django.utils import timezone
#from django.contrib.auth.models import AbstractUser

# Create your models here.
class AccountCustom(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    first_name = models.CharField(max_length=25)
    last_name = models.CharField(max_length=100)
    password = models.CharField(max_length=150)
    username = models.CharField(max_length=100, unique=True)
    account_created = models.DateTimeField(default=timezone.now())
    account_updated = models.DateTimeField(default=timezone.now())
    verified = models.BooleanField(default=False)
