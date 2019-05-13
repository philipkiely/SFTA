from django.db import models
from django.contrib.auth.models import User


class File(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='files/')


class AccessController(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    original = models.ForeignKey(File, on_delete=models.CASCADE)
    file = models.FileField(upload_to='files/')
    key = models.CharField(max_length=150)


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    server_msn = models.PositiveIntegerField()
    client_msn = models.PositiveIntegerField()
