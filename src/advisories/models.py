from django.db import models

from opencve.models import BaseModel


class Advisory(BaseModel):
    key = models.CharField(max_length=32, blank=False, unique=True)
    title = models.CharField(max_length=200, blank=False)
    text = models.TextField(default=None)
    source = models.CharField(max_length=32, blank=False)
    extras = models.JSONField()
    link = models.URLField()

    class Meta:
        db_table = "opencve_advisories"

    def __str__(self):
        return self.key
