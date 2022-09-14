from django.db import models

from core.models import BaseModel


class Advisory(BaseModel):
    name = models.CharField(max_length=128, blank=False)
    text = models.TextField(default=None)
    source = models.CharField(max_length=32, blank=False)
    extras = models.JSONField()

    class Meta:
        db_table = "opencve_advisories"

    def __str__(self):
        return self.name
