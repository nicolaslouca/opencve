from django.db import models

from core.models import BaseModel


class Advisory(BaseModel):
    key = models.CharField(max_length=32, blank=False)
    title = models.CharField(max_length=200, blank=False)
    text = models.TextField(default=None)
    source = models.CharField(max_length=32, blank=False)
    extras = models.JSONField()
    original_url = models.URLField()

    class Meta:
        db_table = "opencve_advisories"

    def __str__(self):
        return self.key
