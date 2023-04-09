import hashlib
import uuid

from django.db import models

from core.models import BaseModel, Cve


def get_random_sha256():
    return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()


class Task(BaseModel):
    nvd_checksum = models.CharField(
        max_length=64, unique=True, default=get_random_sha256
    )

    class Meta:
        db_table = "opencve_tasks"

    def __str__(self):
        return self.nvd_checksum


class Change(BaseModel):
    # Relationships
    cve = models.ForeignKey(Cve, on_delete=models.CASCADE, related_name="changes")
    path = models.TextField(default=None)
    commit = models.CharField(max_length=40)

    class Meta:
        db_table = "opencve_changes"


class Event(BaseModel):
    class EventType(models.TextChoices):
        NEW_CVE = "new_cve", "New CVE"
        FIRST_TIME = "first_time", "Vendors/Products appeared for the first time"
        REFERENCES = "references", "References changed"
        CPES = "cpes", "CPEs changed"
        CVSS = "cvss", "CVSS changed"
        SUMMARY = "summary", "Summary changed"
        CWES = "cwes", "CWEs changed"

    type = models.CharField(
        max_length=10,
        choices=EventType.choices,
        default=EventType.NEW_CVE,
    )
    details = models.JSONField()

    # Relationships
    cve = models.ForeignKey(Cve, on_delete=models.CASCADE, related_name="events")
    change = models.ForeignKey(Change, on_delete=models.CASCADE, related_name="events")

    class Meta:
        db_table = "opencve_events"

    def __str__(self):
        return self.type
