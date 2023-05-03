import json
from pathlib import Path

from django.conf import settings
from django.contrib.postgres.indexes import GinIndex, OpClass
from django.db import models
from django.db.models.functions import Upper

from core.utils import humanize
from opencve.models import BaseModel


class Cwe(BaseModel):
    cwe_id = models.CharField(max_length=16, unique=True)
    name = models.CharField(max_length=256, blank=True, null=True)
    description = models.TextField(blank=True, null=True)

    class Meta:
        db_table = "opencve_cwes"

    @property
    def short_id(self):
        if not self.cwe_id.startswith("CWE-"):
            return None
        return self.cwe_id.split("CWE-")[1]

    def __str__(self):
        return self.cwe_id


class Vendor(BaseModel):
    name = models.CharField(max_length=256, unique=True)

    class Meta:
        db_table = "opencve_vendors"

    @property
    def human_name(self):
        return humanize(self.name)

    def __str__(self):
        return self.name


class Product(BaseModel):
    name = models.CharField(max_length=256)
    vendor = models.ForeignKey(
        Vendor, on_delete=models.CASCADE, related_name="products"
    )

    class Meta:
        db_table = "opencve_products"
        constraints = [
            models.UniqueConstraint(
                fields=["name", "vendor_id"], name="ix_unique_products"
            )
        ]

    @property
    def human_name(self):
        return humanize(self.name)

    def __str__(self):
        return self.name


class Cve(BaseModel):
    cve_id = models.CharField(max_length=20, unique=True)
    vendors = models.JSONField(default=list)
    cwes = models.JSONField(default=list)
    sources = models.JSONField(default=dict)

    # Keep the summary separated when searching keywords
    summary = models.TextField(default=None, null=True)

    # Keep CVSS separated when searching a particupal score
    cvss2 = models.FloatField(default=None, null=True)
    cvss3 = models.FloatField(default=None, null=True)

    class Meta:
        db_table = "opencve_cves"
        indexes = [
            GinIndex(name="ix_cves_vendors", fields=["vendors"]),
            GinIndex(name="ix_cves_cwes", fields=["cwes"]),
            GinIndex(
                OpClass(Upper("summary"), name="gin_trgm_ops"),
                name="ix_cves_summary",
            ),
            GinIndex(
                OpClass(Upper("cve_id"), name="gin_trgm_ops"),
                name="ix_cves_cve_id",
            ),
        ]

    @property
    def json(self):
        source_path = self.sources[next(iter(self.sources))]
        if len(self.sources) > 1 and "nvd" in self.sources:
            source_path = self.sources.get("nvd")

        path = Path(f"{settings.LOCAL_REPO_PATH}") / Path(source_path)
        with open(path) as f:
            data = json.load(f)
        return data

    @property
    def cvss_weight(self):
        """Only used to sort several CVE by their CVSS"""
        w = 0
        if self.cvss2:
            w += self.cvss2
        if self.cvss3:
            w += self.cvss3
        return w

    def __str__(self):
        return self.cve_id
