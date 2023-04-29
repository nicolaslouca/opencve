import importlib

from django.core.validators import RegexValidator
from django.db import models

from opencve.models import BaseModel
from users.models import User
from projects.utils import get_default_configuration


class Project(BaseModel):
    name = models.CharField(max_length=256, blank=True, null=True)
    description = models.TextField(blank=True, null=True)

    # Relationships
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="projects")
    subscriptions = models.JSONField(default=dict)

    class Meta:
        db_table = "opencve_projects"

    def __str__(self):
        return self.name

    @property
    def subscriptions_count(self):
        vendors = self.subscriptions["vendors"]
        products = self.subscriptions["products"]

        return len(vendors) + len(products)


class Integration(BaseModel):
    name = models.CharField(
        max_length=256,
        validators=[
            RegexValidator(
                regex="^[a-zA-Z0-9\-_ ]+$",
                message="Special characters (except dash and underscore) are not accepted",
            ),
        ],
    )
    type = models.CharField(max_length=64)
    is_enabled = models.BooleanField(default=True)
    has_report = models.BooleanField(default=False)
    configuration = models.JSONField(default=get_default_configuration)
    _integration = None

    # Relationships
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="integrations"
    )

    class Meta:
        db_table = "opencve_integrations"

    def __str__(self):
        return self.name

    @property
    def integration(self):
        if not self._integration:
            self._integration = getattr(
                importlib.import_module(f"projects.integrations.{self.type}"),
                f"{self.type}Integration",
            )(self.configuration)
        return self._integration
