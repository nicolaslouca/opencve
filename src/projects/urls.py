from django.urls import path, register_converter

from opencve.utils import DateConverter
from projects.views import (
    IntegrationCreateView,
    IntegrationsView,
    IntegrationUpdateView,
    ProjectDetailView,
    ReportsView,
    ReportView,
    SubscriptionsView,
)

register_converter(DateConverter, "date")

urlpatterns = [
    path("projects/<name>", ProjectDetailView.as_view(), name="project"),
    path(
        "projects/<name>/integrations", IntegrationsView.as_view(), name="integrations"
    ),
    path(
        "projects/<name>/integrations/add",
        IntegrationCreateView.as_view(),
        name="create_integration",
    ),
    path(
        "projects/<name>/integrations/<integration>",
        IntegrationUpdateView.as_view(),
        name="edit_integration",
    ),
    path("projects/<name>/reports", ReportsView.as_view(), name="reports"),
    path("projects/<name>/reports/<date:day>", ReportView.as_view(), name="report"),
    path(
        "projects/<name>/subscriptions",
        SubscriptionsView.as_view(),
        name="subscriptions",
    ),
]
