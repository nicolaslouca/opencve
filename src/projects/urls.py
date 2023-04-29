from django.urls import path

from projects.views import ProjectDetailView, ProjectListView, ReportsView, SubscriptionsView, IntegrationsView, IntegrationCreateView, IntegrationUpdateView

urlpatterns = [
    path("projects/", ProjectListView.as_view(), name="projects"),
    path("projects/<name>", ProjectDetailView.as_view(), name="project"),
    path("projects/<name>/integrations", IntegrationsView.as_view(), name="integrations"),
    path("projects/<name>/integrations/add", IntegrationCreateView.as_view(), name="create_integration"),
    path("projects/<name>/integrations/<integration>", IntegrationUpdateView.as_view(), name="update_integration"),
    path("projects/<name>/reports", ReportsView.as_view(), name="reports"),
    path("projects/<name>/subscriptions", SubscriptionsView.as_view(), name="subscriptions"),
]
