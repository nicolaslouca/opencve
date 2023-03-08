from django.urls import path

from advisories.views import AdvisoryDetailView, AdvisoryListView

urlpatterns = [
    path("advisories/", AdvisoryListView.as_view(), name="advisories"),
    path("advisories/<key>", AdvisoryDetailView.as_view(), name="advisory"),
]
