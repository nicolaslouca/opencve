from django.urls import path

from advisories.views import AdvisoryListView

urlpatterns = [
    path("advisories/", AdvisoryListView.as_view(), name="advisories"),
]
