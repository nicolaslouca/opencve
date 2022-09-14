from django.views.generic import ListView

from advisories.models import Advisory


class AdvisoryListView(ListView):
    context_object_name = "advisories"
    template_name = "advisories/advisory_list.html"
    paginate_by = 20

    def get_queryset(self):
        query = Advisory.objects.all()
        return query.order_by("-updated_at")
