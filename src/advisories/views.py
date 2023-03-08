from django.views.generic import DetailView, ListView

from advisories.models import Advisory


class AdvisoryListView(ListView):
    context_object_name = "advisories"
    template_name = "advisories/advisory_list.html"
    paginate_by = 20

    def get_queryset(self):
        query = Advisory.objects.all()
        return query.order_by("-updated_at")


class AdvisoryDetailView(DetailView):
    model = Advisory
    slug_field = "key"
    slug_url_kwarg = "key"
    template_name = "advisories/advisory_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context
