import importlib

from django.shortcuts import redirect, render, get_object_or_404
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.urls import reverse_lazy
from django.views.generic import DetailView, ListView, CreateView, UpdateView

from changes.models import Change
from projects.forms import FORM_MAPPING
from projects.models import Integration, Project


def get_default_configuration():
    return {
        "cvss": 0,
        "events": [
            "new_cve",
            "first_time",
            "references",
            "cvss",
            "cpes",
            "summary",
            "cwes",
        ],
    }


class ProjectListView(ListView):
    context_object_name = "projects"
    template_name = "projects/project_list.html"
    paginate_by = 20

    def get_queryset(self):
        # TODO: retourner les projets du user seulement
        query = Project.objects.all()
        return query.order_by("-updated_at")


class ProjectDetailView(DetailView):
    #TODO: vérifier que le project appartient bien au user
    model = Project
    slug_field = "name"
    slug_url_kwarg = "name"
    template_name = "projects/home.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Filter on project subscriptions
        vendors = self.object.subscriptions["vendors"] + self.object.subscriptions["products"]

        if vendors:
            query = Change.objects.select_related("cve").prefetch_related("events")
            query = query.filter(cve__vendors__has_any_keys=vendors)
            context["changes"] = query.all().order_by("-created_at")[:10]

        return context


class ReportsView(DetailView):
    # TODO: vérifier que le project appartient bien au user
    model = Project
    slug_field = "name"
    slug_url_kwarg = "name"
    template_name = "projects/reports.html"


class SubscriptionsView(DetailView):
    # TODO: vérifier que le project appartient bien au user
    model = Project
    slug_field = "name"
    slug_url_kwarg = "name"
    template_name = "projects/subscriptions.html"


class IntegrationsView(LoginRequiredMixin, DetailView):
    # TODO: vérifier que le project appartient bien au user
    model = Project
    slug_field = "name"
    slug_url_kwarg = "name"
    template_name = "projects/integrations/list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["integrations"] = Integration.objects.filter(project=self.object).all()
        return context


class IntegrationViewMixin:
    template_name = "projects/integrations/save.html"

    def get_type(self):
        raise NotImplementedError()

    def get_context_data(self, **kwargs):
        # TODO: vérifier que le projet appartient bien au user
        project = get_object_or_404(Project, name=self.kwargs['name'])
        return {
            **super(IntegrationViewMixin, self).get_context_data(**kwargs),
            **{"project": project, "type": self.request.GET.get("type")},
        }

    def get_form_class(self):
        return getattr(
            importlib.import_module("projects.forms"),
            f"{self.get_type().capitalize()}Form",
        )

    def exists(self, project, name, instance=None):
        queryset = Integration.objects.filter(project=project, name=name)
        if instance:
            queryset = queryset.filter(~Q(id=instance.id))

        if queryset.exists():
            messages.error(
                self.request,
                f"The integration {name} already exists.",
            )
            return True
        return False


class IntegrationCreateView(IntegrationViewMixin, CreateView):
    def get_type(self):
        return self.request.GET.get("type")

    def get(self, request, *args, **kwargs):
        if request.GET.get("type") not in ["email", "webhook", "slack"]:
            project = get_object_or_404(Project, name=self.kwargs['name'])
            return redirect("integrations", name=project.name)

        return super(IntegrationCreateView, self).get(request)

    def post(self, request, *args, **kwargs):
        form = self.get_form_class()(request.POST)

        # TODO: vérifier que c'est bien au user
        project = get_object_or_404(Project, name=self.kwargs['name'])

        if form.is_valid():
            if self.exists(project, form.cleaned_data["name"]):
                return render(
                    request,
                    self.template_name,
                    {"form": form, "type": self.get_type()},
                )

            # List of events
            events = [
                t
                for t, b in form.cleaned_data.items()
                if t in get_default_configuration().get("events") and b
            ]

            # Extra configuration
            extras = {}
            custom_fields = FORM_MAPPING.get(request.GET.get("type"), [])
            for field in custom_fields:
                extras[field] = form.cleaned_data[field]

            # Create the integration
            integration = form.save(commit=False)
            integration.project = project
            integration.type = request.GET.get("type")
            integration.configuration = {
                "events": events,
                "cvss": form.cleaned_data["cvss_score"],
                "extras": extras,
            }
            integration.save()

            messages.success(
                request, f"Integration {integration.name} successfully created"
            )
            return redirect("integrations", name=project.name)

        return render(
            request, self.template_name, {"form": form, "type": request.GET.get("type")}
        )


class IntegrationUpdateView(IntegrationViewMixin, UpdateView):
    def get_type(self):
        return self.object.type

    def get_object(self, queryset=None):
        # TODO: vérifier que c'est bien au user
        return get_object_or_404(Integration, name=self.kwargs['integration'], project__name=self.kwargs["name"])

    def get_context_data(self, **kwargs):
        context = super(IntegrationUpdateView, self).get_context_data(**kwargs)

        # Transform JSON field into dedicated fields
        context["form"].initial["cvss_score"] = self.object.configuration["cvss"]
        for event in self.object.configuration["events"]:
            context["form"].initial[event] = True

        custom_fields = FORM_MAPPING.get(self.object.type, [])
        for field in custom_fields:
            context["form"].initial[field] = self.object.configuration["extras"][field]

        return {**context, **{"type": self.object.type}}

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        form = self.get_form_class()(request.POST, instance=self.object)

        # TODO: vérifier que c'est bien au user
        project = get_object_or_404(Project, name=self.kwargs['name'])

        if form.is_valid():
            if self.exists(project, form.cleaned_data["name"], self.object):
                return render(
                    request,
                    self.template_name,
                    {"form": form, "type": self.get_type()},
                )

            # List of events
            events = [
                t
                for t, b in form.cleaned_data.items()
                if t in get_default_configuration().get("events") and b
            ]

            # Extra configuration
            extras = {}
            custom_fields = FORM_MAPPING.get(self.object.type, [])
            for field in custom_fields:
                extras[field] = form.cleaned_data[field]

            # Create the  integration
            integration = form.save(commit=False)
            integration.configuration = {
                "events": events,
                "cvss": form.cleaned_data["cvss_score"],
                "extras": extras,
            }
            integration.save()

            messages.success(
                request, f"Integration {integration.name} successfully updated"
            )
            return redirect("integrations", name=project.name)

        return render(
            request, self.template_name, {"form": form, "type": request.GET.get("type")}
        )
