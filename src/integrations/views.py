import importlib

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.generic import ListView, CreateView, UpdateView

from integrations.forms import FORM_MAPPING
from integrations.models import Integration
from integrations.utils import get_default_configuration


class IntegrationsView(LoginRequiredMixin, ListView):
    context_object_name = "integrations"
    template_name = "users/account/integrations.html"

    def get_queryset(self):
        query = Integration.objects.filter(user=self.request.user).all()
        return query.order_by("-name")


class IntegrationViewMixin:
    def get_type(self):
        raise NotImplementedError()

    def get_form_class(self):
        return getattr(
            importlib.import_module("integrations.forms"),
            f"{self.get_type().capitalize()}Form",
        )

    def exists(self, name, instance=None):
        queryset = Integration.objects.filter(user=self.request.user, name=name)
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
    template_name = "integrations/save_integration.html"

    def get_type(self):
        return self.request.GET.get("type")

    def get_context_data(self, **kwargs):
        return {
            **super(IntegrationCreateView, self).get_context_data(**kwargs),
            **{"type": self.request.GET.get("type")},
        }

    def get(self, request, *args, **kwargs):
        if request.GET.get("type") not in ["email", "webhook", "slack"]:
            return redirect("integrations")

        return super(IntegrationCreateView, self).get(request)

    def post(self, request, *args, **kwargs):
        form = self.get_form_class()(request.POST)

        if form.is_valid():
            if self.exists(form.cleaned_data["name"]):
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
            integration.user = request.user
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
            return redirect("integrations")

        return render(
            request, self.template_name, {"form": form, "type": request.GET.get("type")}
        )


class IntegrationUpdateView(IntegrationViewMixin, UpdateView):
    model = Integration
    slug_field = "name"
    slug_url_kwarg = "name"
    template_name = "integrations/save_integration.html"
    success_url = reverse_lazy("integrations")

    def get_type(self):
        return self.object.type

    def get_object(self, queryset=None):
        return get_object_or_404(
            self.model, user=self.request.user, name=self.kwargs["name"]
        )

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

        if form.is_valid():
            if self.exists(form.cleaned_data["name"], self.object):
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
            return redirect("integrations")

        return render(
            request, self.template_name, {"form": form, "type": request.GET.get("type")}
        )
