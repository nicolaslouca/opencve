from django import forms

from core.constants import CVSS_SCORES
from integrations.models import Integration


FORM_MAPPING = {
    "slack": ["url"],
    "webhook": ["url", "headers"]
}


class IntegrationForm(forms.ModelForm):
    class Meta:
        model = Integration
        fields = ["name", "is_enabled", "has_report"]
        labels = {
            "has_report": "Enable the daily report"
        }

    # Custom fields used for the configuration
    new_cve = forms.BooleanField(required=False)
    first_time = forms.BooleanField(required=False)
    cvss = forms.BooleanField(required=False)
    cpes = forms.BooleanField(required=False)
    summary = forms.BooleanField(required=False)
    cwes = forms.BooleanField(required=False)
    references = forms.BooleanField(required=False)
    cvss_score = forms.ChoiceField(
        choices=CVSS_SCORES,
        label="Be alerted when the CVSSv3 score is greater than or equal to :",
        initial=0,
    )

    def __init__(self, *args, **kwargs):
        super(IntegrationForm, self).__init__(*args, **kwargs)


class EmailForm(IntegrationForm):
    def __init__(self, *args, **kwargs):
        super(EmailForm, self).__init__(*args, **kwargs)


class SlackForm(IntegrationForm):
    url = forms.URLField()


class WebhookForm(IntegrationForm):
    url = forms.URLField()
    headers = forms.JSONField(required=False, initial={})

