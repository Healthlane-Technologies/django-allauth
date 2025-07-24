from django import forms
from django.utils.translation import gettext_lazy as _

from allauth.core import context
from allauth.mfa.adapter import get_adapter
from allauth.mfa.base.internal.flows import check_rate_limit, post_authentication


class BaseAuthenticateForm(forms.Form):
    code = forms.CharField(
        label=_("Code"),
        widget=forms.TextInput(
            attrs={"placeholder": _("Code"), "autocomplete": "one-time-code"},
        ),
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    def clean(self):
        clear_rl = check_rate_limit(self.user)
        code = self.cleaned_data["code"]

        from zango.apps.appauth.models import OTPCode

        otp_codes = OTPCode.objects.filter(user=self.user, otp_type="two_factor_auth")
        for otp_code in otp_codes:
            if otp_code.is_valid() and otp_code.code == code:
                otp_code.mark_as_used()
                clear_rl()
                return code
        raise get_adapter().validation_error("incorrect_code")


class AuthenticateForm(BaseAuthenticateForm):
    def save(self):
        post_authentication(context.request, user = self.user)


class ReauthenticateForm(BaseAuthenticateForm):
    def save(self):
        post_authentication(context.request, user=self.user)
