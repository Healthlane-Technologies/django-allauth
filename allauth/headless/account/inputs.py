from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from allauth.account import app_settings as account_settings
from allauth.account.adapter import get_adapter as get_account_adapter
from allauth.account.fields import PhoneField
from allauth.account.forms import (
    AddEmailForm,
    BaseSignupForm,
    ChangeEmailForm,
    ChangePhoneForm,
    ConfirmLoginCodeForm,
    ReauthenticateForm,
    RequestLoginCodeForm,
    ResetPasswordForm,
    UserTokenForm,
    VerifyPhoneForm,
)
from allauth.account.internal import flows
from allauth.account.models import EmailAddress, Login, get_emailconfirmation_model
from allauth.core import context
from allauth.core.internal.cryptokit import compare_user_code
from allauth.headless.adapter import get_adapter
from allauth.headless.internal.restkit import inputs

from zango.core.utils import get_auth_priority
from zango.api.app_auth.profile.v1.utils import PasswordValidationMixin

class SignupInput(BaseSignupForm, inputs.Input):
    password = inputs.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        password = account_settings.SIGNUP_FIELDS.get("password1")
        if not password:
            del self.fields["password"]
        else:
            self.fields["password"].required = password["required"]

    def clean_password(self):
        password = self.cleaned_data["password"]
        return get_account_adapter().clean_password(password)


class LoginInput(inputs.Input):
    email = inputs.EmailField(required=False)
    # NOTE: Always require E164, no need to use adapter.phone_form_field
    phone = PhoneField(required=False)
    password = inputs.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        policy = get_auth_priority(policy="login_methods")
        password_policy = policy.get("password", {})
        for field in ["email", "phone"]:
            if field not in password_policy.get("allowed_usernames", []):
                del self.fields[field]
        if len(password_policy.get("allowed_usernames")) == 1:
            self.fields[next(iter(password_policy.get("allowed_usernames")))].required = True

    def clean(self):
        cleaned_data = super().clean()
        if self.errors:
            return cleaned_data
        credentials = {}
        for login_method in get_auth_priority(policy="login_methods").get("password", {}).get("allowed_usernames"):
            value = cleaned_data.get(login_method)
            if value is not None and login_method in self.data.keys():
                credentials[login_method] = value
        if len(credentials) != 1:
            raise get_account_adapter().validation_error("invalid_login")
        password = cleaned_data.get("password")
        if password:
            auth_method = next(iter(credentials.keys()))
            credentials["password"] = password
            user = get_account_adapter().authenticate(context.request, **credentials)
            if user:
                self.login = Login(user=user, email=credentials.get("email"))
                if flows.login.is_login_rate_limited(context.request, self.login):
                    raise get_account_adapter().validation_error(
                        "too_many_login_attempts"
                    )
            else:
                error_code = "%s_password_mismatch" % auth_method
                self.add_error(
                    "password", get_account_adapter().validation_error(error_code)
                )
        return cleaned_data


class VerifyEmailInput(inputs.Input):
    key = inputs.CharField()

    def __init__(self, *args, **kwargs):
        self.process = kwargs.pop("process", None)
        super().__init__(*args, **kwargs)

    def clean_key(self):
        key = self.cleaned_data["key"]
        if self.process:
            if not compare_user_code(actual=key, expected=self.process.code):
                raise get_account_adapter().validation_error("incorrect_code")
            valid = True
            email_address = self.process.email_address
        else:
            model = get_emailconfirmation_model()
            verification = model.from_key(key)
            valid = verification and not verification.key_expired()
            if not valid:
                raise get_account_adapter().validation_error(
                    "incorrect_code"
                    if account_settings.EMAIL_VERIFICATION_BY_CODE_ENABLED
                    else "invalid_or_expired_key"
                )
            email_address = verification.email_address
            self.verification = verification
        if valid and not email_address.can_set_verified():
            raise get_account_adapter().validation_error("email_taken")
        return key


class RequestPasswordResetInput(ResetPasswordForm, inputs.Input):
    pass


class ResetPasswordKeyInput(inputs.Input):
    key = inputs.CharField()

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user", None)
        self.code = kwargs.pop("code", None)
        super().__init__(*args, **kwargs)

    def clean_key(self):
        password_policy = get_auth_priority(policy="password_policy")
        password_reset_policy = password_policy.get("reset", {})
        if password_reset_policy.get("by_code", False):
            return self._clean_key_code()
        else:
            return self._clean_key_link()

    def _clean_key_code(self):
        key = self.cleaned_data["key"]
        if not compare_user_code(actual=key, expected=self.code):
            raise get_account_adapter().validation_error("incorrect_code")
        return key

    def _clean_key_link(self):
        key = self.cleaned_data["key"]
        uidb36, _, subkey = key.partition("-")
        token_form = UserTokenForm(data={"uidb36": uidb36, "key": subkey})
        if not token_form.is_valid():
            raise get_account_adapter().validation_error("invalid_password_reset")
        self.user = token_form.reset_user
        return key


class ResetPasswordInput(ResetPasswordKeyInput, PasswordValidationMixin):
    password = inputs.CharField()

    def clean(self):
        cleaned_data = super().clean()
        password = self.cleaned_data.get("password")
        if self.user and password is not None:
            try:
                res = self.run_all_validations(self.user, password)
                if not res.get("validation"):
                    raise ValidationError(res.get("msg"))
                get_account_adapter().clean_password(password, user=self.user)
            except ValidationError as e:
                self.add_error("password", e)
        return cleaned_data


class ChangePasswordInput(inputs.Input):
    current_password = inputs.CharField(required=False)
    new_password = inputs.CharField()

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)
        self.fields["current_password"].required = self.user.has_usable_password()

    def clean_current_password(self):
        current_password = self.cleaned_data["current_password"]
        if current_password:
            if not self.user.check_password(current_password):
                raise get_account_adapter().validation_error("enter_current_password")
        return current_password

    def clean_new_password(self):
        new_password = self.cleaned_data["new_password"]
        adapter = get_account_adapter()
        return adapter.clean_password(new_password, user=self.user)


class AddEmailInput(AddEmailForm, inputs.Input):
    pass


class SelectEmailInput(inputs.Input):
    email = inputs.CharField()

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    def clean_email(self):
        email = self.cleaned_data["email"]
        validate_email(email)
        try:
            return EmailAddress.objects.get_for_user(user=self.user, email=email)
        except EmailAddress.DoesNotExist:
            raise get_adapter().validation_error("unknown_email")


class DeleteEmailInput(SelectEmailInput):
    def clean_email(self):
        email = super().clean_email()
        if not flows.manage_email.can_delete_email(email):
            raise get_account_adapter().validation_error("cannot_remove_primary_email")
        return email


class MarkAsPrimaryEmailInput(SelectEmailInput):
    primary = inputs.BooleanField(required=True)

    def clean_email(self):
        email = super().clean_email()
        if not flows.manage_email.can_mark_as_primary(email):
            raise get_account_adapter().validation_error("unverified_primary_email")
        return email


class ResendEmailVerificationInput(SelectEmailInput):
    def clean_email(self):
        if not account_settings.EMAIL_VERIFICATION_BY_CODE_ENABLED:
            self.process = None
            return super().clean_email()
        email = self.cleaned_data["email"]
        validate_email(email)
        self.process = flows.email_verification_by_code.EmailVerificationProcess.resume(
            context.request
        )
        if not self.process:
            raise get_adapter().validation_error("unknown_email")
        return self.process.email_address


class ReauthenticateInput(ReauthenticateForm, inputs.Input):
    pass


class RequestLoginCodeInput(RequestLoginCodeForm, inputs.Input):
    pass


class ConfirmLoginCodeInput(ConfirmLoginCodeForm, inputs.Input):
    pass


class VerifyPhoneInput(VerifyPhoneForm, inputs.Input):
    pass


class ChangePhoneInput(ChangePhoneForm, inputs.Input):
    pass


class ChangeEmailInput(ChangeEmailForm, inputs.Input):
    pass
