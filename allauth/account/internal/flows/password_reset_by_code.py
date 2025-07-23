from typing import Optional

from django.http import HttpRequest, HttpResponse

from allauth.account import app_settings
from allauth.account.adapter import get_adapter
from allauth.account.internal.flows import password_reset
from allauth.account.internal.flows.code_verification import (
    AbstractCodeVerificationProcess,
)
from allauth.account.internal.flows.email_verification import verify_email_indirectly
from allauth.account.internal.flows.signup import send_unknown_account_mail

from zango.core.utils import get_auth_priority

PASSWORD_RESET_VERIFICATION_SESSION_KEY = (
    "account_password_reset_verification"  # nosec: B105
)


class PasswordResetVerificationProcess(AbstractCodeVerificationProcess):
    def __init__(self, request, state, user=None):
        self.request = request
        password_policy = get_auth_priority(
            policy='password_policy', request=request
        )
        reset_policy = password_policy.get('reset', {})
        super().__init__(
            state=state,
            timeout=reset_policy.get('expiry', 180),
            max_attempts=reset_policy.get(
                'max_attempts', 3
            ),
            user=user,
        )

    def abort(self):
        self.request.session.pop(PASSWORD_RESET_VERIFICATION_SESSION_KEY, None)

    def confirm_code(self):
        if self.state.get("code_confirmed"):
            return
        self.state["code_confirmed"] = True
        self.persist()
        if self.state.get("email"):
            verify_email_indirectly(self.request, self.user, self.state["email"])

    def finish(self) -> Optional[HttpResponse]:
        self.request.session.pop(PASSWORD_RESET_VERIFICATION_SESSION_KEY, None)
        email = self.state.get("email")
        return password_reset.finalize_password_reset(
            self.request, self.user, email=email
        )

    def persist(self):
        self.request.session[PASSWORD_RESET_VERIFICATION_SESSION_KEY] = self.state

    def send(self):
        adapter = get_adapter()
        email = self.state.get("email", None)
        phone = self.state.get("phone", None)
        if not self.user:
            send_unknown_account_mail(self.request, email)
            return
        code = adapter.generate_password_reset_code(email=email, phone=phone)
        self.state["code"] = code
        if email:
            context = {
                "request": self.request,
                "code": code,
            }
            password_policy = get_auth_priority(request=self.request, policy="password_policy", user=self.user)
            password_reset_policy = password_policy.get("reset", {})
            email_hook = password_reset_policy.get("email_hook", None)
            adapter.send_mail("account/email/password_reset_code", email, context, email_hook=email_hook)
        if phone:
            adapter.send_sms(user=self.user, phone=phone, request=self.request, code=code, flow="reset_password")

    @classmethod
    def initiate(cls, *, request, user, email: str | None = None, phone: str | None = None):
        state = cls.initial_state(user, email, phone)
        process = PasswordResetVerificationProcess(request, state=state, user=user)
        process.send()
        process.persist()
        return process

    @classmethod
    def resume(
        cls, request: HttpRequest
    ) -> Optional["PasswordResetVerificationProcess"]:
        state = request.session.get(PASSWORD_RESET_VERIFICATION_SESSION_KEY)
        print("state is ", state)
        if not state:
            return None
        process = PasswordResetVerificationProcess(request, state=state)
        return process.abort_if_invalid()
