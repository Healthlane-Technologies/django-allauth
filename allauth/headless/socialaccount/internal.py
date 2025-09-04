import json

from django.core.exceptions import PermissionDenied, ValidationError
from django.http import JsonResponse

from allauth import app_settings as allauth_settings
from allauth.core.exceptions import (
    ImmediateHttpResponse,
    ReauthenticationRequired,
    SignupClosedException,
)
from allauth.core.internal import httpkit
from allauth.headless.internal.authkit import AuthenticationStatus
from allauth.socialaccount.internal import flows, statekit
from allauth.socialaccount.providers.base.constants import AuthError, AuthProcess
from allauth.headless.base.response import AuthenticationResponse

from zango.core.api import get_api_response


def on_authentication_error(
    request,
    provider,
    error=None,
    exception=None,
    extra_context=None,
    state_id=None,
) -> None:
    """
    Called at a time when it is not clear whether or not this is a headless flow.
    """
    state = None
    if extra_context:
        state = extra_context.get("state")
        if state is None:
            state_id = extra_context.get("state_id")
            if state_id:
                state = statekit.unstash_state(request, state_id)
    params = {"error": error}
    if state is not None:
        headless = state.get("headless")
        next_url = state.get("next")
        params["error_process"] = state["process"]
    else:
        headless = allauth_settings.HEADLESS_ONLY
        next_url = None
        params["error_process"] = AuthProcess.LOGIN
    if not headless:
        return
    if not next_url:
        next_url = httpkit.get_frontend_url(request, "socialaccount_login_error") or "/"
    error_response = {
        "error": {
            "message": str(exception) if exception else error,
        },
        # "error_process": params["error_process"],
    }
    raise ImmediateHttpResponse(JsonResponse(error_response, status=400))


def complete_token_login(request, sociallogin):
    return flows.login.complete_login(request, sociallogin, raises=True)


def complete_login(request, sociallogin):
    """
    Called when `sociallogin.is_headless`.
    """
    error = None
    status = None
    resp = None
    try:
        resp = flows.login.complete_login(request, sociallogin, raises=True)
    except ReauthenticationRequired:
        error = "reauthentication_required"
    except SignupClosedException:
        error = "signup_closed"
    except PermissionDenied:
        error = "permission_denied"
    except ValidationError as e:
        error = e.code
    except Exception as e:
        return get_api_response(success=False, response_content={"error": {"message": str(e)}}, status=400)
    else:
        # At this stage, we're either:
        # 1) logged in (or in of the login pipeline stages, such as email verification)
        # 2) auto signed up -- a pipeline stage, so see 1)
        # 3) performing a social signup

        # 4) Stopped, due to not being open-for-signup
        # It would be good to refactor the above into a more generic social login
        # pipeline with clear stages, but for now the /auth endpoint properly responds
        status = AuthenticationStatus(request)
        if all(
            [
                not status.is_authenticated,
                not status.has_pending_signup,
                not status.get_pending_stage(),
            ]
        ):
            error = AuthError.UNKNOWN
    if status and status.get_pending_stage() and resp:
        request.session["sociallogin"] = sociallogin.serialize()
        authresponse = AuthenticationResponse.from_response(request, resp)
        data = json.loads(authresponse.content.decode("utf-8"))
        return get_api_response(
            success=True if authresponse.status_code == 200 else False,
            response_content=data,
            status=authresponse.status_code,
        )
    next_url = sociallogin.state["next"]
    if error:
        next_url = httpkit.add_query_params(
            next_url,
            {"error": error, "error_process": sociallogin.state["process"]},
        )
    resp =  AuthenticationResponse(request)
    data = json.loads(resp.content.decode("utf-8"))
    return get_api_response(
        success=True if resp.status_code == 200 else False,
        response_content=data,
        status=resp.status_code,
    )
