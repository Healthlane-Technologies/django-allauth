from allauth.usersessions import app_settings
from allauth.usersessions.models import UserSession


class UserSessionsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (
            hasattr(request, "session")
            and request.session.session_key
            and hasattr(request, "user")
            and request.user.is_authenticated
        ):
            if request.tenant.tenant_type != "shared":
                UserSession.objects.create_from_request(request)
        response = self.get_response(request)
        return response
