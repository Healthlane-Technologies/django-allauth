from allauth.headless.base.response import APIResponse
from allauth.usersessions import app_settings
from django.db import connection
from zango.core.utils import get_datetime_str_in_tenant_timezone

class SessionsResponse(APIResponse):
    def __init__(self, request, sessions):
        super().__init__(request, data=[self._session_data(s) for s in sessions])

    def _session_data(self, session):
        data = {
            "user_agent": session.user_agent,
            "ip": session.ip,
            "created_at": get_datetime_str_in_tenant_timezone(session.created_at, connection.tenant),
            "is_current": session.is_current(),
            "id": session.pk,
        }
        # if app_settings.TRACK_ACTIVITY:
        data["last_seen_at"] = get_datetime_str_in_tenant_timezone(session.last_seen_at, connection.tenant)
        return data


def get_config_data(request):
    data = {"usersessions": {"track_activity": app_settings.TRACK_ACTIVITY}}
    return data
