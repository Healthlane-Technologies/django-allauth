from django.core.cache import cache
from django.http import Http404

from allauth.account.internal.decorators import login_not_required
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.models import SocialApp, SocialToken
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)
from allauth.utils import build_absolute_uri


class OpenIDConnectOAuth2Adapter(OAuth2Adapter):
    def __init__(self, request, provider_id):
        self.provider_id = provider_id
        super().__init__(request)

    @property
    def openid_config(self):
        if not hasattr(self, "_openid_config"):
            provider = self.get_provider()
            server_url = provider.server_url
            timeout = provider.app.settings.get("discovery_cache_timeout")
            cache_key = f"allauth:oidc:config:{server_url}"
            config = cache.get(cache_key) if timeout else None
            if config is None:
                resp = get_adapter().get_requests_session().get(server_url)
                resp.raise_for_status()
                config = resp.json()
                if timeout:
                    cache.set(cache_key, config, timeout=timeout)
            self._openid_config = config
        return self._openid_config

    @property
    def basic_auth(self):
        token_auth_method = self.get_provider().app.settings.get("token_auth_method")
        if token_auth_method:
            return token_auth_method == "client_secret_basic"  # nosec
        return "client_secret_basic" in self.openid_config.get(
            "token_endpoint_auth_methods_supported", []
        )

    @property
    def access_token_url(self):
        return self.openid_config["token_endpoint"]

    @property
    def authorize_url(self):
        return self.openid_config["authorization_endpoint"]

    @property
    def profile_url(self):
        return self.openid_config["userinfo_endpoint"]

    def complete_login(self, request, app, token: SocialToken, **kwargs):
        provider = self.get_provider()
        settings = provider.app.settings
        response = kwargs.get("response") or {}
        id_token = response.get("id_token")
        # Set by OAuth2CallbackView before calling us.
        state = getattr(self, "state", None) or {}

        claims = None
        if id_token:
            claims = provider.verify_id_token(
                request, id_token, nonce=state.get("nonce")
            )
        elif settings.get("require_id_token", False):
            raise OAuth2Error("No id_token in token response")

        if settings.get("fetch_userinfo", True) or claims is None:
            resp = (
                get_adapter()
                .get_requests_session()
                .get(
                    self.profile_url,
                    headers={"Authorization": "Bearer " + token.token},
                )
            )
            resp.raise_for_status()
            userinfo = resp.json()
            if claims is not None:
                if str(userinfo.get("sub")) != str(claims.get("sub")):
                    raise OAuth2Error("userinfo 'sub' does not match id_token")
                data = {**claims, **userinfo}
            else:
                data = userinfo
        else:
            data = claims
        login = provider.sociallogin_from_response(request, data)
        # Not persisted; available to the adapter during this request, e.g. as
        # the id_token_hint for RP-initiated logout.
        login.id_token = id_token
        return login

    def get_callback_url(self, request, app):
        callback_url = self.get_provider().get_callback_url()
        protocol = self.redirect_uri_protocol
        return build_absolute_uri(request, callback_url, protocol)


@login_not_required
def login(request, provider_id):
    try:
        view = OAuth2LoginView.adapter_view(
            OpenIDConnectOAuth2Adapter(request, provider_id)
        )
        return view(request)
    except SocialApp.DoesNotExist:
        raise Http404


@login_not_required
def callback(request, provider_id):
    try:
        view = OAuth2CallbackView.adapter_view(
            OpenIDConnectOAuth2Adapter(request, provider_id)
        )
        return view(request)
    except SocialApp.DoesNotExist:
        raise Http404
