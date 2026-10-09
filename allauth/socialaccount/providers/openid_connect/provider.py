import requests

from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.http import urlencode

from allauth.account.models import EmailAddress
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.internal import jwtkit
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from allauth.socialaccount.providers.openid_connect.views import (
    OpenIDConnectOAuth2Adapter,
)


class OpenIDConnectProviderAccount(ProviderAccount):
    pass


class OpenIDConnectProvider(OAuth2Provider):
    """
    App settings understood on top of the standard OAuth2 ones:

    - ``server_url``: issuer or discovery URL (required).
    - ``token_auth_method``: ``client_secret_basic`` or ``client_secret_post``.
    - ``callback_path``: serve the redirect URI at this path instead of the
      ``openid_connect_callback`` URL.
    - ``nonce_enabled`` (default ``True``): send a nonce and require it back in
      the ID token.
    - ``require_id_token`` (default ``False``): fail the login when the token
      response has no ID token. When an ID token is present it is always
      verified.
    - ``fetch_userinfo`` (default ``True``): merge userinfo claims; their
      ``sub`` must match the ID token's.
    - ``id_token_leeway`` (default ``0``): clock skew, in seconds.
    - ``discovery_cache_timeout`` / ``jwks_cache_timeout`` (default off):
      cache the discovery document and signing keys, in seconds.
    """

    id = "openid_connect"
    name = "OpenID Connect"
    account_class = OpenIDConnectProviderAccount
    oauth2_adapter_class = OpenIDConnectOAuth2Adapter
    supports_token_authentication = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = self.app.name

    @property
    def server_url(self):
        url = self.app.settings["server_url"]
        return self.wk_server_url(url)

    def wk_server_url(self, url):
        well_known_uri = "/.well-known/openid-configuration"
        if "/.well-known/" not in url:
            url = url.rstrip("/") + well_known_uri
        return url

    def get_login_url(self, request, **kwargs):
        url = reverse(
            self.app.provider + "_login", kwargs={"provider_id": self.app.provider_id}
        )
        if kwargs:
            url = url + "?" + urlencode(kwargs)
        return url

    def get_callback_url(self):
        callback_path = self.app.settings.get("callback_path")
        if callback_path:
            return callback_path
        return reverse(
            self.app.provider + "_callback",
            kwargs={"provider_id": self.app.provider_id},
        )

    @property
    def token_auth_method(self):
        return self.app.settings.get("token_auth_method")

    def get_default_scope(self):
        return ["openid", "profile", "email"]

    def extract_uid(self, data):
        return str(data["sub"])

    def extract_common_fields(self, data):
        return dict(
            email=data.get("email"),
            username=data.get("preferred_username"),
            name=data.get("name"),
            user_id=data.get("user_id"),
            picture=data.get("picture"),
            last_name=data.get("family_name"),
            first_name=data.get("given_name"),
        )

    def extract_email_addresses(self, data):
        addresses = []
        email = data.get("email")
        if email:
            addresses.append(
                EmailAddress(
                    email=email,
                    verified=data.get("email_verified", False),
                    primary=True,
                )
            )
        return addresses

    def get_oauth2_adapter(self, request):
        return self.oauth2_adapter_class(request, self.app.provider_id)

    def redirect(self, request, process, next_url=None, data=None, **kwargs):
        if self.app.settings.get("nonce_enabled", True):
            nonce = get_random_string(32)
            auth_params = kwargs.get("auth_params")
            if auth_params is None:
                auth_params = self.get_auth_params()
            auth_params = dict(auth_params)
            auth_params["nonce"] = nonce
            kwargs["auth_params"] = auth_params
            # Stashed with the redirect state, checked on callback.
            kwargs["nonce"] = nonce
        return super().redirect(
            request, process, next_url=next_url, data=data, **kwargs
        )

    def verify_id_token(self, request, id_token, nonce=None):
        """
        Verifies signature, issuer, audience, expiry, ``azp`` and (when given)
        ``nonce``. Returns the claims or raises ``OAuth2Error``.
        """
        settings = self.app.settings
        oauth2_adapter = self.get_oauth2_adapter(request)
        openid_config = oauth2_adapter.openid_config
        claims = jwtkit.verify_and_decode(
            credential=id_token,
            keys_url=openid_config["jwks_uri"],
            issuer=openid_config["issuer"],
            audience=[self.app.client_id],
            lookup_kid=jwtkit.lookup_kid_jwk,
            allowed_algorithms=openid_config.get(
                "id_token_signing_alg_values_supported"
            )
            or ["RS256"],
            authorized_party=self.app.client_id,
            leeway=settings.get("id_token_leeway", 0),
            keys_cache_timeout=settings.get("jwks_cache_timeout"),
        )
        if nonce is not None and claims.get("nonce") != nonce:
            raise OAuth2Error("Invalid id_token: 'nonce' mismatch")
        return claims

    def verify_token(self, request, token):
        id_token = token.get("id_token")
        if not id_token:
            raise get_adapter().validation_error("invalid_token")
        try:
            identity_data = self.verify_id_token(request, id_token)
        except (OAuth2Error, requests.RequestException) as e:
            raise get_adapter().validation_error("invalid_token") from e
        login = self.sociallogin_from_response(request, identity_data)
        return login


provider_classes = [OpenIDConnectProvider]
