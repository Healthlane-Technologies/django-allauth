import json
import time

from django.core.cache import cache

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Error


def lookup_kid_pem_x509_certificate(keys_data, kid):
    """
    Looks up the key given keys data of the form:

        {"<kid>": "-----BEGIN CERTIFICATE-----\nCERTIFICATE"}
    """
    key = keys_data.get(kid)
    if key:
        public_key = load_pem_x509_certificate(
            key.encode("utf8"), default_backend()
        ).public_key()
        return public_key


def lookup_kid_jwk(keys_data, kid):
    """
    Looks up the key given keys data of the form:

        {
          "keys": [
            {
              "kty": "RSA",
              "kid": "W6WcOKB",
              "use": "sig",
              "alg": "RS256",
              "n": "2Zc5d0-zk....",
              "e": "AQAB"
            }]
        }

    RSA and EC keys are supported. A token without a ``kid`` header matches
    only when the set holds exactly one signing key.
    """
    keys = [d for d in keys_data.get("keys", []) if d.get("use", "sig") == "sig"]
    if kid is None:
        candidates = keys if len(keys) == 1 else []
    else:
        candidates = [d for d in keys if d.get("kid") == kid]
    for d in candidates:
        kty = d.get("kty")
        if kty == "RSA":
            return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(d))
        if kty == "EC":
            return jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(d))
    return None


def _get_keys_data(keys_url, cache_timeout=None, refresh=False):
    cache_key = f"allauth:jwks:{keys_url}"
    if cache_timeout and not refresh:
        keys_data = cache.get(cache_key)
        if keys_data is not None:
            return keys_data
    response = get_adapter().get_requests_session().get(keys_url)
    response.raise_for_status()
    keys_data = response.json()
    if cache_timeout:
        cache.set(cache_key, keys_data, timeout=cache_timeout)
    return keys_data


def fetch_key(credential, keys_url, lookup, cache_timeout=None):
    """
    Returns ``(alg, key)`` for the key that signed ``credential``.

    With ``cache_timeout`` the key set is cached, and fetched again once when
    the token names a ``kid`` that the cached set does not hold (key rotation).
    """
    header = jwt.get_unverified_header(credential)
    # {'alg': 'RS256', 'kid': '0ad1fec78504f447bae65bcf5afaedb65eec9e81', 'typ': 'JWT'}
    kid = header.get("kid")
    alg = header["alg"]
    keys_data = _get_keys_data(keys_url, cache_timeout=cache_timeout)
    key = lookup(keys_data, kid)
    if not key and cache_timeout:
        keys_data = _get_keys_data(keys_url, cache_timeout=cache_timeout, refresh=True)
        key = lookup(keys_data, kid)
    if not key:
        raise OAuth2Error(f"Invalid 'kid': '{kid}'")
    return alg, key


def verify_jti(data: dict) -> None:
    """
    Put the JWT token on a blacklist to prevent replay attacks.
    """
    iss = data.get("iss")
    exp = data.get("exp")
    jti = data.get("jti")
    if iss is None or exp is None or jti is None:
        return
    timeout = exp - time.time()
    key = f"jwt:iss={iss},jti={jti}"
    if not cache.add(key=key, value=True, timeout=timeout):
        raise OAuth2Error("token already used")


def verify_and_decode(
    *,
    credential,
    keys_url,
    issuer,
    audience,
    lookup_kid,
    verify_signature=True,
    allowed_algorithms=None,
    authorized_party=None,
    leeway=0,
    keys_cache_timeout=None,
):
    """
    Verifies and decodes a JWT.

    ``allowed_algorithms`` restricts the header ``alg``; ``none`` and the
    HMAC family are always refused when it is given. ``authorized_party``
    must equal the ``azp`` claim when the token carries one.
    """
    try:
        if verify_signature:
            alg, key = fetch_key(
                credential, keys_url, lookup_kid, cache_timeout=keys_cache_timeout
            )
            if allowed_algorithms is not None:
                allowed = [
                    a
                    for a in allowed_algorithms
                    if a and a.lower() != "none" and not a.upper().startswith("HS")
                ]
                if alg not in allowed:
                    raise OAuth2Error(f"Disallowed id_token algorithm: '{alg}'")
            algorithms = [alg]
        else:
            key = ""
            algorithms = None
        data = jwt.decode(
            credential,
            key=key,
            options={
                "verify_signature": verify_signature,
                "verify_iss": True,
                "verify_aud": True,
                "verify_exp": True,
            },
            issuer=issuer,
            audience=audience,
            algorithms=algorithms,
            leeway=leeway,
        )
        if authorized_party is not None:
            azp = data.get("azp")
            if azp is not None and azp != authorized_party:
                raise OAuth2Error("Invalid id_token: 'azp' mismatch")
        verify_jti(data)
        return data
    except jwt.PyJWTError as e:
        raise OAuth2Error("Invalid id_token") from e
