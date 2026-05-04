"""
Tests for NS-12574: profile fields (first_name, last_name, email) propagating
through the callback → session cookie → cache hit → auth-check refresh paths
under the new AES-GCM-encrypted session cookie.
"""

import django
from django.conf import settings

if not settings.configured:
    settings.configure(
        NEWTON_AUTH={
            "CLIENT_ID": "test-client",
            "CLIENT_SECRET": "test-secret",
            "CALLBACK_SECRET": "test-callback-secret",
            "NEWTON_API_BASE": "https://api.example.com",
        },
        ALLOWED_HOSTS=["testserver"],
        DATABASES={},
        INSTALLED_APPS=[],
        USE_TZ=True,
    )
    django.setup()

from unittest.mock import patch

import pytest
from django.http import HttpResponse
from django.test import RequestFactory
from helpers import (
    CALLBACK_SECRET,
    CLIENT_ID,
    CLIENT_SECRET,
    NEWTON_API_BASE,
    SESSION_SIGNING_SECRET,
    auth_check_ok,
    build_callback_assertion,
    build_valid_session_cookie,
)

from newton_auth.cookies import build_session_cookie_value, parse_session_cookie_value
from newton_auth.crypto import sign_value
from newton_auth.django import DjangoNewtonAuth
from newton_auth.errors import InvalidSessionError


@pytest.fixture
def auth():
    return DjangoNewtonAuth(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        callback_secret=CALLBACK_SECRET,
        newton_api_base=NEWTON_API_BASE,
    )


@pytest.fixture
def factory():
    return RequestFactory()


# ---------------------------------------------------------------------------
# Cookie crypto: AES-GCM round-trip + AAD binding + v1 rejection
# ---------------------------------------------------------------------------


def test_session_cookie_does_not_carry_profile_fields():
    """Profile fields live in the cache, not the cookie. The cookie is only
    a uid + platform_token bearer; profile is refreshed via auth-check on
    every cache miss so consumers always see fresh data."""
    cookie = build_session_cookie_value(
        uid="user-1",
        platform_token="tok",
        authorized=True,
        session_ttl_seconds=3600,
        secret=SESSION_SIGNING_SECRET,
        client_id=CLIENT_ID,
    )
    parsed = parse_session_cookie_value(cookie, SESSION_SIGNING_SECRET, CLIENT_ID)
    assert "first_name" not in parsed
    assert "last_name" not in parsed
    assert "email" not in parsed


def test_session_cookie_uses_v2_wire_format():
    cookie = build_session_cookie_value(
        uid="user-1",
        platform_token="tok",
        authorized=True,
        session_ttl_seconds=3600,
        secret=SESSION_SIGNING_SECRET,
        client_id=CLIENT_ID,
    )
    assert cookie.startswith("v2.")
    assert len(cookie.split(".")) == 3


def test_session_cookie_rejects_wrong_client_id():
    cookie = build_session_cookie_value(
        uid="user-1",
        platform_token="tok",
        authorized=True,
        session_ttl_seconds=3600,
        secret=SESSION_SIGNING_SECRET,
        client_id="app-A",
    )
    with pytest.raises(InvalidSessionError):
        parse_session_cookie_value(cookie, SESSION_SIGNING_SECRET, "app-B")


def test_legacy_v1_signed_cookie_is_rejected():
    """Old HMAC-signed cookies (pre-NS-12574) must fail to parse so the
    middleware clears them and bounces the user to login."""
    legacy = sign_value(
        {
            "uid": "user-1",
            "platform_token": "tok",
            "authorized": True,
            "session_ttl_seconds": 3600,
            "issued_at": 0,
            "nonce": "abc",
        },
        SESSION_SIGNING_SECRET,
    )
    with pytest.raises(InvalidSessionError):
        parse_session_cookie_value(legacy, SESSION_SIGNING_SECRET, CLIENT_ID)


# ---------------------------------------------------------------------------
# Callback path: profile fields → CallbackResult.user + session cookie + cache
# ---------------------------------------------------------------------------


def test_handle_callback_populates_user_profile_fields(auth, factory):
    state_cookie = sign_value(
        {"state": "s1", "redirect_uri": "/dash", "exp": 9999999999},
        SESSION_SIGNING_SECRET,
    )
    identity = build_callback_assertion(
        sub="user-1",
        first_name="Ada",
        last_name="Lovelace",
        email="ada@example.com",
    )
    request = factory.get(
        "/newton/callback",
        {"state": "s1", "identity": identity},
        HTTP_HOST="app.example.com",
    )
    request.COOKIES[auth.config.state_cookie_name] = state_cookie
    response = HttpResponse()

    result = auth.handle_callback(request, response)

    assert result.user.uid == "user-1"
    assert result.user.first_name == "Ada"
    assert result.user.last_name == "Lovelace"
    assert result.user.email == "ada@example.com"


def test_handle_callback_seeds_cache_with_profile_fields(auth, factory):
    """After a callback, the cache is the source of truth for profile fields —
    not the cookie. This test pins that contract."""
    state_cookie = sign_value(
        {"state": "s1", "redirect_uri": "/dash", "exp": 9999999999},
        SESSION_SIGNING_SECRET,
    )
    identity = build_callback_assertion(
        sub="user-1",
        first_name="Ada",
        last_name="Lovelace",
        email="ada@example.com",
    )
    request = factory.get(
        "/newton/callback",
        {"state": "s1", "identity": identity},
        HTTP_HOST="app.example.com",
    )
    request.COOKIES[auth.config.state_cookie_name] = state_cookie
    response = HttpResponse()

    auth.handle_callback(request, response)

    cached = auth.cache.get("user-1")
    assert cached["first_name"] == "Ada"
    assert cached["email"] == "ada@example.com"

    session_cookie = response.cookies[auth.config.session_cookie_name].value
    parsed = parse_session_cookie_value(session_cookie, SESSION_SIGNING_SECRET, CLIENT_ID)
    assert "first_name" not in parsed
    assert "email" not in parsed


# ---------------------------------------------------------------------------
# Authenticate: cache hit + auth-check refresh both expose profile fields
# ---------------------------------------------------------------------------


def test_authenticate_cache_hit_exposes_profile_fields(auth, factory):
    auth.cache.set(
        "user-1",
        {
            "authenticated": True,
            "authorized": True,
            "first_name": "Ada",
            "last_name": "Lovelace",
            "email": "ada@example.com",
            "client_cache_ttl_seconds": 300,
        },
    )
    cookie = build_valid_session_cookie(uid="user-1")
    request = factory.get("/")
    request.COOKIES[auth.config.session_cookie_name] = cookie

    result = auth.authenticate(request)

    assert result.user is not None
    assert result.user.first_name == "Ada"
    assert result.user.last_name == "Lovelace"
    assert result.user.email == "ada@example.com"


def test_profile_fields_refresh_on_cache_miss_independent_of_cookie(auth, factory):
    """Freshness contract: when the cache evicts (TTL elapsed) the next request
    re-reads profile fields from the auth-check response, regardless of what
    the (long-lived) cookie carries. Demonstrates that an email change
    propagates within client_cache_ttl_seconds, not session_ttl_seconds."""
    cookie = build_valid_session_cookie(uid="user-1")
    request = factory.get("/")
    request.COOKIES[auth.config.session_cookie_name] = cookie

    with patch.object(
        auth.http,
        "auth_check",
        return_value=auth_check_ok(uid="user-1", first_name="Old", email="old@example.com"),
    ):
        first_result = auth.authenticate(request)
    assert first_result.user.email == "old@example.com"

    auth.cache._cache.clear()  # force eviction

    with patch.object(
        auth.http,
        "auth_check",
        return_value=auth_check_ok(uid="user-1", first_name="New", email="new@example.com"),
    ):
        second_result = auth.authenticate(request)

    assert second_result.user.first_name == "New"
    assert second_result.user.email == "new@example.com"


def test_authenticate_refresh_populates_profile_from_auth_check(auth, factory):
    cookie = build_valid_session_cookie(uid="user-1")
    request = factory.get("/")
    request.COOKIES[auth.config.session_cookie_name] = cookie

    with patch.object(
        auth.http,
        "auth_check",
        return_value=auth_check_ok(
            uid="user-1",
            first_name="Ada",
            last_name="Lovelace",
            email="ada@example.com",
        ),
    ):
        result = auth.authenticate(request)

    assert result.user is not None
    assert result.user.first_name == "Ada"
    assert result.user.email == "ada@example.com"


def test_authenticate_refresh_caches_profile_for_next_request(auth, factory):
    cookie = build_valid_session_cookie(uid="user-1")
    request = factory.get("/")
    request.COOKIES[auth.config.session_cookie_name] = cookie

    with patch.object(
        auth.http,
        "auth_check",
        return_value=auth_check_ok(uid="user-1", first_name="Ada", email="ada@example.com"),
    ):
        auth.authenticate(request)

    cached = auth.cache.get("user-1")
    assert cached["first_name"] == "Ada"
    assert cached["email"] == "ada@example.com"
