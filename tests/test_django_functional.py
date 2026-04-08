"""
Functional tests for the Django integration — full request/response cycle.

These tests use real crypto (no mocking of cookie signing or assertion decryption)
and only mock the outbound HTTP call to the Newton auth-check API.
They cover login redirect → callback → protected route access in sequence.
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
from urllib.parse import parse_qs, urlparse

import pytest
from django.http import HttpResponse, JsonResponse
from django.test import RequestFactory
from helpers import (
    CALLBACK_SECRET,
    CLIENT_ID,
    CLIENT_SECRET,
    NEWTON_API_BASE,
    auth_check_ok,
    auth_check_revoked,
    build_callback_assertion,
    build_valid_session_cookie,
)

from newton_auth.django import DjangoNewtonAuth, NewtonAuthMiddleware, newton_protected

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


def _middleware(auth):
    """Build a NewtonAuthMiddleware around a trivial get_response."""
    with patch("newton_auth.django.get_newton_auth", return_value=auth):
        return NewtonAuthMiddleware(lambda request: HttpResponse("passthrough"))


# ---------------------------------------------------------------------------
# Login flow
# ---------------------------------------------------------------------------


def test_login_sets_state_cookie_and_redirects_to_newton(auth, factory):
    middleware = _middleware(auth)
    request = factory.get("/newton/login", {"next": "/dashboard"})

    response = middleware(request)

    assert response.status_code == 302
    assert "newton_state" in response.cookies

    location = response["Location"]
    assert "platform-auth/login" in location
    parsed = urlparse(location)
    qs = parse_qs(parsed.query)
    assert qs["client_id"] == [CLIENT_ID]
    assert "state" in qs
    assert "redirect_uri" in qs


def test_login_rejects_self_redirect(auth, factory):
    middleware = _middleware(auth)
    request = factory.get("/newton/login", {"next": "/newton/login"})

    response = middleware(request)

    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Callback flow
# ---------------------------------------------------------------------------


def test_callback_creates_session_cookie_and_redirects(auth, factory):
    middleware = _middleware(auth)

    # Step 1: get a real state cookie via the login path
    login_req = factory.get("/newton/login", {"next": "/dashboard"})
    login_resp = middleware(login_req)
    state_morsel = login_resp.cookies["newton_state"]
    state_cookie_value = state_morsel.value

    # Extract state param from login redirect URL
    qs = parse_qs(urlparse(login_resp["Location"]).query)
    state_param = qs["state"][0]

    # Step 2: build a valid assertion as Newton would return
    identity = build_callback_assertion()

    # Step 3: submit callback
    callback_req = factory.get(
        "/newton/callback",
        {"state": state_param, "identity": identity},
    )
    callback_req.COOKIES = {"newton_state": state_cookie_value}

    callback_resp = middleware(callback_req)

    assert callback_resp.status_code == 302
    assert callback_resp["Location"] == "/dashboard"
    assert "newton_session" in callback_resp.cookies
    # state cookie should be cleared
    assert callback_resp.cookies["newton_state"]["max-age"] == 0


def test_callback_rejects_state_mismatch(auth, factory):
    middleware = _middleware(auth)

    # Get a real state cookie
    login_req = factory.get("/newton/login", {"next": "/"})
    login_resp = middleware(login_req)
    state_cookie_value = login_resp.cookies["newton_state"].value

    identity = build_callback_assertion()

    callback_req = factory.get(
        "/newton/callback",
        {"state": "wrong-state", "identity": identity},
    )
    callback_req.COOKIES = {"newton_state": state_cookie_value}

    callback_resp = middleware(callback_req)

    assert callback_resp.status_code == 400
    # state cookie must be cleared so the bad state doesn't linger
    assert "newton_state" in callback_resp.cookies
    assert callback_resp.cookies["newton_state"]["max-age"] == 0


def test_callback_rejects_tampered_assertion(auth, factory):
    middleware = _middleware(auth)

    login_req = factory.get("/newton/login", {"next": "/"})
    login_resp = middleware(login_req)
    state_morsel = login_resp.cookies["newton_state"]
    qs = parse_qs(urlparse(login_resp["Location"]).query)
    state_param = qs["state"][0]

    callback_req = factory.get(
        "/newton/callback",
        {"state": state_param, "identity": "v1.garbage.garbage.garbage"},
    )
    callback_req.COOKIES = {"newton_state": state_morsel.value}

    callback_resp = middleware(callback_req)

    assert callback_resp.status_code == 400


# ---------------------------------------------------------------------------
# Protected route — newton_protected decorator
# ---------------------------------------------------------------------------


@pytest.fixture
def protected_view(auth):
    @newton_protected
    def view(request):
        return JsonResponse({"uid": request.newton_user.uid})

    return view


def test_protected_route_allows_valid_authenticated_session(auth, factory, protected_view):
    session_cookie = build_valid_session_cookie()
    request = factory.get("/protected/")
    request.COOKIES = {"newton_session": session_cookie}

    with patch.object(auth.http, "auth_check", return_value=auth_check_ok()):
        with patch("newton_auth.django.get_newton_auth", return_value=auth):
            response = protected_view(request)

    assert response.status_code == 200
    import json

    assert json.loads(response.content)["uid"] == "user-123"


def test_protected_route_rejects_missing_session(auth, factory, protected_view):
    request = factory.get("/protected/")
    request.COOKIES = {}

    with patch("newton_auth.django.get_newton_auth", return_value=auth):
        response = protected_view(request)

    assert response.status_code == 401


def test_protected_route_rejects_corrupt_session_and_clears_cookie(auth, factory, protected_view):
    """Core regression: corrupt cookie must result in 401 + Set-Cookie delete headers."""
    request = factory.get("/protected/")
    request.COOKIES = {"newton_session": "this-is-not-a-valid-cookie"}

    with patch("newton_auth.django.get_newton_auth", return_value=auth):
        response = protected_view(request)

    assert response.status_code == 401
    assert "newton_session" in response.cookies, "session cookie deletion header must be present"
    assert response.cookies["newton_session"]["max-age"] == 0


def test_protected_route_server_revokes_session_and_clears_cookie(auth, factory, protected_view):
    """When auth-check API revokes the session, cookie deletion must reach the client."""
    session_cookie = build_valid_session_cookie()
    request = factory.get("/protected/")
    request.COOKIES = {"newton_session": session_cookie}

    with patch.object(auth.http, "auth_check", return_value=auth_check_revoked()):
        with patch("newton_auth.django.get_newton_auth", return_value=auth):
            response = protected_view(request)

    assert response.status_code == 401
    assert "newton_session" in response.cookies
    assert response.cookies["newton_session"]["max-age"] == 0


def test_protected_route_rejects_unauthorized_user(auth, factory, protected_view):
    session_cookie = build_valid_session_cookie()
    request = factory.get("/protected/")
    request.COOKIES = {"newton_session": session_cookie}

    with patch.object(auth.http, "auth_check", return_value=auth_check_ok(authorized=False)):
        with patch("newton_auth.django.get_newton_auth", return_value=auth):
            response = protected_view(request)

    assert response.status_code == 403
