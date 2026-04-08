"""
Tests for newton_protected cookie-deletion forwarding.

Bug: authenticate() writes Set-Cookie delete headers onto a dummy HttpResponseRedirect,
but newton_protected returned a *different* response object from the handler — so those
deletions never reached the browser. A user with a corrupt/expired session cookie would
get 401 on every request forever.

Fix: when result.should_clear_session is True, copy cookies from the dummy response onto
the handler response before returning it.
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
        DATABASES={},
        INSTALLED_APPS=[],
        USE_TZ=True,
    )
    django.setup()

from unittest.mock import MagicMock, patch

from django.http import HttpResponse
from django.test import RequestFactory

from newton_auth.django import DjangoNewtonAuth, newton_protected
from newton_auth.models import AuthResult


def _make_request(cookie_name="newton_session", cookie_value="corrupt-cookie"):
    factory = RequestFactory()
    req = factory.get("/protected/")
    req.COOKIES = {cookie_name: cookie_value}
    return req


def _mock_auth_with_clear(session_cookie="newton_session", state_cookie="newton_state"):
    """Return a mock DjangoNewtonAuth whose authenticate() simulates what the real
    implementation does when it encounters an invalid session: writes delete_cookie
    headers onto the passed response and returns should_clear_session=True."""
    mock_auth = MagicMock(spec=DjangoNewtonAuth)
    mock_auth.config = MagicMock()
    mock_auth.config.session_cookie_name = session_cookie
    mock_auth.config.state_cookie_name = state_cookie

    def _fake_authenticate(request, response=None):
        if response is not None:
            response.delete_cookie(session_cookie, path="/", samesite="Lax")
            response.delete_cookie(state_cookie, path="/", samesite="Lax")
        return AuthResult(authenticated=False, authorized=False, should_clear_session=True)

    mock_auth.authenticate.side_effect = _fake_authenticate
    return mock_auth


# ---------------------------------------------------------------------------
# Core regression test
# ---------------------------------------------------------------------------


def test_newton_protected_forwards_session_cookie_deletion_to_client():
    """The 401 response must carry Set-Cookie headers that delete the bad session
    cookie, so the browser removes it and the user is not stuck in an infinite loop."""
    request = _make_request()
    mock_auth = _mock_auth_with_clear()

    with patch("newton_auth.django.get_newton_auth", return_value=mock_auth):

        @newton_protected
        def view(request):
            return HttpResponse("ok")

        response = view(request)

    assert response.status_code == 401

    cookies = response.cookies
    assert "newton_session" in cookies, "session cookie deletion must be on the response"
    assert "newton_state" in cookies, "state cookie deletion must be on the response"
    # Django sets max_age=0 and expires in the past when deleting a cookie
    assert cookies["newton_session"]["max-age"] == 0
    assert cookies["newton_state"]["max-age"] == 0


def test_newton_protected_no_cookie_deletion_when_session_valid():
    """When should_clear_session is False, no spurious Set-Cookie headers should be added."""
    request = _make_request()

    mock_auth = MagicMock(spec=DjangoNewtonAuth)
    mock_auth.config = MagicMock()
    mock_auth.config.session_cookie_name = "newton_session"
    mock_auth.config.state_cookie_name = "newton_state"
    mock_auth.authenticate.return_value = AuthResult(authenticated=False, authorized=False, should_clear_session=False)

    with patch("newton_auth.django.get_newton_auth", return_value=mock_auth):

        @newton_protected
        def view(request):
            return HttpResponse("ok")

        response = view(request)

    assert response.status_code == 401
    assert "newton_session" not in response.cookies
    assert "newton_state" not in response.cookies


def test_newton_protected_passes_through_on_valid_session():
    """Authenticated + authorized requests reach the view unchanged."""
    from newton_auth.models import NewtonUser

    request = _make_request()

    mock_auth = MagicMock(spec=DjangoNewtonAuth)
    mock_auth.config = MagicMock()
    mock_auth.config.session_cookie_name = "newton_session"
    mock_auth.config.state_cookie_name = "newton_state"
    mock_auth.authenticate.return_value = AuthResult(
        authenticated=True,
        authorized=True,
        should_clear_session=False,
        user=NewtonUser(uid="user-123", authorized=True),
    )

    with patch("newton_auth.django.get_newton_auth", return_value=mock_auth):

        @newton_protected
        def view(request):
            return HttpResponse("ok", status=200)

        response = view(request)

    assert response.status_code == 200


def test_newton_protected_cookie_deletion_forwarded_to_custom_unauthenticated_handler():
    """Cookie deletions must reach the browser even when a custom handler is used."""
    request = _make_request()
    mock_auth = _mock_auth_with_clear()

    def custom_handler(request, result):
        return HttpResponse("custom 401", status=401)

    with patch("newton_auth.django.get_newton_auth", return_value=mock_auth):

        @newton_protected(unauthenticated_handler=custom_handler)
        def view(request):
            return HttpResponse("ok")

        response = view(request)

    assert response.status_code == 401
    assert response.content == b"custom 401"
    assert "newton_session" in response.cookies
    assert response.cookies["newton_session"]["max-age"] == 0


def test_newton_protected_403_no_spurious_cookie_deletion():
    """Authenticated but unauthorized: no cookie deletions should occur."""
    from newton_auth.models import NewtonUser

    request = _make_request()

    mock_auth = MagicMock(spec=DjangoNewtonAuth)
    mock_auth.config = MagicMock()
    mock_auth.config.session_cookie_name = "newton_session"
    mock_auth.config.state_cookie_name = "newton_state"
    mock_auth.authenticate.return_value = AuthResult(
        authenticated=True,
        authorized=False,
        should_clear_session=False,
        user=NewtonUser(uid="user-123", authorized=False),
    )

    with patch("newton_auth.django.get_newton_auth", return_value=mock_auth):

        @newton_protected
        def view(request):
            return HttpResponse("ok")

        response = view(request)

    assert response.status_code == 403
    assert "newton_session" not in response.cookies
