"""
Tests for require_newton_auth cookie-deletion forwarding.

Bug: authenticate() writes Set-Cookie delete headers onto a dummy RedirectResponse,
but require_newton_auth raised a NewtonAuthResponse wrapping a *different* response —
so those deletions never reached the browser. A user with a corrupt/expired session
cookie would get 401 on every request forever.

Fix: when result.should_clear_session is True, copy Set-Cookie headers from the dummy
response onto the handler response before raising NewtonAuthResponse.
"""

from unittest.mock import MagicMock

import pytest
from fastapi import Depends, FastAPI
from fastapi.responses import RedirectResponse
from httpx import ASGITransport, AsyncClient

from newton_auth.fastapi import (
    FastAPINewtonAuth,
    NewtonAuthMiddleware,
    _copy_headers_and_cookies,
    require_newton_auth,
)
from newton_auth.models import AuthResult, NewtonUser

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_auth(*, session_cookie="newton_session", state_cookie="newton_state"):
    """Return a mock FastAPINewtonAuth whose authenticate() simulates a corrupt
    session: writes delete_cookie headers onto the passed dummy response and
    returns should_clear_session=True."""
    mock_auth = MagicMock(spec=FastAPINewtonAuth)
    mock_auth.config = MagicMock()
    mock_auth.config.session_cookie_name = session_cookie
    mock_auth.config.state_cookie_name = state_cookie

    async def _fake_authenticate(request, response=None):
        if response is not None:
            response.delete_cookie(session_cookie, path="/", samesite="Lax")
            response.delete_cookie(state_cookie, path="/", samesite="Lax")
        return AuthResult(authenticated=False, authorized=False, should_clear_session=True)

    mock_auth.authenticate = _fake_authenticate
    return mock_auth


def _build_app(auth):
    """Build a test FastAPI app that mirrors production setup:
    NewtonAuthMiddleware in the stack (to catch NewtonAuthResponse from dependencies)
    plus a route protected by require_newton_auth."""
    app = FastAPI()
    # Middleware must be configured with login_path / callback_path so it doesn't
    # intercept /protected. MagicMock attributes compare unequal to any string, which
    # is sufficient — the middleware will call_next and catch NewtonAuthResponse.
    app.add_middleware(NewtonAuthMiddleware, auth=auth)

    @app.get("/protected")
    async def protected(user=Depends(require_newton_auth(auth))):
        return {"uid": user.uid}

    return app


# ---------------------------------------------------------------------------
# Core regression test
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_require_newton_auth_forwards_session_cookie_deletion_to_client():
    """The 401 response must carry Set-Cookie headers that delete the corrupt session
    cookie, so the browser removes it and the user is not stuck in an infinite 401 loop."""
    auth = _make_auth()
    app = _build_app(auth)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/protected", cookies={"newton_session": "corrupt-cookie"})

    assert response.status_code == 401

    set_cookie_headers = response.headers.get_list("set-cookie")
    assert set_cookie_headers, "expected Set-Cookie headers on 401 response"

    combined = " ".join(set_cookie_headers).lower()
    assert "newton_session" in combined, "session cookie deletion must be present"
    assert "newton_state" in combined, "state cookie deletion must be present"
    # A deleted cookie has max-age=0
    assert "max-age=0" in combined


@pytest.mark.anyio
async def test_require_newton_auth_no_cookie_deletion_when_session_clean():
    """When should_clear_session is False, no spurious Set-Cookie headers should appear."""
    mock_auth = MagicMock(spec=FastAPINewtonAuth)
    mock_auth.config = MagicMock()
    mock_auth.config.session_cookie_name = "newton_session"
    mock_auth.config.state_cookie_name = "newton_state"

    async def _fake_authenticate(request, response=None):
        return AuthResult(authenticated=False, authorized=False, should_clear_session=False)

    mock_auth.authenticate = _fake_authenticate
    app = _build_app(mock_auth)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/protected")

    assert response.status_code == 401
    set_cookie_headers = response.headers.get_list("set-cookie")
    assert not set_cookie_headers, "no Set-Cookie headers expected when session is clean"


@pytest.mark.anyio
async def test_require_newton_auth_passes_through_on_valid_session():
    """Authenticated + authorized requests reach the route handler unchanged."""
    mock_auth = MagicMock(spec=FastAPINewtonAuth)
    mock_auth.config = MagicMock()
    mock_auth.config.session_cookie_name = "newton_session"
    mock_auth.config.state_cookie_name = "newton_state"

    async def _fake_authenticate(request, response=None):
        return AuthResult(
            authenticated=True,
            authorized=True,
            should_clear_session=False,
            user=NewtonUser(uid="user-abc", authorized=True),
        )

    mock_auth.authenticate = _fake_authenticate
    app = _build_app(mock_auth)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/protected", cookies={"newton_session": "valid"})

    assert response.status_code == 200
    assert response.json() == {"uid": "user-abc"}


@pytest.mark.anyio
async def test_require_newton_auth_cookie_deletion_forwarded_with_custom_handler():
    """Cookie deletions must reach the browser even when a custom unauthenticated handler is used."""
    from fastapi.responses import JSONResponse

    auth = _make_auth()

    def custom_handler(request, result):
        return JSONResponse({"detail": "go away"}, status_code=401)

    app = FastAPI()
    app.add_middleware(NewtonAuthMiddleware, auth=auth)

    @app.get("/protected")
    async def protected(user=Depends(require_newton_auth(auth, unauthenticated_handler=custom_handler))):
        return {"uid": user.uid}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/protected", cookies={"newton_session": "corrupt"})

    assert response.status_code == 401
    assert response.json() == {"detail": "go away"}

    set_cookie_headers = response.headers.get_list("set-cookie")
    assert set_cookie_headers, "Set-Cookie delete headers must be present"
    combined = " ".join(set_cookie_headers).lower()
    assert "newton_session" in combined
    assert "max-age=0" in combined


@pytest.mark.anyio
async def test_require_newton_auth_403_no_spurious_cookie_deletion():
    """Authenticated but unauthorized: no cookie deletions should occur."""
    mock_auth = MagicMock(spec=FastAPINewtonAuth)
    mock_auth.config = MagicMock()
    mock_auth.config.session_cookie_name = "newton_session"
    mock_auth.config.state_cookie_name = "newton_state"

    async def _fake_authenticate(request, response=None):
        return AuthResult(
            authenticated=True,
            authorized=False,
            should_clear_session=False,
            user=NewtonUser(uid="user-abc", authorized=False),
        )

    mock_auth.authenticate = _fake_authenticate
    app = _build_app(mock_auth)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/protected", cookies={"newton_session": "valid"})

    assert response.status_code == 403
    set_cookie_headers = response.headers.get_list("set-cookie")
    assert not set_cookie_headers


# ---------------------------------------------------------------------------
# Unit test for _copy_headers_and_cookies
# ---------------------------------------------------------------------------


def test_copy_headers_and_cookies_transfers_set_cookie():
    """The helper correctly copies Set-Cookie headers while excluding content-length and location."""
    from fastapi.responses import PlainTextResponse

    source = RedirectResponse(url="/", status_code=302)
    source.delete_cookie("newton_session", path="/", samesite="Lax")
    source.delete_cookie("newton_state", path="/", samesite="Lax")

    target = PlainTextResponse("forbidden", status_code=403)
    # record original header count
    original_count = len(target.raw_headers)

    _copy_headers_and_cookies(source, target)

    added_headers = target.raw_headers[original_count:]
    set_cookie_keys = [k for k, v in added_headers if k.lower() == b"set-cookie"]
    assert len(set_cookie_keys) == 2, "both cookie deletions should be copied"
