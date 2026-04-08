"""
Functional tests for the FastAPI integration — full ASGI request/response cycle.

These tests use real crypto (no mocking of cookie signing or assertion decryption)
and only mock the outbound HTTP call to the Newton auth-check API.
They cover login redirect → callback → protected route access in sequence.
"""

from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import Depends, FastAPI
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
from httpx import ASGITransport, AsyncClient

from newton_auth.fastapi import FastAPINewtonAuth, NewtonAuthMiddleware, require_newton_auth

# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def auth():
    return FastAPINewtonAuth(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        callback_secret=CALLBACK_SECRET,
        newton_api_base=NEWTON_API_BASE,
    )


@pytest.fixture
def app(auth):
    _app = FastAPI()
    _app.add_middleware(NewtonAuthMiddleware, auth=auth)

    @_app.get("/protected")
    async def protected(user=Depends(require_newton_auth(auth))):
        return {"uid": user.uid}

    return _app


@pytest.fixture
def client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ---------------------------------------------------------------------------
# Login flow
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_login_sets_state_cookie_and_redirects_to_newton(client):
    async with client as c:
        response = await c.get("/newton/login?next=/dashboard", follow_redirects=False)

    assert response.status_code == 302
    assert "newton_state" in response.cookies

    location = response.headers["location"]
    assert "platform-auth/login" in location
    qs = parse_qs(urlparse(location).query)
    assert qs["client_id"] == [CLIENT_ID]
    assert "state" in qs
    assert "redirect_uri" in qs


@pytest.mark.anyio
async def test_login_rejects_self_redirect(client):
    async with client as c:
        response = await c.get("/newton/login?next=/newton/login", follow_redirects=False)

    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Callback flow
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_callback_creates_session_cookie_and_redirects(client):
    async with client as c:
        # Step 1: get a real state cookie
        login_resp = await c.get("/newton/login?next=/dashboard", follow_redirects=False)
        state_cookie_value = login_resp.cookies["newton_state"]
        qs = parse_qs(urlparse(login_resp.headers["location"]).query)
        state_param = qs["state"][0]

        # Step 2: submit callback with real assertion
        identity = build_callback_assertion()
        callback_resp = await c.get(
            f"/newton/callback?state={state_param}&identity={identity}",
            cookies={"newton_state": state_cookie_value},
            follow_redirects=False,
        )

    assert callback_resp.status_code == 302
    assert callback_resp.headers["location"] == "/dashboard"
    assert "newton_session" in callback_resp.cookies
    # state cookie cleared
    set_cookie_headers = " ".join(callback_resp.headers.get_list("set-cookie")).lower()
    assert "newton_state" in set_cookie_headers
    assert "max-age=0" in set_cookie_headers


@pytest.mark.anyio
async def test_callback_rejects_state_mismatch(client):
    async with client as c:
        login_resp = await c.get("/newton/login?next=/", follow_redirects=False)
        state_cookie_value = login_resp.cookies["newton_state"]
        identity = build_callback_assertion()

        response = await c.get(
            f"/newton/callback?state=wrong-state&identity={identity}",
            cookies={"newton_state": state_cookie_value},
            follow_redirects=False,
        )

    assert response.status_code == 400
    set_cookie_headers = " ".join(response.headers.get_list("set-cookie")).lower()
    assert "newton_state" in set_cookie_headers
    assert "max-age=0" in set_cookie_headers


@pytest.mark.anyio
async def test_callback_rejects_tampered_assertion(client):
    async with client as c:
        login_resp = await c.get("/newton/login?next=/", follow_redirects=False)
        state_cookie_value = login_resp.cookies["newton_state"]
        qs = parse_qs(urlparse(login_resp.headers["location"]).query)
        state_param = qs["state"][0]

        response = await c.get(
            f"/newton/callback?state={state_param}&identity=v1.garbage.garbage.garbage",
            cookies={"newton_state": state_cookie_value},
            follow_redirects=False,
        )

    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Protected route — require_newton_auth dependency
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_protected_route_allows_valid_authenticated_session(auth, client):
    session_cookie = build_valid_session_cookie()

    with patch.object(auth.http, "auth_check", new=AsyncMock(return_value=auth_check_ok())):
        async with client as c:
            response = await c.get("/protected", cookies={"newton_session": session_cookie})

    assert response.status_code == 200
    assert response.json()["uid"] == "user-123"


@pytest.mark.anyio
async def test_protected_route_rejects_missing_session(client):
    async with client as c:
        response = await c.get("/protected")

    assert response.status_code == 401


@pytest.mark.anyio
async def test_protected_route_rejects_corrupt_session_and_clears_cookie(client):
    """Core regression: corrupt cookie must result in 401 + Set-Cookie delete headers."""
    async with client as c:
        response = await c.get("/protected", cookies={"newton_session": "not-a-valid-cookie"})

    assert response.status_code == 401
    set_cookie_headers = " ".join(response.headers.get_list("set-cookie")).lower()
    assert "newton_session" in set_cookie_headers, "session cookie deletion must be present"
    assert "max-age=0" in set_cookie_headers


@pytest.mark.anyio
async def test_protected_route_server_revokes_session_and_clears_cookie(auth, client):
    """When auth-check API revokes the session, cookie deletion must reach the client."""
    session_cookie = build_valid_session_cookie()

    with patch.object(auth.http, "auth_check", new=AsyncMock(return_value=auth_check_revoked())):
        async with client as c:
            response = await c.get("/protected", cookies={"newton_session": session_cookie})

    assert response.status_code == 401
    set_cookie_headers = " ".join(response.headers.get_list("set-cookie")).lower()
    assert "newton_session" in set_cookie_headers
    assert "max-age=0" in set_cookie_headers


@pytest.mark.anyio
async def test_protected_route_rejects_unauthorized_user(auth, client):
    session_cookie = build_valid_session_cookie()

    with patch.object(auth.http, "auth_check", new=AsyncMock(return_value=auth_check_ok(authorized=False))):
        async with client as c:
            response = await c.get("/protected", cookies={"newton_session": session_cookie})

    assert response.status_code == 403
