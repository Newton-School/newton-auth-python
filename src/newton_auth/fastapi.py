from fastapi import Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from newton_auth.async_core import AsyncNewtonAuth
from newton_auth.errors import InvalidCallbackAssertionError, InvalidStateError


class FastAPINewtonAuth(AsyncNewtonAuth):
    @staticmethod
    def _get_origin(request) -> str:
        return "{}://{}".format(request.url.scheme, request.headers["host"])

    @staticmethod
    def _get_current_path(request) -> str:
        return request.url.path if not request.url.query else "{}?{}".format(request.url.path, request.url.query)

    @staticmethod
    def _get_query_param(request, name: str) -> str | None:
        return request.query_params.get(name)

    @staticmethod
    def _get_cookie(request, name: str) -> str | None:
        return request.cookies.get(name)

    @staticmethod
    def _set_cookie(response, name: str, value: str, max_age: int) -> None:
        response.set_cookie(name, value, max_age=max_age, httponly=True, secure=True, samesite="Lax")

    @staticmethod
    def _delete_cookie(response, name: str) -> None:
        response.delete_cookie(name, path="/", samesite="Lax")


class NewtonAuthResponse(Exception):
    def __init__(self, response):
        self.response = response


def _copy_headers_and_cookies(source, target) -> None:
    raw_headers = getattr(source.headers, "raw", [])
    for key, value in raw_headers:
        if key.lower() in {b"content-length", b"location"}:
            continue
        target.raw_headers.append((key, value))


class NewtonAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, auth: FastAPINewtonAuth):
        super().__init__(app)
        self.auth = auth

    async def dispatch(self, request, call_next):
        if request.url.path == self.auth.config.login_path:
            next_path = request.query_params.get("next") or "/"
            if next_path == self.auth.config.login_path:
                return PlainTextResponse("invalid login redirect target", status_code=400)
            response = RedirectResponse(url="/", status_code=302)
            redirect = self.auth.build_login_redirect(request, response, redirect_uri=next_path)
            response.headers["location"] = redirect.location
            return response
        if request.url.path != self.auth.config.callback_path:
            try:
                return await call_next(request)
            except NewtonAuthResponse as exc:
                return exc.response

        response = RedirectResponse(url="/", status_code=302)
        try:
            result = self.auth.handle_callback(request, response)
        except (InvalidStateError, InvalidCallbackAssertionError):
            self.auth.clear_session(response)
            error_response = PlainTextResponse("invalid auth callback", status_code=400)
            _copy_headers_and_cookies(response, error_response)
            return error_response
        response.headers["location"] = result.redirect_uri
        request.state.newton_user = result.user
        return response


def default_unauthorized_handler(request, auth_result):
    accepts = request.headers.get("accept", "")
    if "application/json" in accepts:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return PlainTextResponse("forbidden", status_code=403)


def default_unauthenticated_handler(request, auth_result):
    accepts = request.headers.get("accept", "")
    if "application/json" in accepts:
        return JSONResponse({"error": "authentication_required"}, status_code=401)
    return PlainTextResponse("authentication required", status_code=401)


def require_newton_auth(auth: FastAPINewtonAuth, *, unauthenticated_handler=None, unauthorized_handler=None):
    async def dependency(request: Request):
        response = RedirectResponse(url="/", status_code=302)
        result = await auth.authenticate(request, response=response)
        if not result.authenticated:
            handler = unauthenticated_handler or default_unauthenticated_handler
            unauthenticated_response = handler(request, result)
            if hasattr(unauthenticated_response, "__await__"):
                unauthenticated_response = await unauthenticated_response
            if result.should_clear_session:
                _copy_headers_and_cookies(response, unauthenticated_response)
            raise NewtonAuthResponse(unauthenticated_response)
        if not result.authorized:
            handler = unauthorized_handler or default_unauthorized_handler
            unauthorized_response = handler(request, result)
            if hasattr(unauthorized_response, "__await__"):
                unauthorized_response = await unauthorized_response
            if result.should_clear_session:
                _copy_headers_and_cookies(response, unauthorized_response)
            raise NewtonAuthResponse(unauthorized_response)

        request.state.newton_user = result.user
        return result.user

    return dependency
