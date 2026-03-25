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
    def _get_path(request) -> str:
        return request.url.path

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


class NewtonAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        unauthorized_handler=None,
        **config,
    ):
        super().__init__(app)
        self.auth = FastAPINewtonAuth(**config)
        self.unauthorized_handler = unauthorized_handler or self._default_unauthorized_handler

    async def dispatch(self, request, call_next):
        if self.auth.should_skip_auth(request):
            return await call_next(request)
        if request.url.path == self.auth.config.callback_path:
            response = RedirectResponse(url="/", status_code=302)
            try:
                result = self.auth.handle_callback(request, response)
            except (InvalidStateError, InvalidCallbackAssertionError):
                self.auth.clear_session(response)
                error_response = PlainTextResponse("invalid auth callback", status_code=400)
                self._copy_headers_and_cookies(response, error_response)
                return error_response
            response.headers["location"] = result.redirect_uri
            request.state.newton_user = result.user
            return response

        response = RedirectResponse(url="/", status_code=302)
        result = await self.auth.authenticate(request, response=response)
        if not result.authenticated:
            redirect = self.auth.build_login_redirect(request, response)
            response.headers["location"] = redirect.location
            return response
        if not result.authorized:
            return await self._call_unauthorized_handler(request, result)

        request.state.newton_user = result.user
        return await call_next(request)

    async def _call_unauthorized_handler(self, request, result):
        response = self.unauthorized_handler(request, result)
        if hasattr(response, "__await__"):
            return await response
        return response

    @staticmethod
    def _default_unauthorized_handler(request, result):
        accepts = request.headers.get("accept", "")
        if "application/json" in accepts:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return PlainTextResponse("forbidden", status_code=403)

    @staticmethod
    def _copy_headers_and_cookies(source, target) -> None:
        raw_headers = getattr(source.headers, "raw", [])
        for key, value in raw_headers:
            if key.lower() in {b"content-length", b"location"}:
                continue
            target.raw_headers.append((key, value))
