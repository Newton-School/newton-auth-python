from functools import wraps

from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect

from newton_auth.core import NewtonAuth
from newton_auth.errors import InvalidCallbackAssertionError, InvalidStateError


class DjangoNewtonAuth(NewtonAuth):
    @staticmethod
    def _get_origin(request) -> str:
        return "{}://{}".format("https" if request.is_secure() else "http", request.get_host())

    @staticmethod
    def _get_current_path(request) -> str:
        return request.get_full_path()

    @staticmethod
    def _get_query_param(request, name: str) -> str | None:
        return request.GET.get(name)

    @staticmethod
    def _get_cookie(request, name: str) -> str | None:
        return request.COOKIES.get(name)

    @staticmethod
    def _set_cookie(response, name: str, value: str, max_age: int) -> None:
        response.set_cookie(name, value, max_age=max_age, httponly=True, secure=True, samesite="Lax")

    @staticmethod
    def _delete_cookie(response, name: str) -> None:
        response.delete_cookie(name, path="/", samesite="Lax")


_AUTH_INSTANCE = None


def get_newton_auth() -> DjangoNewtonAuth:
    global _AUTH_INSTANCE
    if _AUTH_INSTANCE is None:
        config = settings.NEWTON_AUTH
        _AUTH_INSTANCE = DjangoNewtonAuth(
            client_id=config["CLIENT_ID"],
            client_secret=config["CLIENT_SECRET"],
            callback_secret=config["CALLBACK_SECRET"],
            newton_api_base=config["NEWTON_API_BASE"],
            session_signing_secret=config.get("SESSION_SIGNING_SECRET"),
            login_path=config.get("LOGIN_PATH", "/newton/login"),
            callback_path=config.get("CALLBACK_PATH", "/newton/callback"),
            cache_max_mb=config.get("CACHE_MAX_MB", 1),
            auth_timeout=config.get("AUTH_TIMEOUT", 10.0),
        )
    return _AUTH_INSTANCE


def get_unauthenticated_handler():
    return settings.NEWTON_AUTH.get("UNAUTHENTICATED_HANDLER") or _default_unauthenticated_handler


def get_unauthorized_handler():
    return settings.NEWTON_AUTH.get("UNAUTHORIZED_HANDLER") or _default_unauthorized_handler


class NewtonAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.auth = get_newton_auth()

    def __call__(self, request):
        if request.path == self.auth.config.login_path:
            next_path = request.GET.get("next") or "/"
            if next_path == self.auth.config.login_path:
                return HttpResponseBadRequest("invalid login redirect target")
            response = HttpResponseRedirect("/")
            redirect = self.auth.build_login_redirect(request, response, redirect_uri=next_path)
            response["Location"] = redirect.location
            return response
        if request.path != self.auth.config.callback_path:
            return self.get_response(request)

        response = HttpResponseRedirect("/")
        try:
            result = self.auth.handle_callback(request, response)
        except (InvalidStateError, InvalidCallbackAssertionError):
            self.auth.clear_session(response)
            error_response = HttpResponseBadRequest("invalid auth callback")
            self._copy_cookies(response, error_response)
            return error_response
        response["Location"] = result.redirect_uri
        request.newton_user = result.user
        return response

    @staticmethod
    def _copy_cookies(source, target) -> None:
        for morsel in source.cookies.values():
            target.cookies[morsel.key] = morsel


def newton_protected(view_func=None, *, unauthenticated_handler=None, unauthorized_handler=None):
    def decorator(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            auth = get_newton_auth()
            request.newton_auth = auth
            response = HttpResponseRedirect("/")
            result = auth.authenticate(request, response=response)
            if not result.authenticated:
                return (unauthenticated_handler or get_unauthenticated_handler())(request, result)
            if not result.authorized:
                return (unauthorized_handler or get_unauthorized_handler())(request, result)

            request.newton_user = result.user
            return view(request, *args, **kwargs)

        return wrapped

    if view_func is None:
        return decorator
    return decorator(view_func)


def _default_unauthorized_handler(request, result):
    return HttpResponseForbidden("forbidden")


def _default_unauthenticated_handler(request, result):
    return HttpResponse("authentication required", status=401)
