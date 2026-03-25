from django.conf import settings
from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect

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
    def _get_path(request) -> str:
        return request.path

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


class NewtonAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        config = settings.NEWTON_AUTH
        self.auth = DjangoNewtonAuth(
            client_id=config["CLIENT_ID"],
            client_secret=config["CLIENT_SECRET"],
            callback_secret=config["CALLBACK_SECRET"],
            newton_api_base=config["NEWTON_API_BASE"],
            session_signing_secret=config.get("SESSION_SIGNING_SECRET"),
            callback_path=config.get("CALLBACK_PATH", "/newton/callback"),
            cache_max_mb=config.get("CACHE_MAX_MB", 1),
            excluded_path_prefixes=tuple(config.get("EXCLUDED_PATH_PREFIXES", ())),
        )
        self.unauthorized_handler = config.get("UNAUTHORIZED_HANDLER") or self._default_unauthorized_handler

    def __call__(self, request):
        if self.auth.should_skip_auth(request):
            return self.get_response(request)
        if request.path == self.auth.config.callback_path:
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

        response = HttpResponseRedirect("/")
        result = self.auth.authenticate(request, response=response)
        if not result.authenticated:
            redirect = self.auth.build_login_redirect(request, response)
            response["Location"] = redirect.location
            return response
        if not result.authorized:
            return self.unauthorized_handler(request, result)

        request.newton_user = result.user
        return self.get_response(request)

    @staticmethod
    def _copy_cookies(source, target) -> None:
        for morsel in source.cookies.values():
            target.cookies[morsel.key] = morsel

    @staticmethod
    def _default_unauthorized_handler(request, result):
        return HttpResponseForbidden("forbidden")
