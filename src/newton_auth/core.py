import secrets

from newton_auth.cache import BoundedLRUCache
from newton_auth.config import NewtonAuthConfig
from newton_auth.cookies import (
    build_session_cookie_value,
    build_state_cookie_value,
    parse_session_cookie_value,
    parse_state_cookie_value,
)
from newton_auth.crypto import decrypt_callback_assertion
from newton_auth.errors import InvalidCallbackAssertionError, InvalidSessionError, InvalidStateError
from newton_auth.http import NewtonAuthHTTPClient
from newton_auth.models import AuthResult, CallbackResult, NewtonUser, RedirectInstruction
from newton_auth.utils import append_query_params, derive_issuer_from_base_url


class NewtonAuth:
    def __init__(self, **kwargs):
        self.config = NewtonAuthConfig(**kwargs)
        if self.config.session_signing_secret is None:
            self.config.session_signing_secret = self.config.client_secret
        self.http = NewtonAuthHTTPClient(
            base_url=self.config.newton_api_base,
            client_id=self.config.client_id,
            client_secret=self.config.client_secret,
            auth_timeout=self.config.auth_timeout,
        )
        self.cache = BoundedLRUCache(max_mb=self.config.cache_max_mb)

    def authenticate(self, request, response=None) -> AuthResult:
        cookie_value = self._get_cookie(request, self.config.session_cookie_name)
        try:
            session = parse_session_cookie_value(
                cookie_value,
                self.config.session_signing_secret,
                self.config.client_id,
            )
        except InvalidSessionError:
            if response is not None:
                self.clear_session(response)
            return AuthResult(authenticated=False, authorized=False, should_clear_session=True)

        uid = session["uid"]
        cached = self.cache.get(uid)
        if cached:
            return AuthResult(
                authenticated=cached["authenticated"],
                authorized=cached["authorized"],
                should_clear_session=False,
                user=NewtonUser(
                    uid=uid,
                    authorized=cached["authorized"],
                    first_name=cached.get("first_name", ""),
                    last_name=cached.get("last_name", ""),
                    email=cached.get("email", ""),
                )
                if cached["authenticated"]
                else None,
                client_cache_ttl_seconds=cached.get("client_cache_ttl_seconds"),
                session_ttl_seconds=session.get("session_ttl_seconds"),
            )

        data = self.http.auth_check(uid=uid, platform_token=session["platform_token"])
        if data.get("should_clear_session") and response is not None:
            self.clear_session(response)
        self.cache.set(
            uid,
            {
                "authenticated": bool(data.get("authenticated")),
                "authorized": bool(data.get("authorized")),
                "first_name": data.get("first_name", ""),
                "last_name": data.get("last_name", ""),
                "email": data.get("email", ""),
                "client_cache_ttl_seconds": int(data.get("client_cache_ttl_seconds", 60)),
            },
        )
        return AuthResult(
            authenticated=bool(data.get("authenticated")),
            authorized=bool(data.get("authorized")),
            should_clear_session=bool(data.get("should_clear_session")),
            user=NewtonUser(
                uid=uid,
                authorized=bool(data.get("authorized")),
                first_name=data.get("first_name", ""),
                last_name=data.get("last_name", ""),
                email=data.get("email", ""),
            )
            if data.get("authenticated")
            else None,
            client_cache_ttl_seconds=int(data.get("client_cache_ttl_seconds", 60)),
            session_ttl_seconds=int(data.get("session_ttl_seconds", session.get("session_ttl_seconds", 86400))),
        )

    def build_login_redirect(self, request, response, redirect_uri: str | None = None) -> RedirectInstruction:
        state = secrets.token_urlsafe(24)
        post_login_redirect = redirect_uri or self._get_current_path(request)
        state_cookie = build_state_cookie_value(state, post_login_redirect, self.config.session_signing_secret)
        self._set_cookie(response, self.config.state_cookie_name, state_cookie, max_age=300)
        callback_url = self._build_callback_uri(request)
        login_url = append_query_params(
            "{}/platform-auth/login".format(self.config.newton_api_base.rstrip("/")),
            {
                "client_id": self.config.client_id,
                "state": state,
                "redirect_uri": callback_url,
            },
        )
        return RedirectInstruction(location=login_url)

    def handle_callback(self, request, response) -> CallbackResult:
        state_param = self._get_query_param(request, "state")
        identity = self._get_query_param(request, "identity")
        state_cookie_value = self._get_cookie(request, self.config.state_cookie_name)
        try:
            state_data = parse_state_cookie_value(state_cookie_value, self.config.session_signing_secret)
        except InvalidSessionError as exc:
            self._delete_cookie(response, self.config.state_cookie_name)
            raise InvalidStateError(str(exc)) from exc
        if state_param != state_data["state"]:
            self._delete_cookie(response, self.config.state_cookie_name)
            raise InvalidStateError("state mismatch")
        try:
            assertion = decrypt_callback_assertion(
                identity,
                self.config.callback_secret,
                self.config.client_id,
                derive_issuer_from_base_url(self.config.newton_api_base),
            )
        except InvalidCallbackAssertionError:
            self._delete_cookie(response, self.config.state_cookie_name)
            raise
        if not assertion.get("sub") or not assertion.get("platform_token"):
            self._delete_cookie(response, self.config.state_cookie_name)
            raise InvalidCallbackAssertionError("assertion missing required fields")

        first_name = assertion.get("first_name", "")
        last_name = assertion.get("last_name", "")
        email = assertion.get("email", "")

        session_cookie_value = build_session_cookie_value(
            uid=assertion["sub"],
            platform_token=assertion["platform_token"],
            authorized=bool(assertion["authorized"]),
            session_ttl_seconds=int(assertion["session_ttl_seconds"]),
            secret=self.config.session_signing_secret,
            client_id=self.config.client_id,
        )
        self._set_cookie(
            response,
            self.config.session_cookie_name,
            session_cookie_value,
            max_age=int(assertion["session_ttl_seconds"]),
        )
        self._delete_cookie(response, self.config.state_cookie_name)
        self.cache.set(
            assertion["sub"],
            {
                "authenticated": bool(assertion["authenticated"]),
                "authorized": bool(assertion["authorized"]),
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "client_cache_ttl_seconds": int(assertion["client_cache_ttl_seconds"]),
            },
        )
        return CallbackResult(
            redirect_uri=state_data["redirect_uri"],
            user=NewtonUser(
                uid=assertion["sub"],
                authorized=bool(assertion["authorized"]),
                first_name=first_name,
                last_name=last_name,
                email=email,
            ),
            client_cache_ttl_seconds=int(assertion["client_cache_ttl_seconds"]),
            session_ttl_seconds=int(assertion["session_ttl_seconds"]),
        )

    def clear_session(self, response) -> None:
        self._delete_cookie(response, self.config.session_cookie_name)
        self._delete_cookie(response, self.config.state_cookie_name)

    def logout(self, request, response) -> None:
        self.clear_session(response)

    def close(self) -> None:
        self.http.close()

    def _build_callback_uri(self, request) -> str:
        return "{}{}".format(self._get_origin(request).rstrip("/"), self.config.callback_path)

    @staticmethod
    def _get_origin(request) -> str:
        raise NotImplementedError

    @staticmethod
    def _get_current_path(request) -> str:
        raise NotImplementedError

    @staticmethod
    def _get_query_param(request, name: str) -> str | None:
        raise NotImplementedError

    @staticmethod
    def _get_cookie(request, name: str) -> str | None:
        raise NotImplementedError

    @staticmethod
    def _set_cookie(response, name: str, value: str, max_age: int) -> None:
        raise NotImplementedError

    @staticmethod
    def _delete_cookie(response, name: str) -> None:
        raise NotImplementedError
