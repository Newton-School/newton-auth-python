from dataclasses import dataclass


@dataclass(slots=True)
class NewtonAuthConfig:
    client_id: str
    client_secret: str
    callback_secret: str
    newton_api_base: str
    session_signing_secret: str | None = None
    login_path: str = "/newton/login"
    callback_path: str = "/newton/callback"
    session_cookie_name: str = "newton_session"
    state_cookie_name: str = "newton_state"
    cache_max_mb: int = 1
    auth_timeout: float = 10.0
