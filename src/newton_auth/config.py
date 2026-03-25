from dataclasses import dataclass, field


@dataclass(slots=True)
class NewtonAuthConfig:
    client_id: str
    client_secret: str
    callback_secret: str
    newton_api_base: str
    session_signing_secret: str | None = None
    callback_path: str = "/newton/callback"
    session_cookie_name: str = "newton_session"
    state_cookie_name: str = "newton_state"
    cache_max_mb: int = 1
    excluded_path_prefixes: tuple[str, ...] = field(default_factory=tuple)
