from dataclasses import dataclass
from typing import Optional


@dataclass
class NewtonUser:
    uid: str
    authorized: bool
    first_name: str = ""
    last_name: str = ""
    email: str = ""


@dataclass
class AuthResult:
    authenticated: bool
    authorized: bool = False
    should_clear_session: bool = False
    user: NewtonUser | None = None
    client_cache_ttl_seconds: int | None = None
    session_ttl_seconds: int | None = None


@dataclass
class RedirectInstruction:
    location: str


@dataclass
class CallbackResult:
    redirect_uri: str
    user: Optional[NewtonUser]
    client_cache_ttl_seconds: int
    session_ttl_seconds: int
    # False when the login completed but the user is not authenticated
    # (e.g. no Newton account); user is None in that case.
    authenticated: bool = True
