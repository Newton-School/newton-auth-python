from newton_auth.config import NewtonAuthConfig
from newton_auth.models import AuthResult, CallbackResult, NewtonUser, RedirectInstruction

__all__ = [
    "AsyncNewtonAuth",
    "AuthResult",
    "CallbackResult",
    "NewtonAuth",
    "NewtonAuthConfig",
    "NewtonUser",
    "RedirectInstruction",
]


def __getattr__(name: str):
    if name == "NewtonAuth":
        from newton_auth.core import NewtonAuth

        return NewtonAuth
    if name == "AsyncNewtonAuth":
        from newton_auth.async_core import AsyncNewtonAuth

        return AsyncNewtonAuth
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
