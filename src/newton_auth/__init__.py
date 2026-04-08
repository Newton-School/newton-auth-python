from newton_auth.config import NewtonAuthConfig
from newton_auth.models import AuthResult, CallbackResult, NewtonUser, RedirectInstruction

__all__ = [
    "AuthResult",
    "CallbackResult",
    "NewtonAuthConfig",
    "NewtonUser",
    "RedirectInstruction",
]

try:
    from newton_auth.core import NewtonAuth

    __all__ += ["NewtonAuth"]
except ImportError:
    pass

try:
    from newton_auth.async_core import AsyncNewtonAuth

    __all__ += ["AsyncNewtonAuth"]
except ImportError:
    pass
