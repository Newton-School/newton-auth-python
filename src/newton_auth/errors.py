class NewtonAuthError(Exception):
    pass


class InvalidStateError(NewtonAuthError):
    pass


class InvalidCallbackAssertionError(NewtonAuthError):
    pass


class InvalidSessionError(NewtonAuthError):
    pass

