# newton-auth-python

Backend-only Newton School authentication SDK for Python applications.

## Installation

Install from a Git tag so consumers get an immutable version instead of a moving branch head.

Django:

```bash
pip install "newton-auth[django] @ git+https://github.com/Newton-School/newton-auth-python.git@v0.1.0"
```

FastAPI:

```bash
pip install "newton-auth[fastapi] @ git+https://github.com/Newton-School/newton-auth-python.git@v0.1.0"
```

For local development:

```bash
pip install -e ".[dev]"
```

Current framework support:
- Django
- FastAPI

## Compatibility

The library currently targets:
- Python `>=3.10`
- Django integrations via the `django` extra
- FastAPI integrations via the `fastapi` extra

Dependency ownership is split by extra:
- Base package: `cryptography`
- `django` extra: `requests`
- `fastapi` extra: `fastapi`, `httpx`

Consumers should install only the extra they use.

## Django usage

Add the callback middleware:

```python
MIDDLEWARE = [
    # ...
    "newton_auth.django.NewtonAuthMiddleware",
]
```

The middleware owns two SDK routes:
- `/newton/login` starts the OAuth redirect flow
- `/newton/callback` completes the callback flow

Configure the SDK:

```python
NEWTON_AUTH = {
    "CLIENT_ID": os.environ["NEWTON_AUTH_CLIENT_ID"],
    "CLIENT_SECRET": os.environ["NEWTON_AUTH_CLIENT_SECRET"],
    "CALLBACK_SECRET": os.environ["NEWTON_AUTH_CALLBACK_SECRET"],
    "NEWTON_API_BASE": os.environ.get("NEWTON_AUTH_BASE_URL", "https://auth.newtonschool.co/api/v1"),
    "LOGIN_PATH": "/newton/login",
    "CALLBACK_PATH": "/newton/callback",
    "CACHE_MAX_MB": 1,
    "AUTH_TIMEOUT": 10.0,
}
```

Protect views explicitly with the decorator:

```python
from django.http import HttpResponse
from newton_auth.django import newton_protected


@newton_protected
def protected_view(request):
    return HttpResponse("hello {}".format(request.newton_user.uid))
```

Unauthenticated protected views return `401`. They do not redirect automatically.
Your frontend or browser page should explicitly navigate to `/newton/login?next=/protected` when it wants to start login.
The SDK rejects `/newton/login?next=/newton/login` to avoid redirect loops.

Optional per-view unauthorized handler:

```python
from django.http import HttpResponseForbidden


def custom_unauthorized_handler(request, auth_result):
    return HttpResponseForbidden("custom forbidden page")


@newton_protected(unauthorized_handler=custom_unauthorized_handler)
def protected_view(request):
    ...
```

Optional per-view unauthenticated handler:

```python
from django.http import JsonResponse


def custom_unauthenticated_handler(request, auth_result):
    return JsonResponse({"error": "login_required"}, status=401)


@newton_protected(unauthenticated_handler=custom_unauthenticated_handler)
def protected_view(request):
    ...
```

The middleware only handles `/newton/login` and `/newton/callback`. Route protection is controlled by `@newton_protected`.

## FastAPI usage

Create a shared auth instance and add the callback middleware:

```python
from fastapi import Depends, FastAPI
from newton_auth.fastapi import FastAPINewtonAuth, NewtonAuthMiddleware, require_newton_auth


auth = FastAPINewtonAuth(
    client_id=os.environ["NEWTON_AUTH_CLIENT_ID"],
    client_secret=os.environ["NEWTON_AUTH_CLIENT_SECRET"],
    callback_secret=os.environ["NEWTON_AUTH_CALLBACK_SECRET"],
    newton_api_base=os.environ.get("NEWTON_AUTH_BASE_URL", "https://auth.newtonschool.co/api/v1"),
    callback_path="/newton/callback",
    cache_max_mb=1,
    auth_timeout=10.0,
)

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app):
    yield
    await auth.aclose()


app = FastAPI(lifespan=lifespan)
app.add_middleware(NewtonAuthMiddleware, auth=auth)
```

The middleware owns two SDK routes:
- `/newton/login` starts the OAuth redirect flow
- `/newton/callback` completes the callback flow

Protect routes explicitly with the dependency:

```python
@app.get("/protected")
async def protected_route(user=Depends(require_newton_auth(auth))):
    return {"uid": user.uid, "authorized": user.authorized}
```

Unauthenticated protected routes return `401`. They do not redirect automatically.
Clients should explicitly navigate the browser to `/newton/login?next=/protected` when they want to start login.
The SDK rejects `/newton/login?next=/newton/login` to avoid redirect loops.

Optional unauthorized handler:

```python
from fastapi.responses import JSONResponse


def custom_unauthorized_handler(request, auth_result):
    return JSONResponse({"error": "custom forbidden"}, status_code=403)


@app.get("/protected")
async def protected_route(
    user=Depends(require_newton_auth(auth, unauthorized_handler=custom_unauthorized_handler))
):
    return {"uid": user.uid}
```

Optional unauthenticated handler:

```python
from fastapi.responses import JSONResponse


def custom_unauthenticated_handler(request, auth_result):
    return JSONResponse({"error": "login_required"}, status_code=401)


@app.get("/protected")
async def protected_route(
    user=Depends(require_newton_auth(auth, unauthenticated_handler=custom_unauthenticated_handler))
):
    return {"uid": user.uid}
```

The middleware only handles `/newton/login` and `/newton/callback`. Route protection is controlled by `require_newton_auth(...)`.

## Versioning And Releases

This repository uses semantic versioning.

- Patch releases are for fixes and non-breaking internal changes.
- Minor releases are for backwards-compatible features or config additions.
- Major releases are for breaking API or behavior changes.

Consumers should pin to a Git tag, not a branch name.
Each release should have:
- a version bump in `pyproject.toml`
- a matching Git tag like `v0.1.1`
- a GitHub Release
- a `CHANGELOG.md` entry

See [RELEASING.md](./RELEASING.md) for the release checklist and [CHANGELOG.md](./CHANGELOG.md) for version history.
