# newton-auth-python

Backend-only Newton School authentication SDK for Python applications.

Current framework support:
- Django
- FastAPI

## Django usage

Add the callback middleware:

```python
MIDDLEWARE = [
    # ...
    "newton_auth.django.NewtonAuthMiddleware",
]
```

Configure the SDK:

```python
NEWTON_AUTH = {
    "CLIENT_ID": os.environ["NEWTON_AUTH_CLIENT_ID"],
    "CLIENT_SECRET": os.environ["NEWTON_AUTH_CLIENT_SECRET"],
    "CALLBACK_SECRET": os.environ["NEWTON_AUTH_CALLBACK_SECRET"],
    "NEWTON_API_BASE": os.environ.get("NEWTON_AUTH_BASE_URL", "https://auth.newtonschool.co/api/v1"),
    "CALLBACK_PATH": "/newton/callback",
    "CACHE_MAX_MB": 1,
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

Optional per-view unauthorized handler:

```python
from django.http import HttpResponseForbidden


def custom_unauthorized_handler(request, auth_result):
    return HttpResponseForbidden("custom forbidden page")


@newton_protected(unauthorized_handler=custom_unauthorized_handler)
def protected_view(request):
    ...
```

The middleware only handles the callback route. Route protection is controlled by `@newton_protected`.

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
)

app = FastAPI()
app.add_middleware(NewtonAuthMiddleware, auth=auth)
```

Protect routes explicitly with the dependency:

```python
@app.get("/protected")
async def protected_route(user=Depends(require_newton_auth(auth))):
    return {"uid": user.uid, "authorized": user.authorized}
```

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

The middleware only handles the callback route. Route protection is controlled by `require_newton_auth(...)`.

See [sdk-final-design.md](./sdk-final-design.md) for the current design.
