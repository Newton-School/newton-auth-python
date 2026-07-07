# Newton Auth Python SDK Final Design

## Overview

`newton-auth-python` is a backend-only authentication SDK for Newton School hosted applications.

It integrates application backends with `auth.newtonschool.co` / `newton-api` and handles:

- redirecting unauthenticated users to Newton auth
- validating the encrypted callback assertion
- creating and verifying app-local session cookies
- caching authorization decisions locally
- revalidating platform auth state with `newton-api`
- clearing stale cookies when platform tokens are revoked or invalid

This SDK is not intended for frontend-only applications.

---

## Goals

- Backend-only integration
- Minimal app-side integration effort
- Correct handling of `authenticated` vs `authorized`
- Support for multiple Python frameworks
- Fast steady-state auth path via local cookie + local LRU
- Central revocation propagation from `newton-api`
- Server-driven auth policy for:
  - client cache TTL
  - app session TTL

---

## Server Contract

The SDK integrates with the `platform_auth` endpoints on `newton-api`.

### Login Redirect

```text
GET /api/v1/platform-auth/login?client_id=...&state=...&redirect_uri=...
```

Behavior:

- `newton-api` authenticates user via Django session / Google login
- mints or reuses a DOT access token for `(user, app)`
- returns a short-lived AES-GCM encrypted callback assertion via redirect

### Callback Assertion Payload

After decrypting the `identity` query param, the SDK should expect:

```json
{
  "sub": "usr_abc123",
  "aud": "app_client_id",
  "iss": "https://auth.newtonschool.co",
  "authenticated": true,
  "authorized": true,
  "client_cache_ttl_seconds": 60,
  "session_ttl_seconds": 86400,
  "platform_token": "dot_access_token",
  "iat": 1710000000,
  "exp": 1710000060,
  "nonce": "..."
}
```

### Callback Assertion Wire Format

The encrypted `identity` query parameter is transported as:

```text
v1.<b64url_nonce>.<b64url_ciphertext>.<b64url_aad>
```

Definitions:

- `v1`: assertion wire-format version
- `nonce`: 12-byte AES-GCM nonce, base64url-encoded
- `ciphertext`: AES-GCM encrypted payload, base64url-encoded
- `aad`: additional authenticated data, base64url-encoded

Current server behavior:

- `aad` is the target app `client_id`
- AES-GCM key is derived as:

```python
hashlib.sha256(callback_secret.encode()).digest()
```

SDK decryption must:

- parse the 4 dot-separated parts
- verify version is `v1`
- base64url-decode `nonce`, `ciphertext`, and `aad`
- decrypt using AES-GCM with:
  - key = `sha256(callback_secret.encode()).digest()`
  - nonce = decoded nonce
  - ciphertext = decoded ciphertext
  - associated data = decoded aad
- verify that decoded `aad` equals configured `client_id`

### Authorization Revalidation

```text
POST /api/v1/platform-auth/auth/check/
Authorization: Basic base64(client_id:client_secret)
```

Request:

```json
{
  "uid": "usr_abc123",
  "platform_token": "dot_access_token"
}
```

Response:

```json
{
  "authenticated": true,
  "authorized": true,
  "uid": "usr_abc123",
  "client_cache_ttl_seconds": 60,
  "session_ttl_seconds": 86400,
  "should_clear_session": false
}
```

Important distinction:

- `authenticated=false` means app should clear local session and redirect to auth
- `authenticated=true, authorized=false` means app should keep local session and show unauthorized behavior without redirecting to auth

---

## Repo Structure

```text
newton-auth-python/
  pyproject.toml
  README.md
  sdk-final-design.md
  src/
    newton_auth/
      __init__.py
      config.py
      core.py
      crypto.py
      cookies.py
      cache.py
      http.py
      models.py
      errors.py
      django.py
      fastapi.py
      wsgi.py
      utils.py
  tests/
    test_crypto.py
    test_cookies.py
    test_cache.py
    test_core.py
    test_django.py
    test_fastapi.py
```

---

## Core Design

The SDK should be built around one framework-agnostic core.

Primary class:

```python
from newton_auth import NewtonAuth
```

The framework wrappers should only adapt request/response objects and delegate to the core.

This keeps:

- Django behavior consistent with FastAPI behavior
- cookie handling centralized
- protocol logic in one place

---

## Public API

### Initialization

```python
auth = NewtonAuth(
    client_id="...",
    client_secret="...",
    callback_secret="...",
    newton_api_base="https://auth.newtonschool.co/api/v1",
    callback_path="/newton/callback",
    cache_max_mb=1,
)
```

Public config should include:

- `client_id`
- `client_secret`
- `callback_secret`
- `newton_api_base`
- `callback_path`
- `cache_max_mb`
- optional cookie names / domain overrides if required

Public config should not include:

- session TTL default
- cache TTL default

Those are server-driven.

---

## Core Methods

`NewtonAuth` should provide:

- `authenticate(request, response=None) -> AuthResult`
- `build_login_redirect(request, response) -> RedirectInstruction`
- `handle_callback(request, response) -> CallbackResult`
- `clear_session(response) -> None`
- `logout(request, response) -> None`

### `authenticate()`

This method should:

1. parse and verify local app session cookie
2. if invalid:
   - clear stale cookies
   - return `authenticated=False`
3. check in-memory LRU for `uid`
4. on hit:
   - return cached result
5. on miss:
   - call `/platform-auth/auth/check/`
   - update local cache
   - clear local session if `should_clear_session=true`
   - return `authenticated` and `authorized` separately

Important:

- `authenticate()` should not itself redirect
- redirect is the responsibility of middleware/wrapper code

---

## Request Flow

### 1. Protected route, no valid session

- middleware calls `authenticate()`
- result is `authenticated=False`
- middleware calls `build_login_redirect()`
- SDK:
  - generates state
  - stores signed state cookie
  - redirects to `newton-api`

State cookie payload:

```json
{
  "state": "random_128_bit_value",
  "redirect_uri": "/protected",
  "exp": 1710000300
}
```

Notes:

- this cookie is owned by the SDK
- it should be signed locally by the SDK for integrity
- it should be short-lived, recommended 5 minutes
- it must be deleted after callback success or failure

### 2. Callback

- middleware or callback route calls `handle_callback()`
- SDK:
  - validates state cookie
  - decrypts callback assertion with `callback_secret`
  - validates `aud`, `iss`, `iat`, `exp`
  - extracts:
    - `sub`
    - `authorized`
    - `platform_token`
    - `client_cache_ttl_seconds`
    - `session_ttl_seconds`
  - creates app-local session cookie
  - seeds local cache
  - deletes temporary state cookie
  - redirects to original route

### 3. Subsequent requests

- SDK validates session cookie locally
- local cache hit -> immediate decision
- local cache miss -> `/auth/check/`

---

## Session Cookie

The SDK should create an app-local session cookie containing:

```json
{
  "uid": "usr_abc123",
  "platform_token": "dot_access_token",
  "authorized": true,
  "session_ttl_seconds": 86400,
  "issued_at": 1710000000,
  "nonce": "..."
}
```

Properties:

- signed locally by the SDK
- `HttpOnly`
- `Secure`
- `SameSite=Lax`
- app-domain scoped

Notes:

- the cookie should be signed for integrity
- the cookie does not need encryption by default
- the session lifetime should be enforced using `session_ttl_seconds` returned by `newton-api`

---

## Local Cache

The SDK maintains an in-memory LRU cache.

Key:

```text
uid
```

Value:

```json
{
  "authenticated": true,
  "authorized": false,
  "client_cache_ttl_seconds": 60,
  "_cached_at": 1710000000
}
```

Rules:

- TTL comes from server response or callback assertion
- cache max size is controlled by SDK config
- no email or profile data should be cached for now

Why cache size remains app-side:

- it is a process/global memory policy
- it depends on the app’s memory footprint
- it is not an auth-policy field per app on `newton-api`

---

## Auth Result Semantics

Core result type:

```python
AuthResult(
    authenticated: bool,
    authorized: bool,
    should_clear_session: bool,
    user: NewtonUser | None,
    client_cache_ttl_seconds: int | None,
    session_ttl_seconds: int | None,
)
```

Behavior:

### Case 1 — invalid/missing local session

- `authenticated=False`
- `authorized=False`
- middleware redirects to auth

### Case 2 — cache hit

- return cached `authenticated` and `authorized`

### Case 3 — cache miss, auth check says `authenticated=False`

- clear local session cookie
- return unauthenticated
- middleware redirects to auth

### Case 4 — cache miss, auth check says `authenticated=True, authorized=False`

- keep session
- cache unauthorized result
- middleware should not redirect to auth
- middleware should return unauthorized behavior

### Case 5 — cache miss, auth check says `authenticated=True, authorized=True`

- keep session
- cache authorized result
- middleware continues request

---

## Cookie Clearing Rules

The SDK must aggressively clear stale cookies.

Clear the local app session cookie when:

- session cookie signature is invalid
- session cookie is expired
- callback assertion is invalid or expired
- `/auth/check/` returns `should_clear_session=true`
- local `uid` and server-validated token do not match

Clear temporary state cookie when:

- callback succeeds
- callback fails
- callback assertion cannot be validated

This avoids stale-cookie loops.

---

## Middleware Design

The SDK should provide framework-native middleware.

### Django

- `newton_auth.django.NewtonAuthMiddleware`

Behavior:

- handles callback path
- protects configured routes
- attaches `request.newton_user`
- redirects when unauthenticated
- returns unauthorized handler response when authenticated but unauthorized

### FastAPI

- middleware or dependency adapter

Behavior:

- identical auth semantics
- attaches user info to `request.state.newton_user`

### Generic WSGI

- wrapper for generic WSGI frameworks and apps such as Flask or plain WSGI services

Clarification:

- `wsgi.py` is not a FastAPI fallback
- FastAPI is ASGI-native and should use `fastapi.py`
- `wsgi.py` exists for WSGI-only frameworks

---

## Unauthorized Handling

The SDK should ship with a default unauthorized handler and allow override.

Default behavior:

- HTML/browser request -> simple 403 page
- JSON/API request -> `{"error": "forbidden"}`

Override support:

```python
auth = NewtonAuth(
    ...,
    unauthorized_handler=my_handler,
)
```

The handler should receive:

- request
- response
- `AuthResult`

This lets applications:

- render custom HTML
- return framework-native responses
- emit JSON
- redirect elsewhere if they choose

---

## Internal Modules

### `config.py`

Typed config object for SDK initialization.

### `crypto.py`

Responsibilities:

- verify/decrypt callback assertion using AES-GCM
- sign/verify app session cookies

### `cookies.py`

Responsibilities:

- build session cookie payload
- parse session cookie
- set and clear cookies via framework adapter

### `cache.py`

Responsibilities:

- bounded in-memory LRU cache
- per-entry TTL enforcement

### `http.py`

Responsibilities:

- call `/platform-auth/auth/check/`
- isolate request/response parsing
- keep network code mockable

### `models.py`

Shared types:

- `NewtonUser`
- `AuthResult`
- `CallbackResult`
- `RedirectInstruction`

### `core.py`

Main protocol implementation.

---

## Security Considerations

- callback assertion is the only browser-transported encrypted auth artifact
- app session cookie includes `platform_token`, so it must be:
  - `HttpOnly`
  - `Secure`
  - integrity-protected
- local session cookie should be cleared immediately when platform token is invalidated
- `authenticated` and `authorized` must not be collapsed into one boolean
- callback validation must enforce:
  - state match
  - `aud`
  - `iss`
  - `iat`
  - `exp`

---

## Testing Plan

Required tests:

- state cookie validation
- callback assertion decrypt success/failure
- callback assertion expiry handling
- callback assertion audience mismatch
- session cookie tamper detection
- local session expiry using server-provided `session_ttl_seconds`
- cache hit/miss behavior
- `authenticated=false` clears session and redirects
- `authenticated=true, authorized=false` does not redirect to login
- Django middleware callback flow
- Django middleware unauthorized flow
- FastAPI integration smoke tests

---

## V1 Implementation Order

1. `models.py`
2. `config.py`
3. `crypto.py`
4. `cookies.py`
5. `cache.py`
6. `http.py`
7. `core.py`
8. `django.py`
9. `README.md`
10. tests

Recommended first usable target:

- complete Django integration first
- then add FastAPI wrapper

Optional V1 add-on:

- `wsgi.py` for Flask / generic WSGI apps if needed immediately

---

## Final Design Summary

The Python SDK will:

- be backend-only
- use `newton-api` as the source of truth
- store app-local signed session cookies
- keep a bounded local LRU for performance
- honor server-provided:
  - `client_cache_ttl_seconds`
  - `session_ttl_seconds`
- preserve separate `authenticated` and `authorized` semantics
- clear local cookies when platform tokens are invalid or revoked
- provide built-in middleware for common Python frameworks

This keeps auth policy centralized while keeping application integration simple and fast.
