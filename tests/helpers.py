"""Shared helpers for building valid crypto artefacts in tests."""

import hashlib
import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from newton_auth.cookies import build_session_cookie_value
from newton_auth.crypto import b64url_encode

# Shared test credentials — must stay consistent across both Django and FastAPI tests
CLIENT_ID = "test-client"
CLIENT_SECRET = "test-secret"
CALLBACK_SECRET = "test-callback-secret"
NEWTON_API_BASE = "https://api.example.com"
# session_signing_secret defaults to client_secret when not provided
SESSION_SIGNING_SECRET = CLIENT_SECRET
ISSUER = "https://api.example.com"  # derive_issuer_from_base_url(NEWTON_API_BASE)


def build_callback_assertion(
    *,
    sub: str = "user-123",
    platform_token: str = "tok-abc",
    authorized: bool = True,
    authenticated: bool = True,
    session_ttl_seconds: int = 86400,
    client_cache_ttl_seconds: int = 60,
    client_id: str = CLIENT_ID,
    callback_secret: str = CALLBACK_SECRET,
    issuer: str = ISSUER,
    exp_offset: int = 300,
    first_name: str = "",
    last_name: str = "",
    email: str = "",
) -> str:
    """Build a valid v1 callback assertion as Newton API would produce it."""
    now = int(time.time())
    payload = {
        "sub": sub,
        "platform_token": platform_token,
        "authorized": authorized,
        "authenticated": authenticated,
        "session_ttl_seconds": session_ttl_seconds,
        "client_cache_ttl_seconds": client_cache_ttl_seconds,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "aud": client_id,
        "iss": issuer,
        "iat": now,
        "exp": now + exp_offset,
    }
    key = hashlib.sha256(callback_secret.encode()).digest()
    nonce = os.urandom(12)
    aad = client_id.encode()
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(payload).encode(), aad)
    return "v1.{}.{}.{}".format(b64url_encode(nonce), b64url_encode(ciphertext), b64url_encode(aad))


def build_valid_session_cookie(
    *,
    uid: str = "user-123",
    platform_token: str = "tok-abc",
    authorized: bool = True,
    session_ttl_seconds: int = 86400,
    secret: str = SESSION_SIGNING_SECRET,
    client_id: str = CLIENT_ID,
) -> str:
    return build_session_cookie_value(
        uid=uid,
        platform_token=platform_token,
        authorized=authorized,
        session_ttl_seconds=session_ttl_seconds,
        secret=secret,
        client_id=client_id,
    )


def auth_check_ok(
    uid: str = "user-123",
    authorized: bool = True,
    first_name: str = "",
    last_name: str = "",
    email: str = "",
) -> dict:
    return {
        "authenticated": True,
        "authorized": authorized,
        "uid": uid,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "client_cache_ttl_seconds": 60,
        "session_ttl_seconds": 86400,
        "should_clear_session": False,
    }


def auth_check_revoked(uid: str = "user-123") -> dict:
    return {
        "authenticated": False,
        "authorized": False,
        "uid": uid,
        "first_name": "",
        "last_name": "",
        "email": "",
        "client_cache_ttl_seconds": 60,
        "session_ttl_seconds": 86400,
        "should_clear_session": True,
    }
