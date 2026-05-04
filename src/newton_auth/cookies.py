import time

from newton_auth.crypto import (
    build_session_cookie_payload,
    decrypt_value,
    encrypt_value,
    sign_value,
    verify_signed_value,
)
from newton_auth.errors import InvalidSessionError


def build_state_cookie_value(state: str, redirect_uri: str, secret: str) -> str:
    return sign_value(
        {
            "state": state,
            "redirect_uri": redirect_uri,
            "exp": int(time.time()) + 300,
        },
        secret,
    )


def parse_state_cookie_value(cookie_value: str, secret: str) -> dict:
    data = verify_signed_value(cookie_value, secret)
    if int(time.time()) > int(data.get("exp", 0)):
        raise InvalidSessionError("state expired")
    return data


def build_session_cookie_value(
    uid,
    platform_token,
    authorized,
    session_ttl_seconds,
    secret: str,
    client_id: str,
) -> str:
    payload = build_session_cookie_payload(
        uid,
        platform_token,
        authorized,
        session_ttl_seconds,
    )
    return encrypt_value(payload, secret, aad=client_id.encode())


def parse_session_cookie_value(cookie_value: str, secret: str, client_id: str) -> dict:
    data = decrypt_value(cookie_value, secret, aad=client_id.encode())
    session_ttl_seconds = int(data.get("session_ttl_seconds", 0))
    issued_at = int(data.get("issued_at", 0))
    if session_ttl_seconds <= 0 or time.time() > issued_at + session_ttl_seconds:
        raise InvalidSessionError("session expired")
    if not data.get("uid") or not data.get("platform_token"):
        raise InvalidSessionError("invalid session payload")
    return data
