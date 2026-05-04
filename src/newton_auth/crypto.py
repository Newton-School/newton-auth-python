import base64
import functools
import hashlib
import hmac
import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from newton_auth.errors import InvalidCallbackAssertionError, InvalidSessionError

SESSION_WIRE_VERSION = "v2"


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


@functools.lru_cache(maxsize=64)
def _aesgcm_for(secret: str) -> AESGCM:
    return AESGCM(hashlib.sha256(secret.encode()).digest())


def decrypt_callback_assertion(identity: str, callback_secret: str, client_id: str, expected_issuer: str) -> dict:
    if not identity:
        raise InvalidCallbackAssertionError("missing assertion")
    parts = identity.split(".")
    if len(parts) != 4 or parts[0] != "v1":
        raise InvalidCallbackAssertionError("invalid assertion wire format")
    _, nonce_value, ciphertext_value, aad_value = parts
    nonce = b64url_decode(nonce_value)
    ciphertext = b64url_decode(ciphertext_value)
    aad = b64url_decode(aad_value)
    try:
        aad_text = aad.decode()
    except UnicodeDecodeError as exc:
        raise InvalidCallbackAssertionError("invalid assertion aad") from exc
    if aad_text != client_id:
        raise InvalidCallbackAssertionError("assertion audience mismatch")
    try:
        plaintext = _aesgcm_for(callback_secret).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise InvalidCallbackAssertionError("assertion decryption failed") from exc
    data = json.loads(plaintext)
    now_ts = int(time.time())
    if data.get("aud") != client_id:
        raise InvalidCallbackAssertionError("assertion aud mismatch")
    if data.get("iss") != expected_issuer:
        raise InvalidCallbackAssertionError("assertion issuer mismatch")
    if now_ts > int(data.get("exp", 0)):
        raise InvalidCallbackAssertionError("assertion expired")
    if int(data.get("iat", 0)) > now_ts + 30:
        raise InvalidCallbackAssertionError("assertion issued in future")
    return data


def sign_value(payload: dict, secret: str) -> str:
    payload_value = b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signature = hmac.new(secret.encode(), payload_value.encode(), hashlib.sha256).hexdigest()
    return "{}.{}".format(payload_value, signature)


def verify_signed_value(value: str, secret: str) -> dict:
    if not value or "." not in value:
        raise InvalidSessionError("invalid signed value")
    payload_value, signature = value.rsplit(".", 1)
    expected = hmac.new(secret.encode(), payload_value.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise InvalidSessionError("invalid signature")
    try:
        return json.loads(b64url_decode(payload_value))
    except Exception as exc:
        raise InvalidSessionError("invalid payload") from exc


def build_session_cookie_payload(
    uid: str,
    platform_token: str,
    authorized: bool,
    session_ttl_seconds: int,
) -> dict:
    return {
        "uid": uid,
        "platform_token": platform_token,
        "authorized": authorized,
        "session_ttl_seconds": session_ttl_seconds,
        "issued_at": int(time.time()),
        "nonce": b64url_encode(os.urandom(16)),
    }


def encrypt_value(payload: dict, secret: str, aad: bytes = b"") -> str:
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    nonce = os.urandom(12)
    ciphertext = _aesgcm_for(secret).encrypt(nonce, payload_bytes, aad)
    return "{}.{}.{}".format(
        SESSION_WIRE_VERSION,
        b64url_encode(nonce),
        b64url_encode(ciphertext),
    )


def decrypt_value(value: str, secret: str, aad: bytes = b"") -> dict:
    if not value:
        raise InvalidSessionError("missing encrypted value")
    parts = value.split(".")
    if len(parts) != 3 or parts[0] != SESSION_WIRE_VERSION:
        raise InvalidSessionError("invalid encrypted value wire format")
    _, nonce_value, ciphertext_value = parts
    try:
        nonce = b64url_decode(nonce_value)
        ciphertext = b64url_decode(ciphertext_value)
    except Exception as exc:
        raise InvalidSessionError("invalid encrypted value encoding") from exc
    try:
        plaintext = _aesgcm_for(secret).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise InvalidSessionError("decryption failed") from exc
    try:
        return json.loads(plaintext)
    except Exception as exc:
        raise InvalidSessionError("invalid payload") from exc
