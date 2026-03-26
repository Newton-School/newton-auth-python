import base64
import hashlib
import hmac
import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from newton_auth.errors import InvalidCallbackAssertionError, InvalidSessionError


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


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
    key = hashlib.sha256(callback_secret.encode()).digest()
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
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
