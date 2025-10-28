from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def generate_state() -> str:
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    return secrets.token_urlsafe(32)


def generate_code_verifier() -> str:
    # 32 bytes random and urlsafe
    return secrets.token_urlsafe(64)


def derive_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64_urlsafe(digest)


def base64_urlsafe(data: bytes) -> str:
    return (
        base64_encode(data)
        .rstrip("=")
        .replace("+", "-")
        .replace("/", "_")
    )


def base64_encode(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def session_expiry(minutes: int) -> datetime:
    return now_utc() + timedelta(minutes=minutes)
