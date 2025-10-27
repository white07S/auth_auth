from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Tuple

from cryptography.fernet import Fernet, InvalidToken


class TokenEncryptor:
    def __init__(self, key: str) -> None:
        self._fernet = Fernet(key.encode("utf-8") if isinstance(key, str) else key)

    def encrypt(self, plaintext: str) -> str:
        token = plaintext.encode("utf-8")
        return self._fernet.encrypt(token).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        try:
            data = self._fernet.decrypt(ciphertext.encode("utf-8"))
        except InvalidToken as exc:
            raise ValueError("Failed to decrypt token cache.") from exc
        return data.decode("utf-8")


def hash_value(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8"))
    return digest.hexdigest()


def generate_session_id() -> str:
    return secrets.token_urlsafe(48)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def generate_state_nonce() -> Tuple[str, str]:
    return secrets.token_urlsafe(32), secrets.token_urlsafe(32)


def generate_pkce_pair() -> Tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = _code_challenge(verifier)
    return verifier, challenge


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)

