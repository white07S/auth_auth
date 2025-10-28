"""
Simple Fernet wrapper used to encrypt sensitive blobs (MSAL cache etc.).
"""

from __future__ import annotations

import base64
import os
from typing import ClassVar

from cryptography.fernet import Fernet


class CryptoService:
    _fernet: Fernet

    def __init__(self, secret: str) -> None:
        key = self._ensure_key(secret)
        self._fernet = Fernet(key)

    @staticmethod
    def _ensure_key(secret: str) -> bytes:
        # Fernet expects 32 url-safe base64-encoded bytes.  Accept raw 32-byte
        # secrets or arbitrary strings and stretch them.
        raw = secret.encode("utf-8")
        if len(raw) == 32:
            return base64.urlsafe_b64encode(raw)
        return base64.urlsafe_b64encode(raw.ljust(32, b"0")[:32])

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        return self._fernet.decrypt(token)
