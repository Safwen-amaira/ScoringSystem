from __future__ import annotations

import hashlib
import hmac
import os
import secrets


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    actual_salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), actual_salt.encode("utf-8"), 120000)
    return actual_salt, digest.hex()


def verify_password(password: str, salt: str, password_hash: str) -> bool:
    _, computed_hash = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, password_hash)


def issue_token() -> str:
    return secrets.token_urlsafe(32)


def default_admin_email() -> str:
    return os.getenv("HANICAR_ADMIN_EMAIL", "admin@hanicar.tn")


def default_admin_password() -> str:
    return os.getenv("HANICAR_ADMIN_PASSWORD", "bornasroot")
