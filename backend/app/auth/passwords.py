"""Password hashing for the email+password login path. bcrypt directly, not
passlib — passlib is unmaintained (no release since 2020) and has broken on
newer Python. bcrypt silently truncates input past 72 bytes, so length is
validated at hash time rather than relying on truncation, which would let two
different long passwords that share a 72-byte prefix hash identically.
"""

import bcrypt

MAX_PASSWORD_BYTES = 72
MIN_PASSWORD_LENGTH = 12


class PasswordTooShortError(ValueError):
    def __init__(self) -> None:
        super().__init__(f"password must be at least {MIN_PASSWORD_LENGTH} characters")


class PasswordTooLongError(ValueError):
    def __init__(self) -> None:
        super().__init__(f"password must be at most {MAX_PASSWORD_BYTES} bytes")


def hash_password(plain: str) -> str:
    if len(plain) < MIN_PASSWORD_LENGTH:
        raise PasswordTooShortError()
    if len(plain.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise PasswordTooLongError()
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False
