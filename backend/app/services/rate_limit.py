"""Redis-backed sliding-ish window throttle for the password login endpoint,
which — unlike Google OAuth — accepts a guessable credential directly from an
internet-reachable client. Keyed on (ip, email) rather than either alone: IP
alone punishes shared NATs/offices, email alone lets an attacker spray many
IPs at one account. INCR+EXPIRE is an approximate fixed window, not a true
sliding window — good enough for a first line of defense, not a precision
guarantee.
"""

import redis

from app.config import Settings

MAX_ATTEMPTS = 5
WINDOW_SECONDS = 15 * 60

_client: redis.Redis | None = None


def _get_client(settings: Settings) -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(settings.redis_url, decode_responses=True)
    return _client


def check_and_increment_login_attempts(*, ip: str, email: str, settings: Settings) -> bool:
    """Returns True if this attempt is allowed, False if the caller should be
    throttled (429). Increments unconditionally so a rejected attempt still
    counts against the window — otherwise retries would never actually cost
    the attacker anything.
    """
    client = _get_client(settings)
    key = f"login_attempts:{ip}:{email.strip().lower()}"
    count = client.incr(key)
    if count == 1:
        client.expire(key, WINDOW_SECONDS)
    return count <= MAX_ATTEMPTS
