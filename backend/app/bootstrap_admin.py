"""Give a bootstrap admin a local password, from inside the api container.

The admin-only password endpoint cannot create the first admin login: calling
it needs an existing admin session, and with Google OAuth unconfigured there
is no other way to get one. This closes that loop for a fresh checkout without
adding an unauthenticated route — whoever can run a process in the api
container can already read .env.local and the database.

It is deliberately limited to addresses in BOOTSTRAP_ADMIN_EMAILS. Every other
account is still created through the audited admin UI.

Usage (password is read from the terminal, or from stdin when piped):

    docker compose -f docker-compose.yml -f docker-compose.local.yml \\
        exec api python -m app.bootstrap_admin admin@example.test
"""

from __future__ import annotations

import getpass
import sys

from sqlalchemy.orm import Session

from app.api.deps import bootstrap_admin_emails
from app.auth.passwords import PasswordTooLongError, PasswordTooShortError
from app.config import Settings, get_settings
from app.models.user import User
from app.services.users import get_or_create_user_by_email, set_user_password


class NotBootstrapAdminError(ValueError):
    def __init__(self, email: str) -> None:
        super().__init__(f"{email} is not listed in BOOTSTRAP_ADMIN_EMAILS")


def set_bootstrap_admin_password(db: Session, *, email: str, password: str, settings: Settings) -> User:
    email = email.strip().lower()
    if email not in bootstrap_admin_emails(settings):
        raise NotBootstrapAdminError(email)
    # The admin is recorded as its own actor: there is no other identity to
    # attribute the change to, and audit_log.user_id is not nullable.
    actor = get_or_create_user_by_email(db, email=email)
    return set_user_password(db, email=email, new_password=password, actor_user_id=actor.id)


def _read_password() -> str:
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("New password: ")
    if first != getpass.getpass("Repeat password: "):
        raise SystemExit("error: passwords do not match")
    return first


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m app.bootstrap_admin <email>", file=sys.stderr)
        return 2

    from app.db import get_session_factory

    db = get_session_factory()()
    try:
        user = set_bootstrap_admin_password(db, email=args[0], password=_read_password(), settings=get_settings())
    except (NotBootstrapAdminError, PasswordTooShortError, PasswordTooLongError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()
    print(f"Password set for {user.email}. Sign in at the local login page.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
