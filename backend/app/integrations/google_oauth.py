"""Google OAuth: authorization URL, code exchange, ID token verification.

The `hd` (hosted domain) claim is the only thing that gates sign-in. It comes
back inside the signature-verified ID token, never from anything the caller
supplied earlier in the flow — the `hd=` param on the authorization URL is
purely a UI hint to Google and is trivially forgeable by whoever builds that
URL, so it must never be trusted for the actual decision.
"""

from __future__ import annotations

from urllib.parse import urlencode

import requests
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token

AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"


class GoogleOAuthError(RuntimeError):
    pass


def build_authorization_url(
    *, client_id: str, redirect_uri: str, state: str, hosted_domain_hint: str
) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "hd": hosted_domain_hint,  # hint only — never trusted on callback
        "prompt": "select_account",
    }
    return f"{AUTHORIZATION_ENDPOINT}?{urlencode(params)}"


def exchange_code_for_id_token(
    *, code: str, client_id: str, client_secret: str, redirect_uri: str
) -> str:
    response = requests.post(
        TOKEN_ENDPOINT,
        data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        timeout=10,
    )
    if response.status_code != 200:
        raise GoogleOAuthError(f"token exchange failed: {response.status_code} {response.text}")
    id_token_str = response.json().get("id_token")
    if not id_token_str:
        raise GoogleOAuthError("token exchange response had no id_token")
    return id_token_str


def verify_id_token(id_token_str: str, *, client_id: str) -> dict:
    """Verifies signature, issuer and audience. Raises GoogleOAuthError on failure."""
    try:
        return google_id_token.verify_oauth2_token(
            id_token_str, google_requests.Request(), audience=client_id
        )
    except ValueError as exc:
        raise GoogleOAuthError(f"invalid id token: {exc}") from exc
