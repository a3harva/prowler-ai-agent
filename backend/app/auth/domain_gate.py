"""The domain gate — kept pure and separate so it's testable without a network
call to Google. Only ever called with claims that already passed signature
verification; never with anything read directly off the request.
"""


class DomainNotAllowedError(RuntimeError):
    def __init__(self, hd_claim: str | None, allowed_domain: str):
        super().__init__(
            f"sign-in refused: account domain '{hd_claim}' is not '{allowed_domain}'"
        )
        self.hd_claim = hd_claim


def check_hosted_domain(claims: dict, *, allowed_domain: str) -> None:
    if claims.get("hd") != allowed_domain:
        raise DomainNotAllowedError(claims.get("hd"), allowed_domain)


def is_email_domain_allowed(email: str, *, allowed_domain: str) -> bool:
    """Used by the password login path, which has no verified `hd` claim to
    check — only the email itself. Google's callback keeps using
    check_hosted_domain above (the `hd` claim is more trustworthy than an
    email suffix), but both ultimately encode the same policy.
    """
    _, _, domain = email.strip().lower().rpartition("@")
    return domain == allowed_domain.lower()
