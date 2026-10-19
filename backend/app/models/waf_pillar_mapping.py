from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base

# The six pillars of the Google Cloud Well-Architected Framework, as published
# by the Architecture Center (last reviewed 2026-01-28). Order is report order.
#
# Sustainability is a full pillar here, not folded into another bucket. The
# AI/ML and Financial Services "perspectives" are lenses across all six, not
# additional buckets, and are deliberately not used for categorization.
WAF_PILLARS = (
    "Operational Excellence",
    "Security, Privacy & Compliance",
    "Reliability",
    "Cost Optimization",
    "Performance Optimization",
    "Sustainability",
)

SECURITY_PILLAR = "Security, Privacy & Compliance"


class WafPillarMapping(Base):
    """Prowler's own category tag → the WAF pillar a finding is reported under.

    Kept as data rather than a constant so a new Prowler tag can be mapped by an
    admin without a deploy, and — more importantly — so the fallback rule is
    *visible*. The `''` row is the fallback made explicit: 5.6% of findings in
    the reference scan carry no category at all, and a mapping that only covered
    the twelve real tags would have dropped them from a customer-facing report
    with nothing to show it had happened.

    Mapping lives at category level, not check level: twelve rows to maintain
    instead of several hundred, and Prowler adds checks far more often than it
    adds categories.
    """

    __tablename__ = "waf_pillar_mapping"

    category: Mapped[str] = mapped_column(String, primary_key=True)
    pillar: Mapped[str] = mapped_column(String, nullable=False)


# Seeded by the migration that creates the table. Prowler is a security scanner,
# so ten of the twelve tags are security concerns — Cost Optimization,
# Performance Optimization and Sustainability get no rows at all, which is why
# the report omits empty pillars rather than printing "not applicable".
DEFAULT_PILLAR_MAPPING: dict[str, str] = {
    "": SECURITY_PILLAR,  # no category — the explicit fallback, see above
    "encryption": SECURITY_PILLAR,
    "identity-access": SECURITY_PILLAR,
    "internet-exposed": SECURITY_PILLAR,
    "secrets": SECURITY_PILLAR,
    "trust-boundaries": SECURITY_PILLAR,
    "vulnerabilities": SECURITY_PILLAR,
    "node-security": SECURITY_PILLAR,
    "container-security": SECURITY_PILLAR,
    "forensics-ready": SECURITY_PILLAR,
    "gen-ai": SECURITY_PILLAR,
    "logging": "Operational Excellence",
    "resilience": "Reliability",
}
