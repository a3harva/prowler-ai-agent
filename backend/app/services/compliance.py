"""The compliance rulebook: which check satisfies which requirement of
which framework. `seed_rulebook_from_scan(...)` is the only place
`compliance_requirements` is ever written — it replaces the table's full
contents atomically from one scan's `compliance/` output directory, every
scan already produces one alongside its main CSV.

What these files actually are is easy to get wrong: each row is a *result*
(one check × one requirement × one scanned resource), not a rulebook row.
The rulebook is the project-independent subset — see the column split
below.
"""

from __future__ import annotations

import csv
import glob
import os
import random
from collections import Counter

from sqlalchemy import and_, delete, func, select
from sqlalchemy.orm import Session

from app.models.compliance_requirement import ComplianceRequirement
from app.models.finding import Finding, FindingStatus
from app.models.scan import ScanStatus
from app.services import audit
from app.services.rbac import ALL_DEPARTMENTS
from app.services.scans import ScanNotFoundError, get_scan
from app.services.errors import UnprocessableError

# Worst-first, matching the app's existing severity-ordering bias: a check
# that produced any FAIL among its resources counts as FAILing overall, and
# a check with no FAIL but at least one MANUAL counts as needs-review — a
# single all-PASS check is the only way to actually earn "pass".
_CHECK_VERDICT_RANK = {"fail": 0, "needs_review": 1, "pass": 2}

# Below this fraction of sampled COMPLIANCE-column requirement ids found in
# the loaded rulebook, a scan is flagged as drifted. Not 100%: some
# requirement ids legitimately collide across frameworks (e.g. "12.4"), so
# a handful of misses is expected noise, not a signal the rulebook is stale.
_COMPLIANCE_DRIFT_THRESHOLD = 0.5
# Enough rows to make the signal reliable without scanning the whole file —
# a sample, not an exhaustive per-row check. Randomly
# chosen, not the first N: scan CSV input is grouped by service, so the
# first N rows can all belong to one already-loaded framework while a
# newly-added one (the actual drift signal) only appears later in the file.
_COMPLIANCE_DRIFT_SAMPLE_SIZE = 50

# Present, with these exact names, in every one of the 21 framework files
# (derived from the public Prowler output format) — no per-framework
# parsing needed for the columns the rulebook actually keeps.
_REQUIREMENT_ID_COL = "REQUIREMENTS_ID"
_REQUIREMENT_DESCRIPTION_COL = "REQUIREMENTS_DESCRIPTION"
_CHECK_ID_COL = "CHECKID"
_FRAMEWORK_COL = "FRAMEWORK"
_FRAMEWORK_NAME_COL = "NAME"
# The framework-level description column — present in every file (unlike
# FRAMEWORK/NAME) — is the fallback source of a display name for CCC, the
# one file with no FRAMEWORK/NAME columns at all.
_FRAMEWORK_DESCRIPTION_COL = "DESCRIPTION"

# Result-bearing and project-bearing columns: keeping any of these would
# bake one customer's results into a table shared by every customer.
_DISCARDED_COLUMNS = {
    "PROVIDER", "STATUS", "STATUSEXTENDED", "RESOURCEID", "RESOURCENAME", "MUTED",
    "ASSESSMENTDATE", "PROJECTID", "ACCOUNTID", "LOCATION", "REGION",
    _REQUIREMENT_ID_COL, _REQUIREMENT_DESCRIPTION_COL, _CHECK_ID_COL,
    _FRAMEWORK_COL, _FRAMEWORK_NAME_COL, _FRAMEWORK_DESCRIPTION_COL,
}


class ScanNotSucceededError(UnprocessableError):
    def __init__(self, scan_id: int):
        super().__init__(f"scan {scan_id} has not succeeded — cannot seed the rulebook from it")
        self.scan_id = scan_id


class ComplianceDirectoryMissingError(UnprocessableError):
    def __init__(self, path: str):
        super().__init__(f"no compliance/ directory (or it is empty) at {path}")
        self.path = path


class ScanCsvMissingError(UnprocessableError):
    def __init__(self, path: str):
        super().__init__(f"scan.csv not found at {path} — cannot determine the scanner version")
        self.path = path


class EmptyRulebookError(UnprocessableError):
    def __init__(self, compliance_dir: str):
        super().__init__(
            f"no requirement rows could be parsed out of {compliance_dir} — refusing to replace "
            "the existing rulebook with an empty one"
        )
        self.compliance_dir = compliance_dir


def _read_prowler_csv_rows(path: str):
    """The one place a Prowler CSV (main or compliance) gets opened with the
    right delimiter — `;`, not the default `,`. A comma-parsed file still
    passes a naive header check and silently yields garbage."""
    with open(path, newline="") as f:
        yield from csv.DictReader(f, delimiter=";")


def _prowler_version_from_main_csv(reports_path: str) -> str:
    scan_csv_path = os.path.join(reports_path, "scan.csv")
    try:
        first_row = next(_read_prowler_csv_rows(scan_csv_path), None)
    except FileNotFoundError as exc:
        raise ScanCsvMissingError(scan_csv_path) from exc
    return (first_row or {}).get("PROWLER_VERSION") or "unknown"


def _parse_framework_file(path: str) -> list[dict]:
    """One file's rows, deduplicated to (framework, requirement_id,
    check_id) — the mapping repeats once per scanned resource, so a
    file can hold several times more rows than actual mappings."""
    rows_by_identity: dict[tuple[str, str, str, str], dict] = {}
    for row in _read_prowler_csv_rows(path):
        requirement_id = (row.get(_REQUIREMENT_ID_COL) or "").strip()
        check_id = (row.get(_CHECK_ID_COL) or "").strip()
        if not requirement_id or not check_id:
            continue

        framework = (row.get(_FRAMEWORK_COL) or "").strip()
        framework_name = (row.get(_FRAMEWORK_NAME_COL) or "").strip()
        if not framework:
            # CCC is the one file in the reference set with no
            # FRAMEWORK/NAME columns at all. Its REQUIREMENTS_ID values
            # are namespaced ("CCC.CntrReg.CN01.AR01"), so the segment
            # before the first "." is a content-derived framework code
            # — not a filename, and not specific to CCC by name (this
            # branch runs for any file missing FRAMEWORK, not "if CCC").
            framework = requirement_id.split(".", 1)[0] or "UNKNOWN"
            framework_name = framework_name or (row.get(_FRAMEWORK_DESCRIPTION_COL) or "").strip() or framework

        framework_name = framework_name or framework
        # framework_name is part of the identity, not just framework — the
        # real CIS files all share FRAMEWORK="CIS" and only differ by NAME
        # ("... Benchmark v2.0.0" vs "v3.0.0" ...), matching the table's
        # own unique constraint (see the model for the full story).
        identity = (framework, framework_name, requirement_id, check_id)
        if identity in rows_by_identity:
            continue

        attributes = {
            key.lower(): value
            for key, value in row.items()
            if key not in _DISCARDED_COLUMNS and value not in (None, "")
        }
        rows_by_identity[identity] = {
            "framework": framework,
            "framework_name": framework_name,
            "requirement_id": requirement_id,
            "requirement_description": row.get(_REQUIREMENT_DESCRIPTION_COL) or None,
            "check_id": check_id,
            "attributes": attributes,
        }
    return list(rows_by_identity.values())


def seed_rulebook_from_scan(db: Session, *, scan_id: int, actor_user_id: int) -> dict:
    """Discards everything result- and project-bearing, deduplicates what
    remains, and replaces `compliance_requirements` in one transaction — a
    half-replaced rulebook silently produces wrong percentages on the
    report built on top of this table, which is the worst
    outcome available to a screen whose output reaches customers."""
    try:
        # Rulebook seeding is a global-admin action over a project-independent
        # table, so there is no per-department scope to apply here. Stated
        # explicitly rather than inherited by omission.
        scan = get_scan(db, scan_id=scan_id, visible_department_ids=ALL_DEPARTMENTS)
    except ScanNotFoundError as exc:
        raise ScanNotSucceededError(scan_id) from exc
    if scan.status != ScanStatus.succeeded or scan.reports_path is None:
        raise ScanNotSucceededError(scan_id)

    compliance_dir = os.path.join(scan.reports_path, "compliance")
    framework_files = sorted(glob.glob(os.path.join(compliance_dir, "*.csv")))
    if not framework_files:
        raise ComplianceDirectoryMissingError(compliance_dir)

    prowler_version = _prowler_version_from_main_csv(scan.reports_path)

    all_rows: list[dict] = []
    for path in framework_files:
        all_rows.extend(_parse_framework_file(path))

    # A compliance/ directory that exists but yields zero parseable rows
    # (e.g. Prowler renamed REQUIREMENTS_ID/CHECKID) must abort rather than
    # replace a working rulebook with an empty one — the exact "half-
    # replaced rulebook silently produces wrong percentages" failure this
    # function's own docstring calls the worst available outcome.
    if not all_rows:
        raise EmptyRulebookError(compliance_dir)

    before_value = {"requirement_count": db.execute(select(func.count(ComplianceRequirement.id))).scalar_one()}

    db.execute(delete(ComplianceRequirement))
    db.execute(
        ComplianceRequirement.__table__.insert(),
        [{**row, "prowler_version": prowler_version} for row in all_rows],
    )

    # Grouped by (framework, framework_name), not `framework` alone — the
    # real files prove `framework` alone isn't a distinct-version key (see
    # the model's identity comment), and `framework_name` is what actually
    # tells CIS 2.0 apart from CIS 3.0/4.0/5.0.
    framework_pairs = sorted({(row["framework"], row["framework_name"]) for row in all_rows})
    after_value = {
        "requirement_count": len(all_rows),
        "framework_count": len(framework_pairs),
        "prowler_version": prowler_version,
        "source_scan_id": scan_id,
    }
    audit.record(
        db,
        user_id=actor_user_id,
        action_type="compliance_rulebook.seed",
        target_type="compliance_rulebook",
        target_id=str(scan_id),
        before_value=before_value,
        after_value=after_value,
    )
    db.commit()

    return {
        "framework_count": len(framework_pairs),
        "requirement_count": len(all_rows),
        "prowler_version": prowler_version,
        # framework_name, not the raw framework code — that's the field
        # that actually reads as "CIS 2.0" vs "CIS 3.0" instead of "CIS"
        # four times over.
        "frameworks": [name for _framework, name in framework_pairs],
    }


def detect_compliance_drift(db: Session, data_rows: list[list[str]], col_index: dict[str, int]) -> bool:
    """Each main-CSV row carries its own framework mappings inline in
    COMPLIANCE (`C5-2025: OPS-25.01B, ... | PCI-4.0: 11.3.1.2.1, ...`).
    Sampling those requirement ids against the loaded rulebook catches the
    real failure mode — upgrade Prowler, forget to reload the rulebook,
    the compliance report silently drifts — for near-zero cost. Matching is
    on requirement id alone, not the inline framework label: the label
    ("C5-2025", "PCI-4.0") doesn't always equal the rulebook's own
    `framework` value ("C5", "PCI"), so label matching would false-positive
    on every load.

    Lives here rather than in `services/importer.py`: this is the one
    place that reads `compliance_requirements`, keeping the table's only
    two read paths (seeding's own dedup and this) in the module that owns
    it, rather than importer.py reaching in independently.
    """
    known_ids = set(db.execute(select(ComplianceRequirement.requirement_id).distinct()).scalars())
    if not known_ids:
        return False  # nothing loaded yet — not a drift signal

    compliance_col = col_index.get("COMPLIANCE")
    if compliance_col is None:
        return False

    sample = data_rows if len(data_rows) <= _COMPLIANCE_DRIFT_SAMPLE_SIZE else random.sample(
        data_rows, _COMPLIANCE_DRIFT_SAMPLE_SIZE
    )

    referenced_ids: set[str] = set()
    for row in sample:
        compliance_field = row[compliance_col]
        if not compliance_field:
            continue
        for segment in compliance_field.split("|"):
            if ":" not in segment:
                continue
            _, ids_part = segment.split(":", 1)
            referenced_ids.update(req_id.strip() for req_id in ids_part.split(",") if req_id.strip())

    if not referenced_ids:
        return False
    matched = referenced_ids & known_ids
    return (len(matched) / len(referenced_ids)) < _COMPLIANCE_DRIFT_THRESHOLD


def list_frameworks(db: Session, *, project_id: int) -> list[dict]:
    """Every framework in the loaded rulebook, ordered by how many of its
    distinct mapped checks actually have a finding in this project right
    now — "most-used" as a live, per-project signal rather than a static
    rulebook-size ranking or a hardcoded list, so a framework becoming
    relevant to a customer never needs a code change to surface first."""
    match_count = func.count(func.distinct(Finding.check_id))
    stmt = (
        select(ComplianceRequirement.framework, ComplianceRequirement.framework_name, match_count)
        .select_from(ComplianceRequirement)
        .outerjoin(
            Finding,
            (Finding.check_id == ComplianceRequirement.check_id) & (Finding.project_id == project_id),
        )
        .group_by(ComplianceRequirement.framework, ComplianceRequirement.framework_name)
        .order_by(match_count.desc(), ComplianceRequirement.framework_name)
    )
    return [
        {"framework": framework, "framework_name": framework_name, "match_count": count}
        for framework, framework_name, count in db.execute(stmt).all()
    ]


def compliance_report(
    db: Session, *, project_id: int, framework: str, framework_name: str, include_muted: bool = False
) -> dict:
    """Live, uncached: joins the project's current findings against the
    loaded rulebook and rolls up to requirement level. Nothing here is
    precomputed or stored, so a report is never stale relative to the
    findings behind it.

    Rollup is two-stage, because one check produces many findings (one per
    resource): a check's own verdict for this project is the worst
    (FAIL > needs_review > pass) among its own findings, and a requirement
    then passes only if every one of its mapped checks that produced a
    verdict at all passed — the "every mapped check with a result passes"
    rule, read at check granularity rather than per-resource.

    `RESOURCE_DOES_NOT_EXIST` findings never contribute to a check's
    verdict — a resource that's gone can't attest current compliance —
    which is the same treatment a check with zero remaining findings gets:
    it simply produces no verdict, and any requirement that leans on it
    solely falls back to `not_assessed` rather than lying with a stale PASS.

    One query, not two: the rulebook rows and the matching findings are
    pulled with a single LEFT JOIN (filters that would otherwise drop an
    unmatched requirement live in the join's ON clause, not a WHERE), so a
    framework with no findings yet still returns every requirement as
    `not_assessed` instead of an empty result set.
    """
    join_conditions = [
        Finding.check_id == ComplianceRequirement.check_id,
        Finding.project_id == project_id,
        Finding.status != FindingStatus.RESOURCE_DOES_NOT_EXIST,
    ]
    if not include_muted:
        join_conditions.append(Finding.muted.is_(False))

    stmt = (
        select(
            ComplianceRequirement.requirement_id,
            ComplianceRequirement.requirement_description,
            ComplianceRequirement.check_id,
            Finding.status,
        )
        .select_from(ComplianceRequirement)
        .outerjoin(Finding, and_(*join_conditions))
        .where(
            ComplianceRequirement.framework == framework,
            ComplianceRequirement.framework_name == framework_name,
        )
    )

    requirements: dict[str, dict] = {}
    check_verdicts_raw: dict[str, list[str]] = {}
    for requirement_id, requirement_description, check_id, status in db.execute(stmt).all():
        entry = requirements.setdefault(
            requirement_id, {"description": requirement_description, "check_ids": set()}
        )
        entry["check_ids"].add(check_id)
        if status is not None:
            if status == FindingStatus.FAIL:
                verdict = "fail"
            elif status == FindingStatus.MANUAL:
                verdict = "needs_review"
            else:
                verdict = "pass"
            check_verdicts_raw.setdefault(check_id, []).append(verdict)

    check_verdicts: dict[str, str] = {
        check_id: min(verdicts, key=lambda v: _CHECK_VERDICT_RANK[v])
        for check_id, verdicts in check_verdicts_raw.items()
    }

    requirement_results = []
    for requirement_id, entry in sorted(requirements.items()):
        mapped_verdicts = [check_verdicts[c] for c in entry["check_ids"] if c in check_verdicts]
        status = min(mapped_verdicts, key=lambda v: _CHECK_VERDICT_RANK[v]) if mapped_verdicts else "not_assessed"
        requirement_results.append(
            {
                "requirement_id": requirement_id,
                "requirement_description": entry["description"],
                "check_ids": sorted(entry["check_ids"]),
                "status": status,
            }
        )

    # Tallied from the computed `status` values themselves, not a parallel
    # set of counters incremented alongside the rollup loop above — the two
    # can't drift out of sync (total_requirements == the sum of all four)
    # because there is only one source of truth for a requirement's status.
    counts = Counter(r["status"] for r in requirement_results)
    passed, failed = counts["pass"], counts["fail"]
    total = passed + failed
    score_percent = round((passed / total) * 100) if total else None

    return {
        "framework": framework,
        "framework_name": framework_name,
        "summary": {
            "passed": passed,
            "failed": failed,
            "needs_review": counts["needs_review"],
            "not_assessed": counts["not_assessed"],
            "total_requirements": len(requirements),
            "score_percent": score_percent,
        },
        "requirements": requirement_results,
    }
