"""Single write path for `findings`. `import_scan_results(scan_id)` is the
only place a finding is ever written, whoever calls it (only the worker,
today) — matching `services/scans.py`'s role for the `scans` table.

Every gate here aborts the *whole* import with nothing written on failure. A
partial import is worse than no import, because it looks like a successful
one — that is the one rule this module exists to enforce, and every gate
below is in service of it.
"""

from __future__ import annotations

import csv
import datetime
import os

from sqlalchemy import select, text, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingStatus, Severity
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.compliance import detect_compliance_drift
from app.services.scans import ScanNotFoundError

# The pinned 44-column expectation, derived from the reference scan
# (Prowler's documented output schema). A mismatch means the scanner
# version changed underneath us — order is not part of the contract (Prowler
# is free to reorder columns without changing their meaning), only the set.
PROWLER_CSV_COLUMNS = frozenset(
    {
        "AUTH_METHOD", "TIMESTAMP", "ACCOUNT_UID", "ACCOUNT_NAME", "ACCOUNT_EMAIL",
        "ACCOUNT_ORGANIZATION_UID", "ACCOUNT_ORGANIZATION_NAME", "ACCOUNT_TAGS",
        "FINDING_UID", "PROVIDER", "CHECK_ID", "CHECK_TITLE", "CHECK_TYPE", "STATUS",
        "STATUS_EXTENDED", "MUTED", "SERVICE_NAME", "SUBSERVICE_NAME", "SEVERITY",
        "RESOURCE_TYPE", "RESOURCE_UID", "RESOURCE_NAME", "RESOURCE_DETAILS",
        "RESOURCE_TAGS", "PARTITION", "REGION", "DESCRIPTION", "RISK", "RELATED_URL",
        "REMEDIATION_RECOMMENDATION_TEXT", "REMEDIATION_RECOMMENDATION_URL",
        "REMEDIATION_CODE_NATIVEIAC", "REMEDIATION_CODE_TERRAFORM", "REMEDIATION_CODE_CLI",
        "REMEDIATION_CODE_OTHER", "COMPLIANCE", "CATEGORIES", "DEPENDS_ON", "RELATED_TO",
        "NOTES", "PROWLER_VERSION", "ADDITIONAL_URLS", "ACCOUNT_OU_UID", "ACCOUNT_OU_NAME",
    }
)

# STATUS values the scanner itself ever emits. RESOURCE_DOES_NOT_EXIST is
# deliberately excluded — it's a status this importer synthesizes for a
# finding that stops appearing on re-scan, never one Prowler
# writes into a file we read.
_VALID_STATUSES = {"PASS", "FAIL", "MANUAL"}
_VALID_SEVERITIES = {s.value for s in Severity}

# The scan-derived columns an upsert overwrites on conflict. Deliberately
# excludes muted/mute_reason/note (the triage overlay to preserve) and
# first_seen_at (set once, on insert, never touched again).
_UPSERT_UPDATE_COLUMNS = [
    "finding_uid", "check_title", "severity", "status", "status_extended", "region",
    "service_name", "subservice_name", "resource_type", "resource_name",
    "description", "risk", "remediation_text", "remediation_url", "remediation_cli",
    "remediation_terraform", "remediation_iac", "categories",
    "last_scan_id", "updated_at",
]

# Prowler's explanatory/remediation columns → the `findings` columns that hold
# them. Every one of these is already in PROWLER_CSV_COLUMNS, so the schema
# pre-check above covers them and a scanner upgrade that drops one is caught
# before a single row is written.
_DETAIL_COLUMNS = {
    "description": "DESCRIPTION",
    "risk": "RISK",
    "remediation_text": "REMEDIATION_RECOMMENDATION_TEXT",
    "remediation_url": "REMEDIATION_RECOMMENDATION_URL",
    "remediation_cli": "REMEDIATION_CODE_CLI",
    "remediation_terraform": "REMEDIATION_CODE_TERRAFORM",
    "remediation_iac": "REMEDIATION_CODE_NATIVEIAC",
    "categories": "CATEGORIES",
}


def _abort(db: Session, scan: Scan, *, status: ScanStatus, message: str) -> Scan:
    scan.status = status
    scan.error_message = message
    db.commit()
    db.refresh(scan)
    return scan


def import_scan_results(db: Session, *, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ScanNotFoundError(scan_id)
    project = db.get(Project, scan.project_id)

    csv_path = os.path.join(scan.reports_path, "scan.csv")
    try:
        with open(csv_path, newline="") as f:
            rows = list(csv.reader(f, delimiter=";"))
    except FileNotFoundError:
        return _abort(
            db, scan, status=ScanStatus.import_failed,
            message=f"scan.csv not found at {csv_path} — the scan container may not have produced output",
        )

    if not rows:
        return _abort(db, scan, status=ScanStatus.import_failed, message="scan.csv is empty")

    header = rows[0]
    data_rows = rows[1:]

    # Gate 1 — schema. A comma-parsed file fails here too: with no
    # semicolons to split on, the entire header line collapses into one
    # column, which can never equal the pinned 44-column set.
    header_set = set(header)
    missing = sorted(PROWLER_CSV_COLUMNS - header_set)
    unexpected = sorted(header_set - PROWLER_CSV_COLUMNS)
    if missing or unexpected:
        parts = []
        if missing:
            parts.append(f"missing: {', '.join(missing)}")
        if unexpected:
            parts.append(f"unexpected: {', '.join(unexpected)}")
        return _abort(
            db, scan, status=ScanStatus.schema_mismatch,
            message="scan.csv header does not match the pinned schema (" + "; ".join(parts) + ")",
        )

    col_index = {name: header.index(name) for name in header}
    n_cols = len(header)

    # Gate 2 — identity. Every row needs a non-blank RESOURCE_UID, and
    # (CHECK_ID, RESOURCE_UID) — never the scanner's own FINDING_UID, which
    # collides for genuinely distinct resources — must be unique in the
    # file. A violation means Prowler changed its identity semantics.
    seen_identity: set[tuple[str, str]] = set()
    for row_num, row in enumerate(data_rows, start=2):
        if len(row) != n_cols:
            return _abort(
                db, scan, status=ScanStatus.import_failed,
                message=f"row {row_num}: expected {n_cols} columns, found {len(row)}",
            )
        resource_uid = row[col_index["RESOURCE_UID"]].strip()
        check_id = row[col_index["CHECK_ID"]].strip()
        if not resource_uid:
            return _abort(
                db, scan, status=ScanStatus.import_failed,
                message=f"row {row_num}: blank RESOURCE_UID",
            )
        identity = (check_id, resource_uid)
        if identity in seen_identity:
            return _abort(
                db, scan, status=ScanStatus.import_failed,
                message=(
                    f"row {row_num}: duplicate identity (check_id={check_id!r}, "
                    f"resource_uid={resource_uid!r}) — Prowler's identity semantics "
                    "may have changed"
                ),
            )
        seen_identity.add(identity)

    # Gate 3 — parse every row into memory before any write. One
    # unparseable row aborts the whole import, nothing committed.
    now = datetime.datetime.now(datetime.timezone.utc)
    parsed_rows: list[dict] = []
    pass_count = 0
    fail_count = 0
    for row_num, row in enumerate(data_rows, start=2):
        status_value = row[col_index["STATUS"]].strip()
        severity_value = row[col_index["SEVERITY"]].strip().lower()
        if status_value not in _VALID_STATUSES:
            return _abort(
                db, scan, status=ScanStatus.import_failed,
                message=f"row {row_num}: unrecognised STATUS {status_value!r}",
            )
        if severity_value not in _VALID_SEVERITIES:
            return _abort(
                db, scan, status=ScanStatus.import_failed,
                message=f"row {row_num}: unrecognised SEVERITY {severity_value!r}",
            )

        if status_value == "PASS":
            pass_count += 1
        elif status_value == "FAIL":
            fail_count += 1

        parsed_rows.append(
            {
                "project_id": project.id,
                "check_id": row[col_index["CHECK_ID"]].strip(),
                "resource_uid": row[col_index["RESOURCE_UID"]].strip(),
                "finding_uid": row[col_index["FINDING_UID"]].strip(),
                "check_title": row[col_index["CHECK_TITLE"]],
                "severity": severity_value,
                "status": status_value,
                "status_extended": row[col_index["STATUS_EXTENDED"]] or None,
                "region": row[col_index["REGION"]],
                "service_name": row[col_index["SERVICE_NAME"]],
                "subservice_name": row[col_index["SUBSERVICE_NAME"]] or None,
                "resource_type": row[col_index["RESOURCE_TYPE"]],
                "resource_name": row[col_index["RESOURCE_NAME"]],
                "last_scan_id": scan.id,
                "updated_at": now,
                # Empty string is stored as NULL: Prowler leaves these blank
                # rather than absent (CLI is missing on ~8% of findings,
                # Terraform ~18%), and "" would make the report render an
                # empty Remediation block instead of omitting it.
                **{
                    column: (row[col_index[csv_column]].strip() or None)
                    for column, csv_column in _DETAIL_COLUMNS.items()
                },
            }
        )

    # Commit — one transaction, under a Postgres advisory lock on
    # project_id. Concurrent scans against the same project still run; only
    # their imports serialize, because carry-forward makes a concurrent
    # absence sweep a correctness bug (it could mark findings a sibling
    # import just wrote), not merely a tolerated race.
    db.execute(text("SELECT pg_advisory_xact_lock(:project_id)"), {"project_id": project.id})

    stmt = pg_insert(Finding).values(parsed_rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=["project_id", "check_id", "resource_uid"],
        set_={col: getattr(stmt.excluded, col) for col in _UPSERT_UPDATE_COLUMNS},
    )
    db.execute(stmt)

    # Absence sweep: anything previously seen for this project that didn't
    # show up in this file is gone. A first scan has no prior rows, so this
    # matches zero — no special-casing needed.
    seen_pairs = list(seen_identity)
    db.execute(
        update(Finding)
        .where(Finding.project_id == project.id)
        .where(Finding.status != FindingStatus.RESOURCE_DOES_NOT_EXIST)
        .where(tuple_(Finding.check_id, Finding.resource_uid).not_in(seen_pairs))
        .values(status=FindingStatus.RESOURCE_DOES_NOT_EXIST, updated_at=now)
    )

    scan.status = ScanStatus.succeeded
    scan.pass_count = pass_count
    scan.fail_count = fail_count
    scan.error_message = None
    scan.compliance_drift_detected = detect_compliance_drift(db, data_rows, col_index)
    db.commit()
    db.refresh(scan)
    return scan
