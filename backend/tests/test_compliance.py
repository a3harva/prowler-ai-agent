"""Seeding the compliance rulebook from a scan's compliance/ output
directory. Fixtures here are small synthetic framework files rather than
the real 21-file reference set — the shapes under test (alias columns,
dedup, the CCC no-FRAMEWORK-column case) don't need production-scale volume
to exercise, and staying small keeps the suite fast.
"""

import csv
from pathlib import Path

import pytest

from app.models.compliance_requirement import ComplianceRequirement
from app.models.department import Department
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.services.compliance import (
    ComplianceDirectoryMissingError,
    EmptyRulebookError,
    ScanNotSucceededError,
    seed_rulebook_from_scan,
)

ADMIN_EMAIL = "admin@example.test"

# Family A shape (PROJECTID/LOCATION, FRAMEWORK/NAME present) — see
# the public Prowler output schema.
_FAMILY_A_COLUMNS = [
    "PROVIDER", "DESCRIPTION", "PROJECTID", "LOCATION", "ASSESSMENTDATE",
    "REQUIREMENTS_ID", "REQUIREMENTS_DESCRIPTION", "REQUIREMENTS_ATTRIBUTES_SECTION",
    "STATUS", "STATUSEXTENDED", "RESOURCEID", "RESOURCENAME", "CHECKID", "MUTED",
    "FRAMEWORK", "NAME",
]

# The CCC shape: no FRAMEWORK/NAME columns at all — the real trap this
# parser has to handle without per-framework code.
_CCC_SHAPE_COLUMNS = [
    "PROVIDER", "DESCRIPTION", "PROJECTID", "LOCATION", "ASSESSMENTDATE",
    "REQUIREMENTS_ID", "REQUIREMENTS_DESCRIPTION", "REQUIREMENTS_ATTRIBUTES_FAMILYNAME",
    "STATUS", "STATUSEXTENDED", "RESOURCEID", "RESOURCENAME", "CHECKID", "MUTED",
]

_MAIN_CSV_COLUMNS = [
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
]


def _make_actor(db_session, email="actor@example.test") -> int:
    user = User(email=email, name="Actor")
    db_session.add(user)
    db_session.flush()
    return user.id


def _make_project(db_session, project_id="proj-1") -> Project:
    dept = Department(freshservice_id=project_id, name="Dept", domains=[], deleted=False)
    db_session.add(dept)
    db_session.flush()
    org = GcpOrganization(org_id=f"org-{project_id}", name="Org", department_id=dept.id)
    db_session.add(org)
    db_session.flush()
    project = Project(
        project_id=project_id, gcp_organization_id=org.id,
        target_sa_email=f"scanner@{project_id}.iam.gserviceaccount.com", deleted=False,
    )
    db_session.add(project)
    db_session.flush()
    return project


def _write_main_csv(reports_dir: Path, *, prowler_version: str = "5.39.0") -> None:
    row = {col: "" for col in _MAIN_CSV_COLUMNS}
    row.update({"PROVIDER": "gcp", "PROWLER_VERSION": prowler_version, "STATUS": "PASS"})
    with open(reports_dir / "scan.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_MAIN_CSV_COLUMNS, delimiter=";")
        writer.writeheader()
        writer.writerow(row)


def _write_family_a_csv(path: Path, rows: list[dict]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_FAMILY_A_COLUMNS, delimiter=";")
        writer.writeheader()
        for override in rows:
            row = {col: "" for col in _FAMILY_A_COLUMNS}
            row.update({"PROVIDER": "gcp", "STATUS": "PASS", "MUTED": "False"})
            row.update(override)
            writer.writerow(row)


def _write_ccc_shape_csv(path: Path, rows: list[dict]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_CCC_SHAPE_COLUMNS, delimiter=";")
        writer.writeheader()
        for override in rows:
            row = {col: "" for col in _CCC_SHAPE_COLUMNS}
            row.update({"PROVIDER": "gcp", "STATUS": "PASS", "MUTED": "False"})
            row.update(override)
            writer.writerow(row)


def _make_scan_with_compliance(
    db_session, project, tmp_path: Path, *, name: str = "reports", status=ScanStatus.succeeded,
    prowler_version: str = "5.39.0", family_a_rows=None, ccc_rows=None,
) -> Scan:
    reports_dir = tmp_path / name
    (reports_dir / "compliance").mkdir(parents=True)
    _write_main_csv(reports_dir, prowler_version=prowler_version)
    if family_a_rows is not None:
        _write_family_a_csv(reports_dir / "compliance" / "framework_a.csv", family_a_rows)
    if ccc_rows is not None:
        _write_ccc_shape_csv(reports_dir / "compliance" / "ccc_shaped.csv", ccc_rows)

    actor_id = _make_actor(db_session, email=f"scan-actor-{name}@example.test")
    scan = Scan(
        project_id=project.id, status=status,
        triggered_by_user_id=actor_id, reports_path=str(reports_dir),
    )
    db_session.add(scan)
    db_session.flush()
    return scan


# ── service layer ────────────────────────────────────────────────────────────


def test_seed_loads_all_frameworks_including_one_with_no_framework_column(db_session, tmp_path):
    project = _make_project(db_session)
    scan = _make_scan_with_compliance(
        db_session, project, tmp_path,
        family_a_rows=[
            {
                "REQUIREMENTS_ID": "7.3", "REQUIREMENTS_DESCRIPTION": "Encrypt with CMEK",
                "REQUIREMENTS_ATTRIBUTES_SECTION": "7 BigQuery", "CHECKID": "bigquery_dataset_cmk_encryption",
                "FRAMEWORK": "CIS-2.0", "NAME": "CIS GCP Foundations Benchmark 2.0",
                "RESOURCENAME": "dataset-a",
            },
        ],
        ccc_rows=[
            {
                "DESCRIPTION": "Common Cloud Controls Catalog (CCC) for GCP",
                "REQUIREMENTS_ID": "CCC.CntrReg.CN01.AR01", "REQUIREMENTS_DESCRIPTION": "Scan artifacts",
                "REQUIREMENTS_ATTRIBUTES_FAMILYNAME": "Risk Management", "CHECKID": "artifacts_scanning_enabled",
                "RESOURCENAME": "repo-a",
            },
        ],
    )
    actor_id = _make_actor(db_session, email="seeder@example.test")

    summary = seed_rulebook_from_scan(db_session, scan_id=scan.id, actor_user_id=actor_id)

    assert summary["framework_count"] == 2
    assert summary["requirement_count"] == 2
    assert summary["prowler_version"] == "5.39.0"
    assert "CIS GCP Foundations Benchmark 2.0" in summary["frameworks"]

    ccc_row = (
        db_session.query(ComplianceRequirement)
        .filter_by(check_id="artifacts_scanning_enabled")
        .one()
    )
    assert ccc_row.framework == "CCC"
    assert ccc_row.framework_name == "Common Cloud Controls Catalog (CCC) for GCP"
    assert ccc_row.requirement_id == "CCC.CntrReg.CN01.AR01"

    cis_row = (
        db_session.query(ComplianceRequirement)
        .filter_by(check_id="bigquery_dataset_cmk_encryption")
        .one()
    )
    # Result- and project-bearing columns discarded; framework-specific
    # extra columns retained generically.
    assert cis_row.attributes == {"requirements_attributes_section": "7 BigQuery"}
    assert cis_row.requirement_description == "Encrypt with CMEK"


def test_seed_deduplicates_repeated_mappings(db_session, tmp_path):
    """The same (framework, requirement, check) mapping repeats once per
    scanned resource in the source file — the rulebook must collapse that
    to one row, not one per resource."""
    project = _make_project(db_session)
    scan = _make_scan_with_compliance(
        db_session, project, tmp_path,
        family_a_rows=[
            {
                "REQUIREMENTS_ID": "7.3", "CHECKID": "bigquery_dataset_cmk_encryption",
                "FRAMEWORK": "CIS-2.0", "NAME": "CIS 2.0", "RESOURCENAME": "dataset-a",
            },
            {
                "REQUIREMENTS_ID": "7.3", "CHECKID": "bigquery_dataset_cmk_encryption",
                "FRAMEWORK": "CIS-2.0", "NAME": "CIS 2.0", "RESOURCENAME": "dataset-b",
            },
            {
                "REQUIREMENTS_ID": "7.3", "CHECKID": "bigquery_dataset_cmk_encryption",
                "FRAMEWORK": "CIS-2.0", "NAME": "CIS 2.0", "RESOURCENAME": "dataset-c",
            },
        ],
    )
    actor_id = _make_actor(db_session, email="seeder@example.test")

    summary = seed_rulebook_from_scan(db_session, scan_id=scan.id, actor_user_id=actor_id)

    assert summary["requirement_count"] == 1
    assert db_session.query(ComplianceRequirement).count() == 1


def test_seed_keeps_distinct_framework_versions_separate(db_session, tmp_path):
    """Regression guard for the real bug this surfaced: CIS 2.0/3.0/4.0/5.0
    all carry the identical FRAMEWORK value ("CIS") in the real reference
    files — only NAME differs ("... v2.0.0" vs "v3.0.0" ...). Keying
    identity on `framework` alone silently merged all four and crashed the
    load on the first duplicate (framework, requirement_id, check_id)."""
    project = _make_project(db_session)
    scan = _make_scan_with_compliance(
        db_session, project, tmp_path,
        family_a_rows=[
            {
                "REQUIREMENTS_ID": "7.3", "CHECKID": "check_a", "FRAMEWORK": "CIS",
                "NAME": "CIS Google Cloud Platform Foundation Benchmark v2.0.0",
            },
            {
                "REQUIREMENTS_ID": "7.3", "CHECKID": "check_a", "FRAMEWORK": "CIS",
                "NAME": "CIS Google Cloud Platform Foundation Benchmark v3.0.0",
            },
        ],
    )
    actor_id = _make_actor(db_session, email="seeder@example.test")

    summary = seed_rulebook_from_scan(db_session, scan_id=scan.id, actor_user_id=actor_id)

    assert summary["framework_count"] == 2
    assert summary["requirement_count"] == 2
    names = {row.framework_name for row in db_session.query(ComplianceRequirement).all()}
    assert names == {
        "CIS Google Cloud Platform Foundation Benchmark v2.0.0",
        "CIS Google Cloud Platform Foundation Benchmark v3.0.0",
    }


def test_seed_replaces_previous_rulebook_entirely(db_session, tmp_path):
    project = _make_project(db_session)
    first_scan = _make_scan_with_compliance(
        db_session, project, tmp_path, name="reports-1",
        family_a_rows=[{"REQUIREMENTS_ID": "old", "CHECKID": "old_check", "FRAMEWORK": "CIS-2.0", "NAME": "CIS 2.0"}],
    )
    actor_id = _make_actor(db_session, email="seeder@example.test")
    seed_rulebook_from_scan(db_session, scan_id=first_scan.id, actor_user_id=actor_id)
    assert db_session.query(ComplianceRequirement).filter_by(check_id="old_check").count() == 1

    second_scan = _make_scan_with_compliance(
        db_session, project, tmp_path, name="reports-2",
        family_a_rows=[{"REQUIREMENTS_ID": "new", "CHECKID": "new_check", "FRAMEWORK": "CIS-2.0", "NAME": "CIS 2.0"}],
    )
    seed_rulebook_from_scan(db_session, scan_id=second_scan.id, actor_user_id=actor_id)

    assert db_session.query(ComplianceRequirement).filter_by(check_id="old_check").count() == 0
    assert db_session.query(ComplianceRequirement).filter_by(check_id="new_check").count() == 1
    assert db_session.query(ComplianceRequirement).count() == 1


def test_seed_tags_rows_with_prowler_version(db_session, tmp_path):
    project = _make_project(db_session)
    scan = _make_scan_with_compliance(
        db_session, project, tmp_path, prowler_version="9.9.9",
        family_a_rows=[{"REQUIREMENTS_ID": "7.3", "CHECKID": "check_a", "FRAMEWORK": "CIS-2.0", "NAME": "CIS 2.0"}],
    )
    actor_id = _make_actor(db_session, email="seeder@example.test")

    seed_rulebook_from_scan(db_session, scan_id=scan.id, actor_user_id=actor_id)

    row = db_session.query(ComplianceRequirement).one()
    assert row.prowler_version == "9.9.9"


def test_seed_produces_an_audit_entry(db_session, tmp_path):
    from app.models.audit_log import AuditLog

    project = _make_project(db_session)
    scan = _make_scan_with_compliance(
        db_session, project, tmp_path,
        family_a_rows=[{"REQUIREMENTS_ID": "7.3", "CHECKID": "check_a", "FRAMEWORK": "CIS-2.0", "NAME": "CIS 2.0"}],
    )
    actor_id = _make_actor(db_session, email="seeder@example.test")

    seed_rulebook_from_scan(db_session, scan_id=scan.id, actor_user_id=actor_id)

    entry = db_session.query(AuditLog).filter_by(target_type="compliance_rulebook").one()
    assert entry.action_type == "compliance_rulebook.seed"
    assert entry.user_id == actor_id
    assert entry.after_value["requirement_count"] == 1


def test_seed_refuses_a_scan_that_has_not_succeeded(db_session, tmp_path):
    project = _make_project(db_session)
    scan = _make_scan_with_compliance(
        db_session, project, tmp_path, status=ScanStatus.running,
        family_a_rows=[{"REQUIREMENTS_ID": "7.3", "CHECKID": "check_a", "FRAMEWORK": "CIS-2.0", "NAME": "CIS 2.0"}],
    )
    actor_id = _make_actor(db_session, email="seeder@example.test")

    with pytest.raises(ScanNotSucceededError):
        seed_rulebook_from_scan(db_session, scan_id=scan.id, actor_user_id=actor_id)


def test_seed_refuses_a_scan_with_no_compliance_directory(db_session, tmp_path):
    project = _make_project(db_session)
    scan = _make_scan_with_compliance(db_session, project, tmp_path)
    actor_id = _make_actor(db_session, email="seeder@example.test")

    with pytest.raises(ComplianceDirectoryMissingError):
        seed_rulebook_from_scan(db_session, scan_id=scan.id, actor_user_id=actor_id)


def test_seed_refuses_to_replace_a_working_rulebook_with_an_empty_one(db_session, tmp_path):
    """The regression this guards: a compliance/ directory that exists but
    yields zero parseable rows (e.g. Prowler renamed REQUIREMENTS_ID or
    CHECKID) must abort rather than silently empty out a rulebook that was
    working — a half-replaced rulebook produces wrong percentages with no
    error anywhere."""
    project = _make_project(db_session)
    good_scan = _make_scan_with_compliance(
        db_session, project, tmp_path, name="reports-good",
        family_a_rows=[{"REQUIREMENTS_ID": "7.3", "CHECKID": "check_a", "FRAMEWORK": "CIS-2.0", "NAME": "CIS 2.0"}],
    )
    actor_id = _make_actor(db_session, email="seeder@example.test")
    seed_rulebook_from_scan(db_session, scan_id=good_scan.id, actor_user_id=actor_id)
    assert db_session.query(ComplianceRequirement).count() == 1

    # Every row is missing REQUIREMENTS_ID/CHECKID, so nothing parses out.
    broken_scan = _make_scan_with_compliance(
        db_session, project, tmp_path, name="reports-broken", family_a_rows=[{}],
    )

    with pytest.raises(EmptyRulebookError):
        seed_rulebook_from_scan(db_session, scan_id=broken_scan.id, actor_user_id=actor_id)

    # The previous, working rulebook must still be intact.
    assert db_session.query(ComplianceRequirement).count() == 1


# ── API layer ────────────────────────────────────────────────────────────────


def _as_admin(monkeypatch):
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", ADMIN_EMAIL)


def test_admin_seeds_rulebook_via_endpoint(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project = _make_project(db_session)
    scan = _make_scan_with_compliance(
        db_session, project, tmp_path,
        family_a_rows=[{"REQUIREMENTS_ID": "7.3", "CHECKID": "check_a", "FRAMEWORK": "CIS-2.0", "NAME": "CIS 2.0"}],
    )
    client = sign_in_as(email=ADMIN_EMAIL)

    response = client.post("/api/compliance/seed", json={"scan_id": scan.id})

    assert response.status_code == 200
    body = response.json()
    assert body["framework_count"] == 1
    assert body["requirement_count"] == 1


def test_non_admin_cannot_seed_rulebook_via_endpoint(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project = _make_project(db_session)
    scan = _make_scan_with_compliance(
        db_session, project, tmp_path,
        family_a_rows=[{"REQUIREMENTS_ID": "7.3", "CHECKID": "check_a", "FRAMEWORK": "CIS-2.0", "NAME": "CIS 2.0"}],
    )
    sign_in_as(email=ADMIN_EMAIL)

    non_admin = User(email="viewer@example.test", name="Viewer")
    db_session.add(non_admin)
    db_session.commit()
    client = sign_in_as(email="viewer@example.test")

    response = client.post("/api/compliance/seed", json={"scan_id": scan.id})
    assert response.status_code == 403


def test_seed_endpoint_refused_without_signing_in(client):
    response = client.post("/api/compliance/seed", json={"scan_id": 1})
    assert response.status_code == 401
