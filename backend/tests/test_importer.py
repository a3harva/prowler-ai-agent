"""The core safety net for the import pipeline. Every gate aborts the whole
import with nothing written on failure — that guarantee is what these tests
exist to prove, not just the happy path.
"""

import csv
from pathlib import Path

import pytest
from sqlalchemy import text

from app.models.department import Department
from app.models.finding import Finding
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.services.importer import import_scan_results

# The public scanner schema. Tests create synthetic rows at runtime rather than
# storing any exported scan data in the repository.
# Order doesn't matter to the importer (it matches by header set, not
# position), but DictWriter needs a fixed fieldnames list to write with.
COLUMNS = [
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

BASE_ROW = {col: "" for col in COLUMNS}
BASE_ROW.update(
    {
        "PROVIDER": "gcp",
        "CHECK_ID": "some_check",
        "CHECK_TITLE": "Some check title",
        "CHECK_TYPE": "",
        "STATUS": "FAIL",
        "STATUS_EXTENDED": "some detail",
        "MUTED": "False",
        "SERVICE_NAME": "compute",
        "SUBSERVICE_NAME": "",
        "SEVERITY": "high",
        "RESOURCE_TYPE": "compute.googleapis.com/Instance",
        "RESOURCE_UID": "projects/x/instance/1",
        "RESOURCE_NAME": "instance-1",
        "REGION": "us-central1",
        "FINDING_UID": "prowler-gcp-some_check-proj-us-central1-instance-1",
    }
)


def _write_csv(tmp_path: Path, rows: list[dict], *, delimiter: str = ";", name: str = "reports") -> str:
    reports_dir = tmp_path / name
    reports_dir.mkdir(exist_ok=True)
    with open(reports_dir / "scan.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, delimiter=delimiter)
        writer.writeheader()
        writer.writerows(rows)
    return str(reports_dir)


def _row(**overrides) -> dict:
    row = dict(BASE_ROW)
    row.update(overrides)
    return row


def _synthetic_fixture_rows() -> list[dict]:
    """Small synthetic data set covering normal import and duplicate UIDs."""
    duplicate_uid = "demo-duplicate-finding"
    return [
        _row(STATUS="PASS", CHECK_ID="demo_pass_check", RESOURCE_UID="projects/demo/instances/one", FINDING_UID="demo-pass"),
        _row(CHECK_ID="demo_duplicate_check", RESOURCE_UID="projects/demo/tables/one", FINDING_UID=duplicate_uid),
        _row(CHECK_ID="demo_duplicate_check", RESOURCE_UID="projects/demo/tables/two", FINDING_UID=duplicate_uid),
        _row(CHECK_ID="demo_duplicate_check", RESOURCE_UID="projects/demo/tables/three", FINDING_UID=duplicate_uid),
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


def _make_scan(db_session, project, *, reports_path: str) -> Scan:
    n = db_session.query(Scan).count()
    actor_id = _make_actor(db_session, email=f"actor-{project.project_id}-{n}@example.test")
    scan = Scan(
        project_id=project.id, status=ScanStatus.importing,
        triggered_by_user_id=actor_id, reports_path=reports_path,
    )
    db_session.add(scan)
    db_session.flush()
    return scan


# ── happy path, against synthetic fixture data ─────────────────────────────


def test_first_scan_inserts_every_row_with_no_special_casing(db_session, tmp_path):
    project = _make_project(db_session)
    reports_path = _write_csv(tmp_path, _synthetic_fixture_rows())
    scan = _make_scan(db_session, project, reports_path=reports_path)

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.status == ScanStatus.succeeded
    assert finished.error_message is None
    findings = db_session.query(Finding).filter_by(project_id=project.id).all()
    assert len(findings) == 4
    assert all(f.status != "RESOURCE_DOES_NOT_EXIST" for f in findings)


def test_duplicate_finding_uid_kept_as_separate_findings(db_session, tmp_path):
    """Three synthetic rows sharing a scanner-issued UID stay distinct."""
    project = _make_project(db_session)
    reports_path = _write_csv(tmp_path, _synthetic_fixture_rows())
    scan = _make_scan(db_session, project, reports_path=reports_path)

    import_scan_results(db_session, scan_id=scan.id)

    dup_uid = "demo-duplicate-finding"
    matching = db_session.query(Finding).filter_by(project_id=project.id, finding_uid=dup_uid).all()
    assert len(matching) == 3
    assert len({f.resource_uid for f in matching}) == 3  # genuinely distinct resources


def test_pass_and_fail_counts_recorded_against_scan(db_session, tmp_path):
    project = _make_project(db_session)
    reports_path = _write_csv(tmp_path, _synthetic_fixture_rows())
    scan = _make_scan(db_session, project, reports_path=reports_path)

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.pass_count == 1
    assert finished.fail_count == 3


def test_manual_status_imports(db_session, tmp_path):
    """Absent from the reference fixture — Prowler does emit MANUAL, and
    omitting it would fail the all-or-nothing parse on the first check that
    returns one."""
    project = _make_project(db_session)
    reports_path = _write_csv(tmp_path, [_row(STATUS="MANUAL")])
    scan = _make_scan(db_session, project, reports_path=reports_path)

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.status == ScanStatus.succeeded
    assert finished.pass_count == 0
    assert finished.fail_count == 0  # MANUAL counts toward neither
    finding = db_session.query(Finding).filter_by(project_id=project.id).one()
    assert finding.status == "MANUAL"


# ── each gate, in order ─────────────────────────────────────────────────────


def test_comma_parsed_csv_rejected(db_session, tmp_path):
    project = _make_project(db_session)
    reports_path = _write_csv(tmp_path, [_row()], delimiter=",")
    scan = _make_scan(db_session, project, reports_path=reports_path)

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.status == ScanStatus.schema_mismatch
    assert db_session.query(Finding).filter_by(project_id=project.id).count() == 0


def test_schema_mismatch_names_missing_and_unexpected_columns(db_session, tmp_path):
    project = _make_project(db_session)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    with open(reports_dir / "scan.csv", "w", newline="") as f:
        columns = [c for c in COLUMNS if c != "REGION"] + ["REGION_RENAMED"]
        writer = csv.DictWriter(f, fieldnames=columns, delimiter=";")
        writer.writeheader()
        row = _row()
        del row["REGION"]
        row["REGION_RENAMED"] = "us-central1"
        writer.writerow(row)
    scan = _make_scan(db_session, project, reports_path=str(reports_dir))

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.status == ScanStatus.schema_mismatch
    assert "REGION" in finished.error_message
    assert "REGION_RENAMED" in finished.error_message
    assert db_session.query(Finding).filter_by(project_id=project.id).count() == 0


def test_blank_resource_uid_rejected(db_session, tmp_path):
    project = _make_project(db_session)
    reports_path = _write_csv(tmp_path, [_row(RESOURCE_UID="")])
    scan = _make_scan(db_session, project, reports_path=reports_path)

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.status == ScanStatus.import_failed
    assert "blank" in finished.error_message.lower()
    assert db_session.query(Finding).filter_by(project_id=project.id).count() == 0


def test_colliding_identity_rejected(db_session, tmp_path):
    """Two rows sharing (check_id, resource_uid) — the real identity, not
    the scanner's own FINDING_UID — abort the import."""
    project = _make_project(db_session)
    reports_path = _write_csv(
        tmp_path,
        [
            _row(CHECK_ID="dup_check", RESOURCE_UID="same-resource", FINDING_UID="uid-a"),
            _row(CHECK_ID="dup_check", RESOURCE_UID="same-resource", FINDING_UID="uid-b"),
        ],
    )
    scan = _make_scan(db_session, project, reports_path=reports_path)

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.status == ScanStatus.import_failed
    assert "duplicate identity" in finished.error_message
    assert db_session.query(Finding).filter_by(project_id=project.id).count() == 0


def test_bad_row_rolls_back(db_session, tmp_path):
    """One unparseable row (an unrecognised STATUS) aborts the whole import,
    leaving the table exactly as it was — nothing committed, including the
    otherwise-valid rows around it."""
    project = _make_project(db_session)
    reports_path = _write_csv(
        tmp_path,
        [
            _row(CHECK_ID="check_a", RESOURCE_UID="resource-a", FINDING_UID="uid-a"),
            _row(CHECK_ID="check_b", RESOURCE_UID="resource-b", FINDING_UID="uid-b", STATUS="NOT_A_REAL_STATUS"),
        ],
    )
    scan = _make_scan(db_session, project, reports_path=reports_path)

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.status == ScanStatus.import_failed
    assert "row 3" in finished.error_message
    assert db_session.query(Finding).filter_by(project_id=project.id).count() == 0


def test_missing_csv_file_marks_import_failed(db_session, tmp_path):
    project = _make_project(db_session)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    scan = _make_scan(db_session, project, reports_path=str(reports_dir))

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.status == ScanStatus.import_failed
    assert "scan.csv" in finished.error_message


def test_wrong_column_count_row_rejected(db_session, tmp_path):
    project = _make_project(db_session)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    with open(reports_dir / "scan.csv", "w", newline="") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(COLUMNS)
        writer.writerow(["only", "a", "few", "values"])
    scan = _make_scan(db_session, project, reports_path=str(reports_dir))

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.status == ScanStatus.import_failed
    assert db_session.query(Finding).filter_by(project_id=project.id).count() == 0


# ── carry-forward across re-scans ───────────────────────────────
#
# The upsert and absence sweep are a no-op on a first scan. These tests
# actually proves the re-scan behavior, not just its absence of side effects.


def test_mute_survives_reimport(db_session, tmp_path):
    from app.services.findings import update_finding

    project = _make_project(db_session)
    reports_path_1 = _write_csv(tmp_path, [_row()], name="scan1")
    scan1 = _make_scan(db_session, project, reports_path=reports_path_1)
    import_scan_results(db_session, scan_id=scan1.id)

    finding = db_session.query(Finding).filter_by(project_id=project.id).one()
    actor_id = _make_actor(db_session, email="muter@example.test")
    from app.models.finding import MuteReason

    update_finding(
        db_session, finding_id=finding.id, muted=True,
        mute_reason=MuteReason.false_positive, note="confirmed safe",
        actor_user_id=actor_id,
    )

    # Re-scan: same identity, status flips to PASS this time.
    reports_path_2 = _write_csv(tmp_path, [_row(STATUS="PASS")], name="scan2")
    scan2 = _make_scan(db_session, project, reports_path=reports_path_2)
    import_scan_results(db_session, scan_id=scan2.id)

    db_session.refresh(finding)
    assert finding.status == "PASS"  # scan-derived field did update
    assert finding.muted is True  # overlay survived, untouched
    assert finding.mute_reason == MuteReason.false_positive
    assert finding.note == "confirmed safe"
    assert finding.last_scan_id == scan2.id


def test_muted_fail_coexist(db_session, tmp_path):
    """A finding can be FAIL and muted at the same time — muting suppresses
    noise, not reality."""
    from app.models.finding import MuteReason
    from app.services.findings import update_finding

    project = _make_project(db_session)
    reports_path = _write_csv(tmp_path, [_row(STATUS="FAIL")])
    scan = _make_scan(db_session, project, reports_path=reports_path)
    import_scan_results(db_session, scan_id=scan.id)

    finding = db_session.query(Finding).filter_by(project_id=project.id).one()
    actor_id = _make_actor(db_session, email="muter@example.test")
    update_finding(
        db_session, finding_id=finding.id, muted=True,
        mute_reason=MuteReason.risk_accepted, note=None, actor_user_id=actor_id,
    )

    db_session.refresh(finding)
    assert finding.status == "FAIL"
    assert finding.muted is True


def test_resource_disappears_marked_not_deleted(db_session, tmp_path):
    project = _make_project(db_session)
    reports_path_1 = _write_csv(
        tmp_path,
        [_row(CHECK_ID="check_a", RESOURCE_UID="res-a"), _row(CHECK_ID="check_b", RESOURCE_UID="res-b")],
        name="scan1",
    )
    scan1 = _make_scan(db_session, project, reports_path=reports_path_1)
    import_scan_results(db_session, scan_id=scan1.id)
    assert db_session.query(Finding).filter_by(project_id=project.id).count() == 2

    # res-b no longer appears — its resource is gone, not its record.
    reports_path_2 = _write_csv(tmp_path, [_row(CHECK_ID="check_a", RESOURCE_UID="res-a")], name="scan2")
    scan2 = _make_scan(db_session, project, reports_path=reports_path_2)
    import_scan_results(db_session, scan_id=scan2.id)

    findings = db_session.query(Finding).filter_by(project_id=project.id).all()
    assert len(findings) == 2  # still there, never deleted
    gone = next(f for f in findings if f.resource_uid == "res-b")
    assert gone.status == "RESOURCE_DOES_NOT_EXIST"
    still_there = next(f for f in findings if f.resource_uid == "res-a")
    assert still_there.status == "FAIL"


def test_resource_returns_reconnects_with_mute_intact(db_session, tmp_path):
    project = _make_project(db_session)
    from app.models.finding import MuteReason
    from app.services.findings import update_finding

    reports_path_1 = _write_csv(tmp_path, [_row(CHECK_ID="check_a", RESOURCE_UID="res-a")], name="scan1")
    scan1 = _make_scan(db_session, project, reports_path=reports_path_1)
    import_scan_results(db_session, scan_id=scan1.id)
    finding = db_session.query(Finding).filter_by(project_id=project.id).one()
    actor_id = _make_actor(db_session, email="muter@example.test")
    update_finding(
        db_session, finding_id=finding.id, muted=True,
        mute_reason=MuteReason.not_applicable, note="not in scope", actor_user_id=actor_id,
    )
    finding_id = finding.id

    # Gone for a scan...
    reports_path_2 = _write_csv(tmp_path, [_row(CHECK_ID="check_other", RESOURCE_UID="res-other")], name="scan2")
    scan2 = _make_scan(db_session, project, reports_path=reports_path_2)
    import_scan_results(db_session, scan_id=scan2.id)
    db_session.refresh(finding)
    assert finding.status == "RESOURCE_DOES_NOT_EXIST"

    # ...then back.
    reports_path_3 = _write_csv(tmp_path, [_row(CHECK_ID="check_a", RESOURCE_UID="res-a")], name="scan3")
    scan3 = _make_scan(db_session, project, reports_path=reports_path_3)
    import_scan_results(db_session, scan_id=scan3.id)

    # 2, not 3: the original identity reconnects to its existing row rather
    # than inserting a new one — scan2's unrelated check_other/res-other is
    # the second, itself now marked gone since scan3 doesn't include it.
    findings = db_session.query(Finding).filter_by(project_id=project.id).all()
    assert len(findings) == 2
    db_session.refresh(finding)
    assert finding.id == finding_id  # same row throughout, never recreated
    assert finding.status == "FAIL"
    assert finding.muted is True  # mute came back with it
    assert finding.mute_reason == MuteReason.not_applicable
    assert finding.note == "not in scope"


def test_reimport_never_touches_overlay_columns_in_the_write_itself(db_session, tmp_path):
    """Belt-and-suspenders on the importer's design constraint:
    the upsert's SET clause must not name muted/mute_reason/note at all —
    verified structurally, not just by outcome."""
    from app.services.importer import _UPSERT_UPDATE_COLUMNS

    assert "muted" not in _UPSERT_UPDATE_COLUMNS
    assert "mute_reason" not in _UPSERT_UPDATE_COLUMNS
    assert "note" not in _UPSERT_UPDATE_COLUMNS
    assert "first_seen_at" not in _UPSERT_UPDATE_COLUMNS  # set once, on insert, never again


def test_scanners_own_muted_column_is_ignored(db_session, tmp_path):
    """Mute is this system's overlay, not the scanner's — the CSV's own
    MUTED column must have zero effect on stored mute state, in either
    direction."""
    project = _make_project(db_session)
    reports_path = _write_csv(tmp_path, [_row(MUTED="True")])
    scan = _make_scan(db_session, project, reports_path=reports_path)

    import_scan_results(db_session, scan_id=scan.id)

    finding = db_session.query(Finding).filter_by(project_id=project.id).one()
    assert finding.muted is False  # CSV said True; our overlay says otherwise by default
    assert finding.mute_reason is None


def test_advisory_lock_serializes_imports_on_the_same_project(db_engine):
    """The exact mechanism import_scan_results relies on: a transaction
    holding pg_advisory_xact_lock(project_id) blocks a second transaction
    requesting the same lock until the first commits or rolls back. This is
    what makes the absence sweep safe under concurrent scans on one
    project — proven directly, rather than by racing the full import
    end-to-end and hoping the timing lines up."""
    import threading
    import time

    project_id = 424242  # a database row is not needed for this lock test

    conn_a = db_engine.connect()
    trans_a = conn_a.begin()
    conn_a.execute(text("SELECT pg_advisory_xact_lock(:pid)"), {"pid": project_id})

    acquired_by_b = threading.Event()

    def _try_acquire_in_b():
        conn_b = db_engine.connect()
        trans_b = conn_b.begin()
        conn_b.execute(text("SELECT pg_advisory_xact_lock(:pid)"), {"pid": project_id})
        acquired_by_b.set()
        trans_b.rollback()
        conn_b.close()

    thread = threading.Thread(target=_try_acquire_in_b)
    thread.start()

    # B must NOT have acquired the lock while A still holds it.
    time.sleep(0.3)
    assert not acquired_by_b.is_set()

    trans_a.rollback()
    conn_a.close()

    # Once A releases, B acquires promptly.
    thread.join(timeout=5)
    assert acquired_by_b.is_set()


# ── compliance drift guard ──────────────────────────────────────


def _seed_one_requirement(db_session, *, requirement_id: str, check_id: str, prowler_version: str = "5.39.0"):
    from app.models.compliance_requirement import ComplianceRequirement

    db_session.add(
        ComplianceRequirement(
            framework="CIS-2.0", framework_name="CIS 2.0", requirement_id=requirement_id,
            requirement_description=None, check_id=check_id, attributes={},
            prowler_version=prowler_version,
        )
    )
    db_session.flush()


def test_import_with_no_rulebook_loaded_is_not_flagged_as_drifted(db_session, tmp_path):
    project = _make_project(db_session)
    row = _row(COMPLIANCE="CIS-2.0: some-requirement-id")
    reports_dir = _write_csv(tmp_path, [row])
    scan = _make_scan(db_session, project, reports_path=reports_dir)

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.compliance_drift_detected is False


def test_import_flags_drift_when_compliance_mappings_are_not_in_the_rulebook(db_session, tmp_path):
    _seed_one_requirement(db_session, requirement_id="some-other-id", check_id="some_check")
    project = _make_project(db_session)
    row = _row(COMPLIANCE="CIS-2.0: a-requirement-id-not-in-the-rulebook")
    reports_dir = _write_csv(tmp_path, [row])
    scan = _make_scan(db_session, project, reports_path=reports_dir)

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.compliance_drift_detected is True


def test_import_not_flagged_when_compliance_mappings_match_the_rulebook(db_session, tmp_path):
    _seed_one_requirement(db_session, requirement_id="7.3", check_id="bigquery_dataset_cmk_encryption")
    project = _make_project(db_session)
    row = _row(COMPLIANCE="CIS-2.0: 7.3")
    reports_dir = _write_csv(tmp_path, [row])
    scan = _make_scan(db_session, project, reports_path=reports_dir)

    finished = import_scan_results(db_session, scan_id=scan.id)

    assert finished.compliance_drift_detected is False


# ── Prowler's explanatory and remediation content ────────────────────────────
# These columns were validated by the header check and then discarded until a
# screen needed them. The AI report does: it
# reuses Prowler's own remediation text verbatim rather than having a model
# generate a gcloud command for a customer to run.

_DETAIL_ROW = dict(
    DESCRIPTION="Checks whether datasets use customer-managed keys.",
    RISK="Without CMEK you lose cryptographic control of data at rest.",
    REMEDIATION_RECOMMENDATION_TEXT="Protect datasets with CMEK via Cloud KMS.",
    REMEDIATION_RECOMMENDATION_URL="https://cloud.google.com/kms/docs",
    REMEDIATION_CODE_CLI="bq update --default_kms_key projects/X/... --dataset D",
    REMEDIATION_CODE_TERRAFORM='resource "google_bigquery_dataset" "d" {}',
    REMEDIATION_CODE_NATIVEIAC="",
    CATEGORIES="encryption",
)


def test_remediation_detail_is_persisted(db_session, tmp_path):
    project = _make_project(db_session, project_id="proj-detail")
    reports_path = _write_csv(tmp_path, [_row(**_DETAIL_ROW)], name="detail")
    scan = _make_scan(db_session, project, reports_path=reports_path)

    import_scan_results(db_session, scan_id=scan.id)

    finding = db_session.query(Finding).filter_by(project_id=project.id).one()
    assert finding.description == _DETAIL_ROW["DESCRIPTION"]
    assert finding.risk == _DETAIL_ROW["RISK"]
    assert finding.remediation_text == _DETAIL_ROW["REMEDIATION_RECOMMENDATION_TEXT"]
    assert finding.remediation_url == _DETAIL_ROW["REMEDIATION_RECOMMENDATION_URL"]
    assert finding.remediation_cli == _DETAIL_ROW["REMEDIATION_CODE_CLI"]
    assert finding.remediation_terraform == _DETAIL_ROW["REMEDIATION_CODE_TERRAFORM"]
    assert finding.categories == "encryption"


def test_blank_remediation_columns_are_stored_as_null_not_empty_string(db_session, tmp_path):
    """Prowler leaves these blank rather than absent — CLI is missing on ~8% of
    findings, Terraform on ~18%. Empty string would make the report render an
    empty Remediation block instead of omitting it."""
    project = _make_project(db_session, project_id="proj-blank")
    reports_path = _write_csv(tmp_path, [_row(**_DETAIL_ROW)], name="blank")
    scan = _make_scan(db_session, project, reports_path=reports_path)

    import_scan_results(db_session, scan_id=scan.id)

    finding = db_session.query(Finding).filter_by(project_id=project.id).one()
    assert finding.remediation_iac is None


def test_reimport_refreshes_remediation_detail(db_session, tmp_path):
    """A Prowler upgrade that rewords its own guidance must reach existing
    rows — these are scan-derived, so they belong in the upsert's update set
    alongside severity and status."""
    project = _make_project(db_session, project_id="proj-refresh")

    first_path = _write_csv(tmp_path, [_row(**_DETAIL_ROW)], name="refresh-1")
    first_scan = _make_scan(db_session, project, reports_path=first_path)
    import_scan_results(db_session, scan_id=first_scan.id)

    updated = dict(_DETAIL_ROW, DESCRIPTION="Reworded by a newer Prowler.")
    second_path = _write_csv(tmp_path, [_row(**updated)], name="refresh-2")
    second_scan = _make_scan(db_session, project, reports_path=second_path)
    import_scan_results(db_session, scan_id=second_scan.id)

    finding = db_session.query(Finding).filter_by(project_id=project.id).one()
    assert finding.description == "Reworded by a newer Prowler."
