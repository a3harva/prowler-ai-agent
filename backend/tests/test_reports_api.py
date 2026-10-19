"""Router-level tests for `/api/reports` endpoints that need a real HTTP
response to prove something the service layer can't — status codes, media
types, headers, and permission gating. Everything else about report
generation is exercised at the service layer in test_reports.py.
"""

from app.models.department import Department
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user_department_role import Role, UserDepartmentRole
from app.models.finding import Finding, FindingStatus, Severity
from app.models.user import User
from app.services.reports import finalize_report, submit_report


def _seed_project_with_finding(db_session):
    dept = Department(freshservice_id="930", name="Dept", domains=[], deleted=False)
    db_session.add(dept)
    db_session.flush()
    org = GcpOrganization(org_id="org-pdf-api", name="Org", department_id=dept.id)
    db_session.add(org)
    db_session.flush()
    project = Project(
        project_id="proj-pdf-api", gcp_organization_id=org.id,
        target_sa_email="scanner@proj-pdf-api.iam.gserviceaccount.com", deleted=False,
    )
    db_session.add(project)
    db_session.flush()

    user = User(email="scan-actor@example.test", name="Scan Actor")
    db_session.add(user)
    db_session.flush()
    scan = Scan(project_id=project.id, status=ScanStatus.succeeded, triggered_by_user_id=user.id)
    db_session.add(scan)
    db_session.flush()

    finding = Finding(
        project_id=project.id, check_id="c1", resource_uid="r1", finding_uid="uid-r1",
        check_title="Title", severity=Severity.high, status=FindingStatus.FAIL,
        status_extended="detail", region="global", service_name="svc", resource_type="type",
        resource_name="r1", last_scan_id=scan.id, muted=False,
        description="what it checks", risk="why it matters",
        remediation_text="do the thing", remediation_cli="gcloud do-thing", categories="encryption",
    )
    db_session.add(finding)
    db_session.flush()

    # The viewer these tests sign in as needs an actual grant on this
    # department. Before `get_report` was scoped it needed none, and both
    # tests below passed while downloading another department's report —
    # which is exactly the hole the scoping fixed. Seeding the grant here
    # keeps these tests about what they claim to be about (status code,
    # media type, headers) rather than silently also asserting that anyone
    # may read any report.
    viewer = User(email="viewer@example.test", name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(
        UserDepartmentRole(user_id=viewer.id, department_id=dept.id, role=Role.viewer)
    )
    db_session.flush()
    return project, scan, user


def test_download_pdf_returns_pdf_bytes_when_available(client, db_session, sign_in_as):
    project, scan, requester = _seed_project_with_finding(db_session)
    report = submit_report(db_session, project_id=project.id, actor_user_id=requester.id)
    finalize_report(
        db_session, report_id=report.id, content="# Report",
        pdf_content=b"%PDF-1.7 fake bytes for the api test",
        skipped=0, unknown_categories=0,
    )

    sign_in_as(email="viewer@example.test")
    response = client.get(f"/api/reports/{report.id}/download.pdf")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert report.task_reference_id in response.headers["content-disposition"]
    assert response.content == b"%PDF-1.7 fake bytes for the api test"


def test_download_pdf_404s_when_no_pdf_stored(client, db_session, sign_in_as):
    """A report that hasn't finished generating (or predates this feature)
    has `pdf_content is None` — the endpoint must say so with a 404, not
    serve an empty or broken file."""
    project, scan, requester = _seed_project_with_finding(db_session)
    report = submit_report(db_session, project_id=project.id, actor_user_id=requester.id)

    sign_in_as(email="viewer@example.test")
    response = client.get(f"/api/reports/{report.id}/download.pdf")

    assert response.status_code == 404


def test_download_pdf_404s_for_another_departments_report(client, db_session, sign_in_as):
    """The cross-department guard, at the endpoint that leaks the most.

    A report body is a finished, customer-facing assessment of somebody
    else's estate — not a single row. This endpoint served it to any signed-in
    user until `get_report` was scoped.
    """
    project, scan, requester = _seed_project_with_finding(db_session)
    report = submit_report(db_session, project_id=project.id, actor_user_id=requester.id)
    finalize_report(
        db_session, report_id=report.id, content="# Report",
        pdf_content=b"%PDF-1.7 fake bytes for the api test",
        skipped=0, unknown_categories=0,
    )

    outsider_dept = Department(
        freshservice_id="931", name="Other Dept", domains=[], deleted=False
    )
    db_session.add(outsider_dept)
    db_session.flush()
    outsider = User(email="outsider@example.test", name="Outsider")
    db_session.add(outsider)
    db_session.flush()
    db_session.add(
        UserDepartmentRole(
            user_id=outsider.id, department_id=outsider_dept.id, role=Role.viewer
        )
    )
    db_session.commit()

    sign_in_as(email="outsider@example.test")
    assert client.get(f"/api/reports/{report.id}/download.pdf").status_code == 404
    assert client.get(f"/api/reports/{report.id}").status_code == 404
    assert client.get(f"/api/reports/{report.id}/download").status_code == 404


# ── deep mode ────────────────────────────────────────────────────────────────
# Only what an HTTP round trip can prove: that `mode` is accepted, that it
# reaches the row, and — the part that actually matters — that it selects a
# different Celery task. Everything about what that task then does is covered
# at the graph level in test_report_agent.py.


def _grant_editor(db_session, email="editor@example.test"):
    from sqlalchemy import select

    from app.models.department import Department as Dept

    user = User(email=email, name="Editor")
    db_session.add(user)
    db_session.flush()
    dept_id = db_session.execute(select(Dept.id).order_by(Dept.id.desc()).limit(1)).scalar_one()
    db_session.add(UserDepartmentRole(user_id=user.id, department_id=dept_id, role=Role.editor))
    db_session.flush()
    return user


def test_submitting_a_deep_report_enqueues_the_graph_task(
    client, db_session, sign_in_as, monkeypatch
):
    project, _scan, _requester = _seed_project_with_finding(db_session)
    _grant_editor(db_session)
    enqueued = []
    monkeypatch.setattr(
        "app.api.routers.reports.generate_deep_report_task.delay",
        lambda report_id: enqueued.append(("deep", report_id)),
    )
    monkeypatch.setattr(
        "app.api.routers.reports.generate_report_task.delay",
        lambda report_id: enqueued.append(("standard", report_id)),
    )

    sign_in_as(email="editor@example.test")
    response = client.post(
        "/api/reports",
        json={
            "project_id": project.id,
            "mode": "deep",
            "instructions": "Lead with anything touching customer data.",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["mode"] == "deep"
    assert enqueued == [("deep", body["id"])]


def test_submitting_without_a_mode_stays_on_the_standard_pipeline(
    client, db_session, sign_in_as, monkeypatch
):
    """The default must not move. An existing client that never heard of
    `mode` keeps the behaviour it has today."""
    project, _scan, _requester = _seed_project_with_finding(db_session)
    _grant_editor(db_session, email="editor2@example.test")
    enqueued = []
    monkeypatch.setattr(
        "app.api.routers.reports.generate_report_task.delay",
        lambda report_id: enqueued.append(("standard", report_id)),
    )
    monkeypatch.setattr(
        "app.api.routers.reports.generate_deep_report_task.delay",
        lambda report_id: enqueued.append(("deep", report_id)),
    )

    sign_in_as(email="editor2@example.test")
    response = client.post("/api/reports", json={"project_id": project.id})

    assert response.status_code == 201
    assert response.json()["mode"] == "standard"
    assert enqueued == [("standard", response.json()["id"])]


def test_over_long_instructions_are_refused(client, db_session, sign_in_as):
    project, _scan, _requester = _seed_project_with_finding(db_session)
    _grant_editor(db_session, email="editor3@example.test")

    sign_in_as(email="editor3@example.test")
    response = client.post(
        "/api/reports",
        json={"project_id": project.id, "mode": "deep", "instructions": "x" * 4001},
    )

    assert response.status_code == 422


# ── content editing ─────────────────────────────────────────────────────────


def test_update_report_content_saves_and_clears_stored_pdf(client, db_session, sign_in_as):
    """The happy path: an editor corrects the text after generation. The
    stored PDF is cleared because it was built from the *original* Markdown
    by WeasyPrint and would otherwise silently drift out of sync with what
    the edit endpoint just wrote — see services/reports.py::update_report_content."""
    project, _scan, requester = _seed_project_with_finding(db_session)
    report = submit_report(db_session, project_id=project.id, actor_user_id=requester.id)
    finalize_report(
        db_session, report_id=report.id, content="# Report\noriginal text",
        pdf_content=b"%PDF-1.7 stale bytes", skipped=0, unknown_categories=0,
    )
    _grant_editor(db_session, email="editor-edit@example.test")

    sign_in_as(email="editor-edit@example.test")
    response = client.patch(f"/api/reports/{report.id}", json={"content": "# Report\nedited text"})

    assert response.status_code == 200
    body = response.json()
    assert body["content"] == "# Report\nedited text"
    assert body["content_edited_at"] is not None
    assert body["has_pdf"] is False

    assert client.get(f"/api/reports/{report.id}/download.pdf").status_code == 404


def test_update_report_content_requires_editor(client, db_session, sign_in_as):
    """A Viewer grant (seeded by `_seed_project_with_finding`) is not enough —
    correcting a customer-facing document is the same weight as generating
    one, not a read."""
    project, _scan, requester = _seed_project_with_finding(db_session)
    report = submit_report(db_session, project_id=project.id, actor_user_id=requester.id)
    finalize_report(
        db_session, report_id=report.id, content="# Report",
        pdf_content=b"%PDF-1.7 bytes", skipped=0, unknown_categories=0,
    )

    sign_in_as(email="viewer@example.test")
    response = client.patch(f"/api/reports/{report.id}", json={"content": "# Report\nedited"})

    assert response.status_code == 403


def test_update_report_content_rejects_a_report_that_is_not_completed(
    client, db_session, sign_in_as
):
    """A queued/generating/failed report has no finished document to correct."""
    project, _scan, requester = _seed_project_with_finding(db_session)
    report = submit_report(db_session, project_id=project.id, actor_user_id=requester.id)
    _grant_editor(db_session, email="editor-incomplete@example.test")

    sign_in_as(email="editor-incomplete@example.test")
    response = client.patch(f"/api/reports/{report.id}", json={"content": "whatever"})

    assert response.status_code == 400
