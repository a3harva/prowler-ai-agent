"""PDF rendering — Phase 1 (plumbing) of the branded-PDF export.

Mirrors test_report_render.py's own rule: **remediation commands never pass
through the model.** The PDF path consumes the same already-separated
`payload`/`narratives`/`explanations` the Markdown path does and never calls
Gemini itself, so this file re-asserts the same invariant holds for the
second consumer of that boundary.
"""

from app.services import report_pdf


def _group(**overrides):
    group = {
        "check_id": "bigquery_dataset_cmk_encryption",
        "check_title": "BigQuery datasets use CMEK",
        "severity": "high",
        "categories": "encryption",
        "description": "Checks whether datasets use customer-managed keys.",
        "risk": "Without CMEK you lose cryptographic control.",
        "remediation_text": "Protect datasets with CMEK via Cloud KMS.",
        "remediation_cli": "bq update --default_kms_key projects/X/... --dataset D",
        "remediation_terraform": None,
        "resources": [
            {"resource_name": "ds-one", "region": "US", "status_extended": "not using CMEK",
             "muted": False, "mute_reason": None},
        ],
    }
    group.update(overrides)
    return group


def _payload(groups=None, **overrides):
    payload = {
        "pillars": {"Security, Privacy & Compliance": groups or [_group()]},
        "severity_counts": {"Security, Privacy & Compliance": {"high": 1}},
        "skipped_finding_count": 0,
        "unknown_category_count": 0,
        "muted_excluded_count": 0,
    }
    payload.update(overrides)
    return payload


def _render_html(payload=None, **kwargs):
    defaults = dict(
        project_id="synthetic-project-id",
        scan_id=12,
        payload=payload or _payload(),
        narratives={"Security, Privacy & Compliance": "Narrative."},
        explanations={"bigquery_dataset_cmk_encryption": "Plain-language explanation."},
        executive_summary="Summary.",
    )
    defaults.update(kwargs)
    return report_pdf.render_pdf_html(**defaults)


def test_html_contains_check_severity_and_executive_summary():
    html = _render_html()
    assert "bigquery_dataset_cmk_encryption" in html
    assert "High" in html
    assert "Summary." in html
    assert "synthetic-project-id" in html


def test_remediation_reaches_the_pdf_only_via_payload_never_via_prose():
    """A distinctive remediation string appears in the output because it is
    in `payload`, not because it leaked in through `narratives`/
    `explanations` — those two dicts deliberately do not carry it, mirroring
    `test_remediation_is_never_sent_to_the_model`'s own boundary check."""
    distinctive = "gcloud spanner-databases-update-DISTINCTIVE-MARKER-42"
    group = _group(remediation_cli=distinctive)
    html = _render_html(
        _payload([group]),
        narratives={"Security, Privacy & Compliance": "Narrative with no commands in it."},
        explanations={"bigquery_dataset_cmk_encryption": "Explanation with no commands in it."},
    )
    assert distinctive in html


def test_render_pdf_bytes_starts_with_pdf_magic_number():
    pdf_bytes = report_pdf.render_pdf_bytes(
        project_id="synthetic-project-id",
        scan_id=12,
        payload=_payload(),
        narratives={"Security, Privacy & Compliance": "Narrative."},
        explanations={},
        executive_summary="Summary.",
    )
    assert pdf_bytes[:4] == b"%PDF"


def test_untrusted_resource_text_is_html_escaped():
    """Prowler-sourced text is untrusted. Autoescaping is what keeps a
    resource name or status string from corrupting the rendered HTML rather
    than just looking odd — the same class of risk `_resource_table()` in
    report_render.py guards against for Markdown with its own `|` escaping."""
    group = _group(
        resources=[
            {"resource_name": "<script>alert(1)</script>", "region": "US",
             "status_extended": "a & b <b>bold</b>", "muted": False, "mute_reason": None},
        ]
    )
    html = _render_html(_payload([group]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "a &amp; b &lt;b&gt;bold&lt;/b&gt;" in html


def test_muted_resources_are_tagged_inline():
    group = _group(
        resources=[
            {"resource_name": "ds-muted", "region": "US", "status_extended": "not using CMEK",
             "muted": True, "mute_reason": "accepted_risk"},
        ]
    )
    html = _render_html(_payload([group]))
    assert "Accepted Risk" in html
    assert "accepted_risk" in html


def test_coverage_notes_appear_when_present():
    html = _render_html(_payload(muted_excluded_count=3721, skipped_finding_count=7))
    assert "3721 muted finding(s) are excluded" in html
    assert "7 finding(s) are not covered" in html


def test_pre_fenced_and_bare_terraform_snippets_render_once():
    """Same normalization `report_render.py`'s Markdown path uses — the PDF
    must never double up a fence Prowler already supplied. (The quotes come
    back HTML-escaped — that's the autoescaping test above already covering
    correctness; here the only thing under test is "exactly once".)"""
    pre_fenced = _render_html(
        _payload([_group(remediation_terraform='```hcl\nresource "x" "y" {}\n```')])
    )
    bare = _render_html(_payload([_group(remediation_terraform='resource "x" "y" {}')]))
    needle = 'resource &#34;x&#34; &#34;y&#34; {}'
    for html in (pre_fenced, bare):
        assert html.count(needle) == 1
        assert "```" not in html


def test_remediation_bold_markers_render_as_real_emphasis():
    """Prowler's remediation text carries literal `**bold**` markers — the
    same source the Markdown report renders as real emphasis via
    react-markdown. Printed unconverted in the PDF, a customer would see raw
    asterisks; `md_inline` converts only that one pattern to `<strong>`."""
    group = _group(remediation_text="Enable **request logging** with **least privilege**.")
    html = _render_html(_payload([group]))
    assert "<strong>request logging</strong>" in html
    assert "<strong>least privilege</strong>" in html
    assert "**" not in html


def test_md_inline_escapes_untrusted_text_before_adding_any_tag():
    """`md_inline` must not become a second, unescaped text path alongside
    the autoescaping the rest of this file protects. A hostile description
    containing both real HTML and a `**bold**` marker should have the HTML
    neutralised and only the bold marker converted."""
    group = _group(
        remediation_text='<img src=x onerror=alert(1)> and **bold** and <b>already-tagged</b>'
    )
    html = _render_html(_payload([group]))
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<strong>bold</strong>" in html
    assert "&lt;b&gt;already-tagged&lt;/b&gt;" in html
