"""Markdown assembly and prompt construction.

The rule these tests exist to protect: **remediation commands never pass
through the model.** They are copied out of the finding row into the document,
and the prompt payload deliberately does not contain them, so there is nothing
for Gemini to rewrite even if it tried.
"""

from app.services import report_render


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


def _render(payload=None, **kwargs):
    defaults = dict(
        project_id="synthetic-project-id",
        scan_id=12,
        payload=payload or _payload(),
        narratives={"Security, Privacy & Compliance": "Narrative."},
        explanations={"bigquery_dataset_cmk_encryption": "Plain-language explanation."},
        executive_summary="Summary.",
    )
    defaults.update(kwargs)
    return report_render.render_markdown(**defaults)


def test_remediation_is_never_sent_to_the_model():
    """The payload the model receives carries description and risk — what it
    needs to explain a check — and none of the remediation fields. A model that
    invents a gcloud command is the worst failure this feature could have, so
    it is never shown one to paraphrase."""
    content = report_render.pillar_user_content("Security, Privacy & Compliance", [_group()])
    assert "description" in content
    assert "risk" in content
    assert "bq update" not in content
    assert "remediation" not in content.lower()


def test_prompt_payload_omits_the_resource_list():
    """Forty resource identifiers add tokens and hallucination surface without
    changing a word of the explanation — a count and one example is enough."""
    group = _group(resources=[
        {"resource_name": f"ds-{i}", "region": "US", "status_extended": "detail",
         "muted": False, "mute_reason": None}
        for i in range(40)
    ])
    content = report_render.pillar_user_content("Security, Privacy & Compliance", [group])
    assert "affected_resource_count" in content
    assert "ds-39" not in content


def test_scope_rule_is_in_both_prompts():
    """One project per report is a product constraint, so the model is told so
    explicitly rather than merely being handed one project's data."""
    assert "exactly ONE GCP project" in report_render.PILLAR_SYSTEM_PROMPT
    assert "exactly ONE GCP project" in report_render.SUMMARY_SYSTEM_PROMPT


def test_remediation_appears_verbatim_in_the_markdown():
    markdown = _render()
    assert "bq update --default_kms_key projects/X/... --dataset D" in markdown
    assert "```bash" in markdown


def test_empty_remediation_blocks_are_omitted_not_placeholdered():
    """Terraform is absent on ~18% of findings. An empty 'Terraform' heading
    reads as a missing answer rather than an inapplicable one."""
    markdown = _render()
    assert "Terraform:" not in markdown
    assert "```hcl" not in markdown


def test_muted_resources_are_tagged_inline():
    group = _group(resources=[
        {"resource_name": "ds-muted", "region": "US", "status_extended": "not using CMEK",
         "muted": True, "mute_reason": "accepted_risk"},
    ])
    markdown = _render(_payload([group]))
    assert "Accepted Risk — accepted_risk" in markdown


def test_excluded_muted_findings_are_stated_in_the_document():
    """Stated, not silent. A reader comparing the report against the findings
    screen would otherwise find numbers that disagree with no explanation — and
    on a heavily-muted project the muted exclusion is most of the difference."""
    markdown = _render(_payload(muted_excluded_count=3721))
    assert "3721 muted finding(s) are excluded" in markdown
    assert "accepted as risks" in markdown


def test_both_coverage_notes_render_as_separate_paragraphs():
    """A blank line has to separate the two `*note*` lines, or CommonMark
    merges them into one run-on paragraph instead of two distinct notes."""
    markdown = _render(_payload(muted_excluded_count=3721, skipped_finding_count=7))
    assert "*3721 muted finding(s) are excluded from this report" in markdown
    assert "*7 finding(s) are not covered" in markdown
    muted_note = next(line for line in markdown.splitlines() if "muted finding(s)" in line)
    skipped_note = next(line for line in markdown.splitlines() if "finding(s) are not covered" in line)
    lines = markdown.splitlines()
    assert lines[lines.index(muted_note) + 1] == ""
    assert lines.index(skipped_note) == lines.index(muted_note) + 2


def test_no_coverage_note_when_nothing_was_excluded():
    markdown = _render(_payload())
    assert "excluded from this report" not in markdown
    assert "not covered" not in markdown


def test_skipped_findings_are_stated_in_the_document():
    """Not merely recorded on the row — the reader of the document needs to
    know its coverage, otherwise the count silently disagrees with the
    findings screen."""
    markdown = _render(_payload(skipped_finding_count=7))
    assert "7 finding(s) are not covered" in markdown


def test_pipes_in_detail_text_do_not_break_the_table():
    group = _group(resources=[
        {"resource_name": "ds-one", "region": "US", "status_extended": "a | b",
         "muted": False, "mute_reason": None},
    ])
    markdown = _render(_payload([group]))
    assert r"a \| b" in markdown


def test_already_fenced_snippets_are_not_double_wrapped():
    """Prowler ships every Terraform snippet pre-fenced and every CLI snippet
    bare — verified across a real 356-finding scan. Wrapping a pre-fenced
    snippet closes the outer fence on the inner one and spills the code into
    the document as body text."""
    group = _group(remediation_terraform='```hcl\nresource "google_x" "y" {}\n```')
    markdown = _render(_payload([group]))
    assert "```hcl\n```hcl" not in markdown
    assert markdown.count("```hcl") == 1
    assert 'resource "google_x" "y" {}' in markdown


def test_bare_snippets_still_get_a_fence():
    group = _group(remediation_terraform='resource "google_x" "y" {}')
    markdown = _render(_payload([group]))
    assert "```hcl" in markdown
    assert 'resource "google_x" "y" {}' in markdown


# ── fence normalisation, every shape Prowler might supply ────────────────────


def test_every_fence_shape_yields_exactly_one_block():
    """Prowler pre-fences Terraform and leaves CLI bare, but that is an
    observation about one scanner version, not a contract. Normalising rather
    than trusting the observed shape means a future Prowler that flips the
    convention needs no change here."""
    for name, value in {
        "pre-fenced": '```hcl\nresource "x" "y" {}\n```',
        "bare": 'resource "x" "y" {}',
        "fenced, no language": '```\nresource "x" "y" {}\n```',
        "tilde-fenced": '~~~\nresource "x" "y" {}\n~~~',
    }.items():
        markdown = _render(_payload([_group(remediation_terraform=value)]))
        assert markdown.count("```hcl") == 1, name
        assert "```hcl\n```" not in markdown, name
        assert 'resource "x" "y" {}' in markdown, name


def test_content_with_several_blocks_is_passed_through_untouched():
    """Not recognised as one wrapper, so it is left exactly as the scanner
    supplied it — corrupting a command a customer will run is worse than
    imperfect formatting."""
    value = '```hcl\na\n```\nthen\n```hcl\nb\n```'
    markdown = _render(_payload([_group(remediation_terraform=value)]))
    assert "```hcl\n```hcl" not in markdown
    assert "a" in markdown and "b" in markdown


# ── the validator ────────────────────────────────────────────────────────────


def test_validator_catches_the_defect_that_shipped():
    """43 double-fenced blocks reached the first generated report. This is the
    gate that stops that ever being stored again."""
    broken = "# T\n\n```hcl\n```hcl\nx\n```\n```\n"
    problems = report_render.validate_markdown(broken)
    assert any("nested code fence" in p for p in problems)


def test_validator_catches_unbalanced_fences():
    problems = report_render.validate_markdown("# T\n\n```bash\nx\n")
    assert any("unbalanced" in p for p in problems)


def test_validator_catches_a_table_row_that_does_not_match_its_header():
    """An unescaped pipe in cell text silently splits a row into extra columns."""
    broken = "| A | B |\n| --- | --- |\n| one | two | three |\n"
    problems = report_render.validate_markdown(broken)
    assert any("table row" in p for p in problems)


def test_a_well_formed_report_passes_validation():
    assert report_render.validate_markdown(_render()) == []


def test_review_prompt_forbids_returning_a_corrected_document():
    """The model reports on formatting; it never rewrites. Handing it the
    document to correct would hand it the remediation commands to paraphrase,
    which is the one thing this feature's design exists to prevent."""
    # Whitespace-normalised: the prompt is hard-wrapped, so the sentence spans
    # a line break in the source.
    prompt = " ".join(report_render.MARKDOWN_REVIEW_PROMPT.split())
    assert "Do NOT return a corrected document" in prompt
    assert "FORMATTING ONLY" in prompt
    assert "never the technical content" in prompt
