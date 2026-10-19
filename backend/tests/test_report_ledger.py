"""The count guarantee, tested without a database or a model.

Everything in `agents/report_ledger.py` is pure, so the whole safety net can
be exercised against a hand-built payload. That is the point of the split: the
gates are testable before the graph that calls them exists, and a regression
in them shows up here rather than in a customer-facing document.
"""

from __future__ import annotations

import pytest

from app.agents.report_ledger import (
    build_index,
    digest,
    parse_rendered,
    scan_prose,
    verify_artifacts,
    verify_document,
)
from app.services.report_render import render_markdown


SECURITY = "Security, Privacy & Compliance"
OPS = "Operational Excellence"


def _group(check_id, *, severity="high", resources=2, pillar_service="iam"):
    return {
        "check_id": check_id,
        "check_title": f"Title for {check_id}",
        "severity": severity,
        "service_name": pillar_service,
        "categories": "identity-access",
        "description": f"description of {check_id}",
        "risk": f"risk of {check_id}",
        "remediation_text": "Do the thing.",
        "remediation_cli": "gcloud projects remove-iam-policy-binding x --member y",
        "remediation_terraform": 'resource "google_project_iam_binding" "x" {}',
        "resources": [
            {
                "resource_name": f"{check_id}-resource-{i}",
                "region": "global",
                "status_extended": f"{check_id} failed on resource {i}",
                "muted": False,
                "mute_reason": None,
            }
            for i in range(resources)
        ],
    }


@pytest.fixture()
def payload():
    return {
        "pillars": {
            SECURITY: [
                _group("iam_role_too_broad", severity="critical", resources=3),
                _group("bucket_public", severity="high", resources=1, pillar_service="storage"),
            ],
            OPS: [_group("logging_disabled", severity="medium", resources=2,
                         pillar_service="logging")],
        },
        "skipped_finding_count": 0,
        "unknown_category_count": 0,
        "muted_excluded_count": 0,
        "severity_counts": {
            SECURITY: {"critical": 1, "high": 1},
            OPS: {"medium": 1},
        },
    }


@pytest.fixture()
def index(payload):
    return build_index(payload)


def _sound_artifacts(index):
    """Artifacts that pass every gate, as the baseline each test perturbs."""
    return {
        "check_analysis": {
            c: {"explanation": f"What {c} means.", "why_here": f"Why {c} matters here."}
            for c in index
        },
        "pillar_analysis": {
            SECURITY: {"narrative": "Security narrative.", "analysis": "Security analysis."},
            OPS: {"narrative": "Ops narrative.", "analysis": "Ops analysis."},
        },
        "themes": [
            {
                "title": "Over-broad identity grants",
                "narrative": "Several checks trace to one permissive binding.",
                "refs": ["iam_role_too_broad", "bucket_public"],
            }
        ],
        "remediation_plan": [
            {
                "label": "Close the identity gaps",
                "rationale": "Do these first; everything else assumes least privilege.",
                "refs": ["iam_role_too_broad", "bucket_public"],
            },
            {
                "label": "Restore audit coverage",
                "rationale": "Needs the identity work finished to be meaningful.",
                "refs": ["logging_disabled"],
            },
        ],
        "executive_summary": "The project has three open issues across two pillars.",
    }


# ── the ledger itself ────────────────────────────────────────────────────────


def test_index_is_keyed_by_check_and_carries_the_facts(index):
    assert set(index) == {"iam_role_too_broad", "bucket_public", "logging_disabled"}
    assert index["iam_role_too_broad"]["pillar"] == SECURITY
    assert index["iam_role_too_broad"]["severity"] == "critical"
    assert index["iam_role_too_broad"]["resource_count"] == 3
    assert index["bucket_public"]["service_name"] == "storage"


def test_digest_is_stable_and_content_sensitive(payload):
    first = digest(payload)
    assert first == digest(dict(payload)), "same content must hash the same"

    mutated = {**payload, "skipped_finding_count": 1}
    assert digest(mutated) != first, "a changed ledger must not hash the same"


def test_index_tolerates_a_payload_without_service_name(payload):
    for groups in payload["pillars"].values():
        for group in groups:
            group.pop("service_name")
    assert build_index(payload)["bucket_public"]["service_name"] == ""


# ── C1 coverage ──────────────────────────────────────────────────────────────


def test_sound_artifacts_pass_every_artifact_gate(index):
    assert verify_artifacts(index=index, **_sound_artifacts(index)) == []


def test_c1_flags_a_check_with_no_analysis(index):
    artifacts = _sound_artifacts(index)
    del artifacts["check_analysis"]["bucket_public"]

    failures = verify_artifacts(index=index, **artifacts)

    c1 = [f for f in failures if f.gate == "C1"]
    assert len(c1) == 1
    assert "bucket_public" in c1[0].detail
    assert c1[0].repair_targets == ("check:bucket_public",)


def test_c1_flags_analysis_for_a_check_that_does_not_exist(index):
    artifacts = _sound_artifacts(index)
    artifacts["check_analysis"]["invented_check"] = {"explanation": "x", "why_here": "y"}

    failures = verify_artifacts(index=index, **artifacts)

    c1 = [f for f in failures if f.gate == "C1"]
    assert len(c1) == 1
    assert "invented_check" in c1[0].detail
    # Unattributable, so every pillar is regenerated.
    assert set(c1[0].repair_targets) == {f"pillar:{SECURITY}", f"pillar:{OPS}"}


# ── C2 reference integrity ───────────────────────────────────────────────────


def test_c2_flags_a_theme_citing_an_unknown_check(index):
    artifacts = _sound_artifacts(index)
    artifacts["themes"][0]["refs"].append("not_a_real_check")

    failures = verify_artifacts(index=index, **artifacts)

    c2 = [f for f in failures if f.gate == "C2"]
    assert len(c2) == 1
    assert "not_a_real_check" in c2[0].detail
    assert c2[0].repair_targets == ("themes",)


def test_c2_flags_a_wave_citing_an_unknown_check(index):
    artifacts = _sound_artifacts(index)
    artifacts["remediation_plan"][0]["refs"].append("ghost_check")

    failures = verify_artifacts(index=index, **artifacts)

    c2 = [f for f in failures if f.gate == "C2"]
    assert [f.repair_targets for f in c2] == [("plan",)]


def test_c2_flags_analysis_for_a_pillar_with_no_findings(index):
    artifacts = _sound_artifacts(index)
    artifacts["pillar_analysis"]["Sustainability"] = {"narrative": "n", "analysis": "a"}

    failures = verify_artifacts(index=index, **artifacts)

    c2 = [f for f in failures if f.gate == "C2"]
    assert len(c2) == 1
    assert "Sustainability" in c2[0].detail


# ── C3 plan partition ────────────────────────────────────────────────────────


def test_c3_flags_work_the_plan_dropped(index):
    artifacts = _sound_artifacts(index)
    artifacts["remediation_plan"][1]["refs"] = []

    failures = verify_artifacts(index=index, **artifacts)

    c3 = [f for f in failures if f.gate == "C3"]
    assert len(c3) == 1
    assert "logging_disabled" in c3[0].detail
    assert c3[0].repair_targets == ("plan",)


def test_c3_flags_work_counted_twice(index):
    artifacts = _sound_artifacts(index)
    artifacts["remediation_plan"][1]["refs"].append("bucket_public")

    failures = verify_artifacts(index=index, **artifacts)

    c3 = [f for f in failures if f.gate == "C3"]
    assert len(c3) == 1
    assert "bucket_public" in c3[0].detail


def test_c3_flags_an_empty_plan(index):
    artifacts = _sound_artifacts(index)
    artifacts["remediation_plan"] = []

    failures = verify_artifacts(index=index, **artifacts)

    assert any(f.gate == "C3" for f in failures)


# ── C6 fabricated commands ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "prose",
    [
        "Run gcloud projects add-iam-policy-binding to fix this.",
        "Use gsutil iam ch -d user:x gs://reports-bucket to correct it.",
        "Apply bq update --set_label owner:security on the dataset.",
        "Try kubectl apply -f restricted-psp.yaml against the cluster.",
        'Add resource "google_project_iam_binding" to your config.',
        "Here is the fix:\n```bash\necho hi\n```",
    ],
)
def test_c6_refuses_a_command_in_model_prose(index, prose):
    artifacts = _sound_artifacts(index)
    artifacts["check_analysis"]["bucket_public"]["why_here"] = prose

    failures = verify_artifacts(index=index, **artifacts)

    # One string can legitimately trip more than one pattern (a gsutil call
    # with both a flag and a bucket URI). What matters is that it is refused
    # and that the repair is scoped to the check that carried it.
    c6 = [f for f in failures if f.gate == "C6"]
    assert c6, "this prose must be refused"
    assert {f.repair_targets for f in c6} == {("check:bucket_public",)}


@pytest.mark.parametrize(
    "prose",
    [
        "The gcloud command supplied below closes this gap.",
        "Terraform is the recommended route for this resource.",
        "The bq tool can confirm the dataset's labels.",
        "This is a well-documented gcloud behaviour, not a misconfiguration.",
    ],
)
def test_c6_allows_prose_that_merely_mentions_the_tooling(index, prose):
    """A report should be able to say "run the gcloud command below" without
    being refused. Only command *shapes* are forbidden, not the words."""
    assert scan_prose("test", prose) == []


def test_c6_scans_every_prose_field_including_themes_and_waves(index):
    artifacts = _sound_artifacts(index)
    artifacts["themes"][0]["narrative"] = "Fix with gcloud iam service-accounts delete."
    artifacts["remediation_plan"][0]["rationale"] = "Start with gsutil rb gs://old-bucket."
    artifacts["executive_summary"] = "Overall, run gcloud projects set-iam-policy first."

    failures = verify_artifacts(index=index, **artifacts)

    targets = {f.repair_targets for f in failures if f.gate == "C6"}
    assert targets == {("themes",), ("plan",), ("summary",)}


# ── C4 / C5 against a really rendered document ───────────────────────────────


def _render(payload, index, artifacts, **overrides):
    return render_markdown(
        project_id="demo-project",
        scan_id=7,
        payload=payload,
        narratives={p: e["narrative"] for p, e in artifacts["pillar_analysis"].items()},
        explanations={c: e["explanation"] for c, e in artifacts["check_analysis"].items()},
        executive_summary=artifacts["executive_summary"],
        analysis={
            "themes": artifacts["themes"],
            "remediation_plan": artifacts["remediation_plan"],
            "pillar_analysis": {p: e["analysis"] for p, e in artifacts["pillar_analysis"].items()},
            "check_context": {c: e["why_here"] for c, e in artifacts["check_analysis"].items()},
            **overrides,
        },
    )


def test_a_deep_report_reconciles_against_its_own_ledger(payload, index):
    content = _render(payload, index, _sound_artifacts(index))
    assert verify_document(index=index, payload=payload, content=content) == []


def test_a_standard_report_reconciles_too(payload, index):
    """The new sections are additive: `analysis=None` must still verify, which
    is what keeps `standard` mode inside the same guarantee."""
    artifacts = _sound_artifacts(index)
    content = render_markdown(
        project_id="demo-project",
        scan_id=7,
        payload=payload,
        narratives={p: e["narrative"] for p, e in artifacts["pillar_analysis"].items()},
        explanations={c: e["explanation"] for c, e in artifacts["check_analysis"].items()},
        executive_summary=artifacts["executive_summary"],
    )
    assert verify_document(index=index, payload=payload, content=content) == []


def test_parse_rendered_does_not_mistake_a_wave_for_a_check(payload, index):
    """The Remediation Plan emits `###` headings of its own. If the parser
    counted those as checks, C4 would fail every deep report."""
    parsed = parse_rendered(_render(payload, index, _sound_artifacts(index)))

    assert set(parsed["pillars"]) == {SECURITY, OPS}
    assert sorted(parsed["pillars"][SECURITY]) == ["bucket_public", "iam_role_too_broad"]
    assert parsed["resource_rows"]["iam_role_too_broad"] == 3


def test_c4_catches_a_dropped_check_section(payload, index):
    content = _render(payload, index, _sound_artifacts(index))
    # Simulate a renderer that lost a section.
    start = content.index("### Title for bucket_public")
    end = content.index("### Title for iam_role_too_broad") if content.index(
        "### Title for iam_role_too_broad"
    ) > start else len(content)
    broken = content[:start] + content[end:]

    failures = verify_document(index=index, payload=payload, content=broken)

    assert any(f.gate == "C4" for f in failures)


def test_c4_catches_a_dropped_resource_row(payload, index):
    content = _render(payload, index, _sound_artifacts(index))
    broken = content.replace(
        "| `iam_role_too_broad-resource-2` | global | iam_role_too_broad failed on resource 2 |"
        " Open |\n",
        "",
    )
    assert broken != content, "the row this test removes must exist"

    failures = verify_document(index=index, payload=payload, content=broken)

    c4 = [f for f in failures if f.gate == "C4"]
    assert len(c4) == 1
    assert "iam_role_too_broad rendered 2 resource row(s), ledger has 3" in c4[0].detail


def test_c5_catches_a_wrong_severity_count(payload, index):
    content = _render(payload, index, _sound_artifacts(index))
    broken = content.replace(
        f"| {SECURITY} | 1 | 1 | 0 | 0 |", f"| {SECURITY} | 2 | 1 | 0 | 0 |"
    )
    assert broken != content, "the summary row this test edits must exist"

    failures = verify_document(index=index, payload=payload, content=broken)

    c5 = [f for f in failures if f.gate == "C5"]
    assert len(c5) == 1
    assert "critical" in c5[0].detail
