"""Prompt construction and Markdown assembly.

Split from `services/reports.py` so the DB write path and the text generation
stay separately readable — and so the whole of this module can be tested with a
plain dict, no database at all.

The division of labour is the point of the design: **tables and remediation
blocks never pass through the model.** Gemini receives a trimmed JSON payload
and returns two kinds of prose; everything factual is assembled here from the
`findings` row.
"""

from __future__ import annotations

import datetime
import json
import re
from typing import Any

from app.models.finding import Severity
from app.services.report_snippets import FENCE_RE, strip_outer_fence
from app.services.reports import build_check_index

# Repeated inside the prompt, not just enforced by the schema: the model is told
# it is looking at exactly one project so it cannot reach for comparisons or
# generalisations across an estate it cannot see.
_SCOPE_RULE = (
    "SCOPE: This report covers exactly ONE GCP project. Do not reference, compare to, "
    "or imply the existence of any other project. Do not generalize beyond the findings "
    "provided below."
)

PILLAR_SYSTEM_PROMPT = f"""You are writing one section of a GCP security assessment report \
for a non-technical audience: support staff and customers without cloud expertise.

{_SCOPE_RULE}

Every finding below belongs to the "{{pillar}}" pillar of the Google Cloud \
Well-Architected Framework.

For the pillar as a whole, write ONE paragraph of 3-5 sentences summarizing the overall \
theme and severity of the issues found in this project.

For EACH finding, write ONE paragraph explaining, in plain language a non-expert can \
follow:
- what the check evaluates
- why it matters, in terms of business or security impact rather than technical detail

Do NOT write remediation steps or commands. They are supplied separately, verbatim from \
the scanner, and must not be duplicated or altered by you.
Do NOT invent details that are not present in the description and risk text provided.
Do NOT use the words "critical" or "urgent" unless the finding's own severity says so.

Return one entry in "findings" for every check_id given, using the check_id exactly as \
provided."""

SUMMARY_SYSTEM_PROMPT = f"""You are writing the executive summary of a GCP security \
assessment report for a non-technical audience.

{_SCOPE_RULE}

You are given the per-pillar narratives already written for this report, plus the counts \
of findings by severity. Write ONE paragraph of 4-6 sentences that a manager could read \
on its own: what the overall posture of this project looks like, which pillar needs \
attention first, and what the general character of the work is.

Do NOT list individual findings. Do NOT invent anything not present in the narratives \
and counts provided."""


def pillar_user_content(pillar: str, groups: list[dict[str, Any]]) -> str:
    """Only the fields the model needs to write prose.

    Resource lists are trimmed to a count and a short sample: the model is
    explaining what a check means, and forty resource identifiers add tokens
    and hallucination surface without changing a single word of the answer.
    """
    payload = [
        {
            "check_id": g["check_id"],
            "check_title": g["check_title"],
            "severity": g["severity"],
            "category": g["categories"],
            "description": g["description"],
            "risk": g["risk"],
            "affected_resource_count": len(g["resources"]),
            "example_detail": (g["resources"][0]["status_extended"] if g["resources"] else ""),
        }
        for g in groups
    ]
    return f"Pillar: {pillar}\n\nFindings:\n{json.dumps(payload, indent=2)}"


def summary_user_content(narratives: dict[str, str], severity_counts: dict[str, Any]) -> str:
    return json.dumps(
        {
            "pillar_narratives": narratives,
            "severity_counts": {p: dict(c) for p, c in severity_counts.items()},
        },
        indent=2,
    )


# ── Markdown assembly ────────────────────────────────────────────────────────

_SEVERITY_COLUMNS = ("critical", "high", "medium", "low")


def _summary_table(severity_counts: dict[str, Any]) -> list[str]:
    lines = ["## Pillar Summary", "", "| Pillar | Critical | High | Medium | Low |",
             "| --- | ---: | ---: | ---: | ---: |"]
    for pillar, counts in severity_counts.items():
        cells = " | ".join(str(counts.get(s, 0)) for s in _SEVERITY_COLUMNS)
        lines.append(f"| {pillar} | {cells} |")
    return lines + [""]


def _resource_table(resources: list[dict[str, Any]]) -> list[str]:
    lines = ["**Affected resources**", "",
             "| Resource | Region | Detail | Status |", "| --- | --- | --- | --- |"]
    for r in resources:
        # Muted findings appear inline, tagged, rather than hidden in an
        # appendix: the reader is an L1 or a customer who will not know to go
        # looking for one, and an accepted risk they cannot see reads as an
        # omission when they later find it.
        status = f"Accepted Risk — {r['mute_reason']}" if r["muted"] else "Open"
        detail = " ".join((r["status_extended"] or "").split()).replace("|", "\\|")
        lines.append(f"| `{r['resource_name']}` | {r['region']} | {detail} | {status} |")
    return lines + [""]


def _code_block(label: str, content: str | None, language: str) -> list[str]:
    """Emit Prowler's snippet as exactly one fenced block.

    Double-fencing was a real defect, not a hypothetical: the first generated
    report contained 43 blocks shaped

        ```hcl
        ```hcl
        resource ...

    where the outer fence is closed by the inner one and the code escapes the
    block as body text.
    """
    body = (content or "").strip()
    if not body:
        return []
    inner = strip_outer_fence(body)
    if inner is not None:
        return [f"{label}:", "", f"```{language}", inner, "```", ""]
    if FENCE_RE.search(body):
        # Multiple blocks, or something we do not recognise — pass through
        # untouched rather than risk corrupting a command a customer will run.
        return [f"{label}:", "", body, ""]
    return [f"{label}:", "", f"```{language}", body, "```", ""]


def _remediation_block(group: dict[str, Any]) -> list[str]:
    """Verbatim from Prowler. An empty block is omitted rather than printed
    with a placeholder — CLI is absent on ~8% of findings and Terraform on
    ~18%, and an empty "Terraform" heading reads as a missing answer."""
    lines: list[str] = []
    if (group.get("remediation_text") or "").strip():
        lines += ["**Remediation**", "", group["remediation_text"].strip(), ""]
    lines += _code_block("Command line", group.get("remediation_cli"), "bash")
    lines += _code_block("Terraform", group.get("remediation_terraform"), "hcl")
    return lines


# ── the deep report's extra sections ─────────────────────────────────────────
# All optional. `analysis=None` renders exactly the document this module
# rendered before they existed, which is what keeps `standard` mode and every
# test written against it unchanged.
#
# The division of labour is the same one the rest of this module holds to, and
# it is what makes the count guarantee mechanical rather than aspirational:
# **the model supplies prose and a list of check_ids; every number below is
# computed here from the payload.** A model cannot overstate a blast radius
# because it is never asked for one.

_SEVERITY_RANK = {s.value: i for i, s in enumerate(Severity)}


def _cell(text: str) -> str:
    """Table-cell text: whitespace collapsed, pipes escaped.

    Same treatment `_resource_table` gives Prowler's `status_extended`. A raw
    `|` in a model-written label would split the row into extra columns, which
    `validate_markdown` would then reject — better to make it impossible than
    to fail the report over it.
    """
    return " ".join((text or "").split()).replace("|", "\\|")


def _theme_facts(refs: list[str], index: dict[str, Any]) -> tuple[int, int]:
    """(resources, distinct services) for the checks a theme cites.

    Unknown refs are skipped rather than counted as zero — gate C2 has already
    refused them by the time this runs, and skipping keeps the arithmetic
    honest if this is ever called on unverified input.
    """
    known = [index[c] for c in refs if c in index]
    resources = sum(e["resource_count"] for e in known)
    services = len({e["service_name"] for e in known if e["service_name"]})
    return resources, services


def _themes_section(themes: list[dict[str, Any]], index: dict[str, Any]) -> list[str]:
    """Cross-check correlations — the thing a per-pillar pass structurally
    cannot see, since a theme's whole value is that it spans pillars."""
    if not themes:
        return []
    out = ["## Key Themes", ""]
    for theme in themes:
        out += [f"### {theme.get('title', 'Theme')}", ""]
        narrative = (theme.get("narrative") or "").strip()
        if narrative:
            out += [narrative, ""]
        refs = [c for c in (theme.get("refs") or []) if c in index]
        if refs:
            out += ["Related checks: " + " · ".join(f"`{c}`" for c in refs), ""]
            resources, services = _theme_facts(refs, index)
            noun = "service" if services == 1 else "services"
            out += [f"Affected resources: {resources} across {services} {noun}", ""]
    return out


def _plan_section(waves: list[dict[str, Any]], index: dict[str, Any]) -> list[str]:
    """Remediation sequencing.

    **Sequencing, not commands.** Every `gcloud` and Terraform snippet stays
    where it already is — inside the per-check remediation block, verbatim
    from Prowler. What the model adds here is the order to do the work in and
    why, which is exactly the judgement a static severity sort cannot make.
    Gate C6 refuses a command in any of this prose.

    The rationale is a paragraph under each wave's own heading rather than a
    sixth table column: a multi-sentence cell makes the table unreadable, and
    a paragraph carrying an unescaped pipe is a row-splitting defect waiting
    to happen.
    """
    if not waves:
        return []
    out = [
        "## Remediation Plan",
        "",
        "| Wave | Focus | Checks | Resources | Highest severity |",
        "| ---: | --- | ---: | ---: | --- |",
    ]
    for i, wave in enumerate(waves, start=1):
        refs = [c for c in (wave.get("refs") or []) if c in index]
        resources = sum(index[c]["resource_count"] for c in refs)
        severity = (
            min((index[c]["severity"] for c in refs), key=lambda s: _SEVERITY_RANK[s])
            if refs
            else "—"
        )
        out.append(
            f"| {i} | {_cell(wave.get('label', ''))} | {len(refs)} | {resources} | "
            f"{severity.title()} |"
        )
    out.append("")

    for i, wave in enumerate(waves, start=1):
        out += [f"### Wave {i} — {wave.get('label', 'Unlabelled')}", ""]
        rationale = (wave.get("rationale") or "").strip()
        if rationale:
            out += [rationale, ""]
        refs = [c for c in (wave.get("refs") or []) if c in index]
        if refs:
            out += ["Checks in this wave: " + " · ".join(f"`{c}`" for c in refs), ""]
    return out


# ── the live-state sections ──────────────────────────────────────────────────
# The section names are defined here, where they are emitted, and imported by
# `agents/report_ledger.py` — which has to know which `##` headings are not WAF
# pillars, and would otherwise carry a second copy of these strings that could
# drift silently. `frontend/src/lib/report-markdown-plugin.ts` carries the third
# copy for its table of contents, and cannot import from Python; adding a
# section means adding it there too.
RECONCILIATION_SECTION = "Live-State Reconciliation"
EVIDENCE_SECTION = "Evidence Appendix"

# What each verdict is called in front of a customer. The model returns the
# machine word; the reader never sees it. `contradicts` in particular is a
# terrible thing to print — it sounds like the scanner was wrong, when what it
# means is that the finding overstates a risk something else already controls.
VERDICT_LABELS = {
    "confirms": "Confirmed against live state",
    "contradicts": "Reduced by live state",
    "moot": "No longer applicable",
    "amplifies": "Raised by live state",
    "no_evidence": "Not checked against live state",
}

# The two verdicts that mean "you can stop worrying about this one", grouped
# together in the reconciliation section so the zero-risk cleanup is the
# report's own conclusion rather than something a reader has to assemble by
# reading every finding and noticing a pattern.
REDUCED_VERDICTS = ("moot", "contradicts")


def _evidence_refs(entry: dict[str, Any]) -> str:
    """`E1`, `E4` — the citation a reader can look up in the appendix."""
    ids = [str(e) for e in (entry.get("evidence") or []) if str(e).strip()]
    return " · ".join(f"`{e}`" for e in ids)


def _live_context_line(entry: dict[str, Any] | None) -> list[str]:
    """One finding's live-state verdict, under its prose and above its table.

    Rendered for **every** check including `no_evidence`, for the same reason
    the banner renders on success: a line that appears only sometimes teaches a
    reader to skim past its absence, and "we did not look at this one" is
    exactly the thing they cannot otherwise detect.
    """
    if not entry:
        return []
    label = VERDICT_LABELS.get(entry.get("verdict") or "", VERDICT_LABELS["no_evidence"])
    refs = _evidence_refs(entry)
    heading = f"**Live context — {label}**" + (f" · evidence {refs}" if refs else "")
    statement = (entry.get("statement") or "").strip()
    return [heading, ""] + ([statement, ""] if statement else [])


def _reconciliation_rows(
    reconciliation: dict[str, dict[str, Any]],
    index: dict[str, Any],
    verdicts: tuple[str, ...],
) -> list[str]:
    rows = []
    for check_id, entry in reconciliation.items():
        if entry.get("verdict") not in verdicts or check_id not in index:
            continue
        meta = index[check_id]
        rows.append(
            f"| `{check_id}` | {_cell(meta['check_title'])} | "
            f"{meta['severity'].title()} | {meta['resource_count']} | "
            f"{VERDICT_LABELS[entry['verdict']]} | {_evidence_refs(entry) or '—'} |"
        )
    return rows


def _reconciliation_section(
    reconciliation: dict[str, dict[str, Any]] | None,
    index: dict[str, Any],
) -> list[str]:
    """What live state changed about the findings, grouped by what to do next.

    Only the verdicts that change a decision get a group. `confirms` and
    `no_evidence` are deliberately absent: they are already on every finding's
    own Live context line, and listing 300 confirmed checks a second time
    would bury the twenty that can be closed — which is the one conclusion
    this section exists to hand the reader.
    """
    reconciliation = reconciliation or {}
    reduced = _reconciliation_rows(reconciliation, index, REDUCED_VERDICTS)
    raised = _reconciliation_rows(reconciliation, index, ("amplifies",))
    if not reduced and not raised:
        return []

    header = [
        "| Check | Finding | Severity | Resources | Live state | Evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    out = [f"## {RECONCILIATION_SECTION}", ""]
    if reduced:
        out += [
            "### Findings live state has reduced or closed",
            "",
            "Live state shows these are already controlled, or that the exposure "
            "cannot occur at all. Each is backed by a command in the "
            f"{EVIDENCE_SECTION.lower()} below. They remain in the counts above — "
            "nothing here changes what the scan found — but they are where the "
            "cheapest progress is.",
            "",
        ] + header + reduced + [""]
    if raised:
        out += [
            "### Findings live state has raised",
            "",
            "Live state shows what these protect matters more than their recorded "
            "severity suggests. Consider them earlier in the plan than their "
            "severity alone would place them.",
            "",
        ] + header + raised + [""]
    return out


def evidence_outcome(entry: dict[str, Any]) -> str:
    """One phrase saying what became of a command.

    A refusal and a permission error are different events with different
    meanings — one is this system declining to run something, the other is the
    project declining to answer — and flattening either into "failed" destroys
    the distinction a reader needs to judge what the report could not see.
    """
    kind = entry.get("kind") or "ran"
    if kind == "rejected":
        return f"refused before it ran ({entry.get('reason') or 'not permitted'})"
    if kind == "budget":
        return "not run — the run's command budget was exhausted"
    if kind == "cache_hit":
        return "repeat of an earlier command in this run; the same output was reused"
    if entry.get("ok"):
        return "succeeded"
    exit_code = entry.get("exit_code")
    detail = " ".join(str(entry.get("stderr") or entry.get("error") or "").split())[:200]
    return (
        f"failed (exit {exit_code})" if exit_code is not None else "failed"
    ) + (f" — {detail}" if detail else "")


def evidence_when(entry: dict[str, Any]) -> str:
    at = entry.get("at")
    if not isinstance(at, (int, float)):
        return ""
    return datetime.datetime.fromtimestamp(at, datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%SZ"
    )


def _evidence_appendix(live_context: dict[str, Any] | None) -> list[str]:
    """Every command this report ran, including the ones that did not work.

    The failures are the half that cannot be omitted. A reader who is told
    which context was unavailable can weigh the report accordingly; one who is
    shown only the successes has no way to tell a project with no org policies
    from a project nobody was allowed to ask.

    Commands go in fenced blocks rather than inline code spans because a
    `bq query` statement contains backticks — BigQuery requires them around a
    dataset identifier, and an inline span cannot hold one. Gate C6 reads these
    blocks back and refuses any command that is not in the log.
    """
    log = (live_context or {}).get("command_log") or []
    if not log:
        return []
    out = [
        "---",
        "",
        f"## {EVIDENCE_SECTION}",
        "",
        "Every read-only command run against the live project while this report "
        "was written, in the order they were attempted. Commands that failed or "
        "were refused are listed too — what could not be read is part of what "
        "this report knows.",
        "",
    ]
    for entry in log:
        evidence_id = str(entry.get("evidence_id") or "?")
        why = " ".join(str(entry.get("why") or "").split())
        when = evidence_when(entry)
        out += [f"**{evidence_id}** — {evidence_outcome(entry)}", ""]
        if why:
            out += [f"*Why:* {why}", ""]
        if when:
            out += [f"*Run at:* {when}", ""]
        out += ["```text", str(entry.get("command") or "").strip(), "```", ""]
    return out


def _live_context_banner(live_context: dict[str, Any] | None) -> list[str]:
    """What the reader is told about live state, on the face of the report.

    **This exists because recon is always on.** An opt-in flag would have
    doubled as the record that live context was attempted — a reader could tell
    from the request. Without one, a report whose recon failed silently is
    indistinguishable from one that never had it, which is the worst outcome
    available for a document whose whole value is that it was checked against
    reality. So the pipeline states the status itself, every time.

    Rendered for **every** deep report, including `complete`, and that is
    deliberate rather than noisy: a notice that appears only on failure trains a
    reader to skim past its absence, and absence is exactly the case they cannot
    otherwise detect. A standard report renders nothing here — it never claimed
    to have looked.
    """
    body = live_context_note(live_context)
    return ["> **Live context:** " + body, ""] if body else []


def live_context_note(live_context: dict[str, Any] | None) -> str:
    """The banner's sentence, as plain text with Markdown emphasis.

    Split out from `_live_context_banner` because the PDF renders the same
    sentence, and the two artifacts are built from the same objects precisely
    so they cannot drift — a second copy of this wording is exactly how they
    would. Returns "" when there is nothing to say, which is a standard report:
    it never claimed to have looked.
    """
    if not live_context:
        return ""
    status = str(live_context.get("status") or "unavailable")
    reason = (live_context.get("reason") or "").strip()
    ran = len([e for e in (live_context.get("command_log") or []) if e.get("kind") == "ran"])

    if status == "complete":
        body = (
            f"The findings below were checked against the project's live state. "
            f"{ran} read-only command{'s' if ran != 1 else ''} ran successfully."
        )
    elif status == "partial":
        body = (
            "Live state was **partly** reachable, so some findings below could not be "
            "checked against it. "
            + (f"{reason}. " if reason else "")
            + "Treat anything not explicitly reconciled as unverified against live state."
        )
    else:
        body = (
            "**Live context unavailable.** This report was not checked against the "
            "project's live state"
            + (f": {reason}" if reason else "")
            + ". Every finding below is reported exactly as the scanner recorded it, "
            "which means a latent misconfiguration cannot be told apart from an "
            "active exposure here."
        )
    return (body + org_context_note(live_context)).strip()


_GCLOUD_AUTH_BOILERPLATE = "This command is authenticated with an access token"


def _readable_reason(reason: str | None) -> str:
    """A permission error as a customer should read it.

    **Trimmed for display only.** The stored `live_context` and the evidence
    appendix keep the error byte-for-byte, because "the agent saw no org
    policies" and "the agent was not allowed to look" are different facts and
    the appendix is where that is settled. What gets cut here is gcloud's own
    trailing sentence — *"This command is authenticated with an access token
    from the CLOUDSDK_AUTH_ACCESS_TOKEN environment variable"* — which tells a
    reader nothing about their cloud and names one of our environment variables
    in a document we hand to a customer.
    """
    text = (reason or "").strip()
    if not text:
        return ""
    head = text.split(_GCLOUD_AUTH_BOILERPLATE, 1)[0].strip()
    return (head or text).rstrip(". ")


def org_context_note(live_context: dict[str, Any] | None) -> str:
    """The organization half of the banner, appended to the sentence above.

    Separate function, same reason `live_context_note` is one: the PDF renders
    the same words from the same object, and a second copy is how the two
    artifacts drift apart.

    **It says something in every case, including the ordinary one.** An
    organization policy can override a project-level finding — public access
    prevention enforced at the org makes a public-bucket finding moot — so a
    reader who is not told whether that was checked cannot tell a report that
    looked and found nothing from one that could not look. `unavailable` is the
    common case today and it still gets a sentence.
    """
    org = (live_context or {}).get("organization") or {}
    status = str(org.get("status") or "not_applicable")
    reason = _readable_reason(org.get("reason"))

    if status == "available":
        note = " Organization-level policy was also read"
        return note + (f", though {reason}." if reason else " in full.")
    if status == "unavailable":
        return (
            " **Organization-level policy was not readable**, so any constraint set "
            "above this project — public access prevention or domain-restricted "
            "sharing enforced organization-wide — is not reflected below"
            + (f": {reason}" if reason else "")
            + ". A finding here may already be prevented by a policy this report "
            "could not see."
        )
    return ""


def render_markdown(
    *,
    project_id: str,
    scan_id: int,
    payload: dict[str, Any],
    narratives: dict[str, str],
    explanations: dict[str, str],
    executive_summary: str,
    generated_at: datetime.datetime | None = None,
    analysis: dict[str, Any] | None = None,
    live_context: dict[str, Any] | None = None,
) -> str:
    generated = (generated_at or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%d")
    out: list[str] = [
        "# GCP Infrastructure Assessment Report",
        "",
        f"**Project:** {project_id}  ",
        f"**Scan:** {scan_id}  ",
        f"**Generated:** {generated}",
        "",
        "## Executive Summary",
        "",
    ]
    # Above the summary, not below it. The summary is what a reader acts on,
    # and "this was never checked against live state" is a caveat on that
    # sentence rather than a footnote to it.
    out += _live_context_banner(live_context)
    out += [executive_summary.strip(), ""]
    out += _summary_table(payload["severity_counts"])

    # `analysis` carries only what the deep pipeline adds. Absent for a
    # standard report, and every lookup below tolerates that.
    analysis = analysis or {}
    index = build_check_index(payload)
    pillar_analysis: dict[str, str] = analysis.get("pillar_analysis") or {}
    check_context: dict[str, str] = analysis.get("check_context") or {}
    reconciliation: dict[str, dict[str, Any]] = analysis.get("reconciliation") or {}

    out += _themes_section(analysis.get("themes") or [], index)
    # Before the plan, not after it: what live state has already closed changes
    # which of the plan's waves a reader should care about, and a conclusion
    # printed after the work it revises has arrived too late to revise it.
    out += _reconciliation_section(reconciliation, index)
    out += _plan_section(analysis.get("remediation_plan") or [], index)

    for pillar, groups in payload["pillars"].items():
        out += ["---", "", f"## {pillar}", ""]
        if narratives.get(pillar):
            out += [narratives[pillar].strip(), ""]
        if (pillar_analysis.get(pillar) or "").strip():
            out += ["**Analysis**", "", pillar_analysis[pillar].strip(), ""]
        for group in groups:
            out += [
                f"### {group['check_title']}",
                "",
                f"`{group['check_id']}` · **{group['severity'].title()}**"
                + (f" · {group['categories']}" if group["categories"] else ""),
                "",
            ]
            if explanations.get(group["check_id"]):
                out += ["**What this means**", "", explanations[group["check_id"]].strip(), ""]
            if (check_context.get(group["check_id"]) or "").strip():
                out += [
                    "**Why this matters here**",
                    "",
                    check_context[group["check_id"]].strip(),
                    "",
                ]
            # Under the model's prose and above the resource table: it is a
            # statement about this finding, not about the resources, and a
            # reader who has just been told what the finding means is exactly
            # where they need to be told whether it is still true.
            out += _live_context_line(reconciliation.get(group["check_id"]))
            out += _resource_table(group["resources"])
            out += _remediation_block(group)

    # Coverage notes. Both omissions are stated rather than left implicit: a
    # reader comparing this document against the findings screen will otherwise
    # find numbers that disagree with no explanation, and on a heavily-muted
    # project the muted exclusion accounts for most of the difference.
    notes: list[str] = []
    if payload.get("muted_excluded_count"):
        notes.append(
            f"{payload['muted_excluded_count']} muted finding(s) are excluded from this "
            "report. They have been reviewed and accepted as risks, and are not part of "
            "the remediation work described here."
        )
    if payload["skipped_finding_count"]:
        notes.append(
            f"{payload['skipped_finding_count']} finding(s) are not covered because they "
            "were recorded before remediation detail was captured. Re-scan this project to "
            "include them."
        )
    if notes:
        out += ["---", ""]
        for note in notes:
            out += [f"*{note}*", ""]

    # Last, because it is a reference rather than a reading: the citations
    # throughout the document point down into it, and nobody reads it in order.
    out += _evidence_appendix(live_context)
    return "\n".join(out)


# ── formatting validation ────────────────────────────────────────────────────
# A rendered report is a customer-facing artifact, so it is checked before it is
# stored rather than after someone notices. Two passes, with deliberately
# different authority:
#
#   validate_markdown()  — deterministic, and FATAL. Catches the structural
#                          breakage that actually happened (double-fenced code
#                          spilling into body text) and anything like it.
#   the model review     — advisory only, recorded on the report row.
#
# The model is never allowed to rewrite the document. It can only report on it.
# Letting it return corrected Markdown would hand it the remediation commands to
# paraphrase, which is the one thing this feature's design exists to prevent.

MARKDOWN_REVIEW_PROMPT = """You are proofreading the Markdown formatting of a \
generated report. Judge FORMATTING ONLY — never the technical content, and never \
the wording.

Look for:
- code fences that are nested, unbalanced, or wrap another fence
- tables whose rows do not match their header's column count, or whose cell text
  breaks the table
- headings that skip a level or are malformed
- list or emphasis markers that will not render as intended
- raw Markdown syntax that will show up literally to a reader

Do NOT suggest rewording, restructuring, or improving the content. Do NOT return a
corrected document — you are reporting problems, not fixing them.

Return valid JSON only:
{"issues": [{"severity": "error"|"warning", "location": "<a short quote or heading>", \
"problem": "<one sentence>"}]}

Return an empty issues list if the formatting is clean."""

MARKDOWN_REVIEW_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "issues": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "severity": {"type": "STRING"},
                    "location": {"type": "STRING"},
                    "problem": {"type": "STRING"},
                },
                "required": ["severity", "location", "problem"],
            },
        }
    },
    "required": ["issues"],
}


def validate_markdown(content: str) -> list[str]:
    """Structural problems that make the document render wrongly. Empty list
    means clean. Deterministic, so it can be trusted to fail a report."""
    problems: list[str] = []
    lines = content.splitlines()

    fence_lines = [i for i, line in enumerate(lines) if FENCE_RE.match(line)]
    if len(fence_lines) % 2 != 0:
        problems.append(f"unbalanced code fences: {len(fence_lines)} fence markers")

    # The exact defect that shipped in the first report: a fence immediately
    # followed by another, so the outer block closes on the inner one.
    for a, b in zip(fence_lines, fence_lines[1:]):
        if b == a + 1:
            problems.append(f"nested code fence at line {a + 1}: '{lines[a].strip()}' then '{lines[b].strip()}'")

    # Table rows must agree with their header. A stray unescaped pipe in cell
    # text silently splits a row into extra columns.
    in_table = False
    header_cols = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        is_row = stripped.startswith("|") and stripped.endswith("|")
        if is_row and not in_table:
            in_table, header_cols = True, stripped.count("|")
        elif is_row and in_table:
            if stripped.count("|") != header_cols:
                problems.append(
                    f"table row at line {i + 1} has {stripped.count('|') - 1} cells, "
                    f"header has {header_cols - 1}"
                )
        elif not is_row:
            in_table = False

    for i, line in enumerate(lines):
        if line.startswith("#") and not re.match(r"^#{1,6} \S", line):
            problems.append(f"malformed heading at line {i + 1}: {line[:60]!r}")

    return problems
