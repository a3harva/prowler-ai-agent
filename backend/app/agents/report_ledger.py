"""The ledger, and the deterministic gates that hold it.

`services/reports.py::build_report_payload` produces the payload. This module
promotes it into a **ledger**: an index keyed by `check_id`, a content hash,
and eight checks that prove a finished document still says what the database
says.

**The guarantee, and where it actually comes from.** It does not come from
these gates. It comes from `report_render.render_markdown` iterating the
*ledger* and looking model prose up by key — so a model cannot add a section
(it never emits one) and cannot drop a section (the ledger drives the loop).
The gates exist to catch the ways prose can still be wrong *around* that
structure: a check with no explanation, a theme citing a check that is not in
this project, a remediation wave that forgets half the work, a paragraph
containing a `gcloud` command the model made up.

Every function here is pure — a plain dict in, findings out. No database, no
model, no network. That is what makes the safety net testable before anything
it protects exists.

**Two verifiers, deliberately different in authority:**

- `verify_artifacts` runs on the model's output *before* rendering. Its
  failures name repair targets and the graph regenerates just those. A failure
  here is a model that got something wrong, which is expected and recoverable.
- `verify_document` runs on the rendered Markdown *after*. Its failures are
  fatal and un-repairable, because they compare the document against the
  ledger and a mismatch there is a renderer bug — no amount of regenerating
  prose fixes a renderer that dropped a row.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

# One definition of "the index", owned by the module that owns the payload.
# Re-exported here because the gates' vocabulary calls it the ledger index,
# and because every importer of this module expects to find it here.
from app.services.report_render import EVIDENCE_SECTION, RECONCILIATION_SECTION
from app.services.reports import build_check_index as build_index  # noqa: F401

# `## ` headings that are not pillars. `render_markdown` emits one `##` per
# pillar plus these six fixed sections, so structural parsing has to know
# which is which — and getting this list wrong is how the Remediation Plan's
# own `###` wave headings would be miscounted as checks. The two live-context
# sections are on the list for the same reason the other four are: `render_markdown` emits them as `##`, and anything `##` that is not on
# this list is read as a WAF pillar — by `parse_rendered` below, which would
# then fail C4 for a pillar the ledger has never heard of, and by
# `frontend/src/lib/report-markdown-plugin.ts`, which would list it in the
# table of contents. Adding a section means adding it in both places.
NON_PILLAR_SECTIONS = frozenset(
    {
        "Executive Summary",
        "Pillar Summary",
        "Key Themes",
        "Remediation Plan",
        RECONCILIATION_SECTION,
        EVIDENCE_SECTION,
    }
)

_SEVERITY_COLUMNS = ("critical", "high", "medium", "low")

# The meta line under each check heading: `check_id` · **Severity** · categories
_CHECK_META_RE = re.compile(r"^`([^`]+)`\s+·\s+\*\*")

_RESOURCE_HEADER = "| Resource | Region | Detail | Status |"

# ── C6: what a model must never write ────────────────────────────────────────
# Remediation commands come verbatim from Prowler's version-pinned output,
# carried through the `findings` row. A model that invents one is the single
# worst failure this feature can have, so prose is scanned for the shapes a
# command takes rather than trusted to a prompt.
#
# The patterns match executable *shapes*, not the words. A flat search for
# "gcloud" would refuse the perfectly good sentence "run the gcloud command
# shown below" — prose a report should be allowed to contain — and a loose
# "binary followed by two words" rule refuses it too ("gcloud command
# supplied"). So a command is recognised by what makes it runnable: a fence, a
# flag, a hyphenated subcommand, or a bucket URI.
#
# The known gap is an inline, flagless, unhyphenated command such as `gcloud
# config set project x`. Accepted deliberately: tightening far enough to catch
# it starts refusing ordinary sentences, the fence rule already catches the
# shape a model actually produces, and C6 is repairable rather than fatal — so
# the cost of a miss is one imperfect paragraph, while the cost of a false
# positive is a wasted regeneration on good prose.
# The binaries a fabricated GCP remediation command would invoke. `terraform`
# is deliberately absent — it is an ordinary English noun that legitimately
# starts a sentence ("Terraform is the recommended route here"), and the
# Terraform risk is already covered by the `resource "google_` pattern and by
# the fence rule.
_BINARIES = r"gcloud|gsutil|bq|kubectl"

_FORBIDDEN_PROSE = (
    # By far the dominant real-world shape: a model that decides to be helpful
    # fences the command. Unambiguous, so it is refused outright.
    (re.compile(r"^\s*(?:```|~~~)", re.MULTILINE), "a fenced code block"),
    # Inline, but carrying a flag. Prose does not contain `-f` or `--project`,
    # and a command without arguments is not one a customer could run.
    (
        re.compile(rf"\b(?:{_BINARIES})\b[^\n]{{0,80}}?\s-{{1,2}}[A-Za-z]"),
        "a command with flags",
    ),
    # A hyphenated subcommand directly after the binary — `projects
    # add-iam-policy-binding`, `iam service-accounts`. English prose does not
    # put a hyphenated compound in that position after a CLI name.
    (
        re.compile(rf"\b(?:{_BINARIES})\s+[a-z][a-z0-9]*\s+[a-z0-9]+(?:-[a-z0-9]+)+"),
        "a command",
    ),
    (re.compile(r"\bgsutil\b[^\n]{0,60}gs://"), "a gsutil command"),
    (re.compile(r'resource\s+"google_'), "a Terraform resource block"),
)


@dataclass(frozen=True)
class GateFailure:
    """One thing a gate found wrong.

    `repair_targets` is the vocabulary the graph's repair node dispatches on:
    `check:<check_id>`, `pillar:<name>`, `themes`, `plan`, `summary`,
    `reconciliation`. Empty
    means nothing can be regenerated to fix it — which for `verify_artifacts`
    should not happen, and for `verify_document` is always the case.
    """

    gate: str
    detail: str
    repair_targets: tuple[str, ...] = field(default=())

    def as_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "detail": self.detail,
            "repair_targets": list(self.repair_targets),
        }


# ── building the ledger ──────────────────────────────────────────────────────


def digest(payload: dict[str, Any]) -> str:
    """A content hash of the ledger.

    Recorded on the report and re-checked before rendering. Its job is to
    catch the ledger being mutated mid-run — by a node that edited the dict it
    was handed rather than copying it, or by a resumed run picking up a
    checkpoint written against a different scan. Cheap insurance on the one
    object the whole count guarantee rests on.
    """
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def pillar_order(payload: dict[str, Any]) -> list[str]:
    """Pillars with content, in report order. `build_report_payload` already
    orders and omits empties; this just names the operation."""
    return list(payload["pillars"].keys())


# ── C6 helper ────────────────────────────────────────────────────────────────


def scan_prose(label: str, text: str) -> list[str]:
    """Every forbidden shape found in one piece of model-authored prose."""
    problems = []
    for pattern, description in _FORBIDDEN_PROSE:
        if pattern.search(text or ""):
            problems.append(f"{label} contains {description}")
    return problems


def _prose_fields(
    *,
    check_analysis: dict[str, dict[str, str]],
    pillar_analysis: dict[str, dict[str, str]],
    themes: list[dict[str, Any]],
    remediation_plan: list[dict[str, Any]],
    executive_summary: str,
    reconciliation: dict[str, dict[str, Any]] | None = None,
) -> list[tuple[str, str, str]]:
    """(label, text, repair_target) for every string a model wrote.

    Enumerated in one place so C6 cannot silently miss a field that a later
    change adds to an artifact.
    """
    fields: list[tuple[str, str, str]] = [
        ("the executive summary", executive_summary, "summary")
    ]
    for check_id, entry in check_analysis.items():
        for key in ("explanation", "why_here"):
            fields.append((f"{check_id}'s {key}", entry.get(key, ""), f"check:{check_id}"))
    for pillar, entry in pillar_analysis.items():
        for key in ("narrative", "analysis"):
            fields.append((f"{pillar}'s {key}", entry.get(key, ""), f"pillar:{pillar}"))
    for i, theme in enumerate(themes):
        fields.append((f"theme {i + 1}'s title", theme.get("title", ""), "themes"))
        fields.append((f"theme {i + 1}'s narrative", theme.get("narrative", ""), "themes"))
    for i, wave in enumerate(remediation_plan):
        fields.append((f"wave {i + 1}'s label", wave.get("label", ""), "plan"))
        fields.append((f"wave {i + 1}'s rationale", wave.get("rationale", ""), "plan"))
    # A reconciliation statement is prose about commands, written by a model
    # that has just been reading command output — which makes it the single
    # most likely place in the document for one to be quoted back. C6 covers
    # it for exactly that reason.
    for check_id, entry in (reconciliation or {}).items():
        fields.append(
            (f"{check_id}'s live-state statement", entry.get("statement", ""), "reconciliation")
        )
    return fields


# ── verify_artifacts: C1, C2, C3, C6, C7 ─────────────────────────────────────


def verify_artifacts(
    *,
    index: dict[str, dict[str, Any]],
    check_analysis: dict[str, dict[str, str]],
    pillar_analysis: dict[str, dict[str, str]],
    themes: list[dict[str, Any]],
    remediation_plan: list[dict[str, Any]],
    executive_summary: str,
    reconciliation: dict[str, dict[str, Any]] | None = None,
    evidence_ids: set[str] | None = None,
) -> list[GateFailure]:
    """Everything checkable before a single character is rendered.

    Returns an empty list when the artifacts are sound. Every failure names
    repair targets, because the point of running this before the renderer is
    that the graph can fix what it finds instead of failing the report.
    """
    failures: list[GateFailure] = []
    known = set(index)
    reconciliation = reconciliation or {}
    evidence_ids = evidence_ids or set()

    # ── C1 coverage ─────────────────────────────────────────────────────────
    # The document renders one section per ledger check. A check with no
    # explanation renders as a section with a table and no prose, which reads
    # as an oversight to a customer; a check_analysis entry for something not
    # in the ledger renders as nothing at all, which means the model is
    # reasoning about a project it cannot see.
    missing = sorted(known - set(check_analysis))
    if missing:
        failures.append(
            GateFailure(
                gate="C1",
                detail=(
                    f"{len(missing)} check(s) in the ledger have no analysis: "
                    + ", ".join(missing[:8])
                    + ("…" if len(missing) > 8 else "")
                ),
                repair_targets=tuple(f"check:{c}" for c in missing),
            )
        )

    unknown = sorted(set(check_analysis) - known)
    if unknown:
        # Repairable rather than fatal: the extra key changes nothing in the
        # output, so failing the whole report over it is disproportionate.
        # What it does signal is a model that has lost track of scope, and
        # regenerating the affected pillar is the proportionate response. If
        # it survives the repair budget the run fails anyway.
        # Every pillar, because an unattributable key cannot be traced to
        # the pillar whose compose pass produced it. That is blunt, and it is
        # meant to be rare: `report_nodes.compose` already discards keys
        # outside the pillar it is composing, so reaching here at all means
        # something upstream of that filter is wrong.
        failures.append(
            GateFailure(
                gate="C1",
                detail=(
                    f"analysis written for {len(unknown)} check(s) that are not in this "
                    "project's ledger: " + ", ".join(unknown[:8])
                ),
                repair_targets=tuple(
                    f"pillar:{p}" for p in sorted({e["pillar"] for e in index.values()})
                ),
            )
        )

    # ── C2 reference integrity ──────────────────────────────────────────────
    # A theme or a wave is only meaningful if the checks it cites exist here.
    # An unknown ref would render as a dead `check_id` a reader cannot find in
    # the document, and would break the renderer's resource-count arithmetic.
    for i, theme in enumerate(themes):
        bad = sorted(set(theme.get("refs") or []) - known)
        if bad:
            failures.append(
                GateFailure(
                    gate="C2",
                    detail=(
                        f"theme {i + 1} ({theme.get('title', 'untitled')!r}) cites "
                        f"{len(bad)} unknown check(s): " + ", ".join(bad[:5])
                    ),
                    repair_targets=("themes",),
                )
            )
    for i, wave in enumerate(remediation_plan):
        bad = sorted(set(wave.get("refs") or []) - known)
        if bad:
            failures.append(
                GateFailure(
                    gate="C2",
                    detail=(
                        f"wave {i + 1} ({wave.get('label', 'unlabelled')!r}) cites "
                        f"{len(bad)} unknown check(s): " + ", ".join(bad[:5])
                    ),
                    repair_targets=("plan",),
                )
            )

    unknown_pillars = sorted(set(pillar_analysis) - {e["pillar"] for e in index.values()})
    if unknown_pillars:
        failures.append(
            GateFailure(
                gate="C2",
                detail=(
                    "analysis written for pillar(s) with no findings in this project: "
                    + ", ".join(unknown_pillars)
                ),
                repair_targets=tuple(f"pillar:{p}" for p in unknown_pillars),
            )
        )

    # ── C3 plan partition ───────────────────────────────────────────────────
    # The remediation plan is the document's answer to "what do we do, in what
    # order". A check missing from every wave is work the plan silently drops;
    # a check in two waves is work counted twice, and makes the per-wave
    # resource totals the renderer computes add up to more than the project
    # actually has.
    if remediation_plan:
        seen = Counter()
        for wave in remediation_plan:
            seen.update(set(wave.get("refs") or []))

        unplanned = sorted(known - set(seen))
        if unplanned:
            failures.append(
                GateFailure(
                    gate="C3",
                    detail=(
                        f"{len(unplanned)} check(s) appear in no remediation wave: "
                        + ", ".join(unplanned[:8])
                        + ("…" if len(unplanned) > 8 else "")
                    ),
                    repair_targets=("plan",),
                )
            )

        duplicated = sorted(c for c, n in seen.items() if n > 1 and c in known)
        if duplicated:
            failures.append(
                GateFailure(
                    gate="C3",
                    detail=(
                        f"{len(duplicated)} check(s) appear in more than one wave: "
                        + ", ".join(duplicated[:8])
                    ),
                    repair_targets=("plan",),
                )
            )
    elif known:
        failures.append(
            GateFailure(
                gate="C3",
                detail="the remediation plan is empty but the ledger has checks to plan for",
                repair_targets=("plan",),
            )
        )

    # ── C7 every verdict is backed by evidence that exists ──────────────────
    # This is the gate the whole live-context feature rests on. A verdict is a
    # claim about the world — "this database is stopped, close the finding" —
    # and a customer will act on it. An uncited claim is indistinguishable from
    # a guess, and a claim citing a command that never ran is worse than a
    # guess, because the citation makes it look checked.
    #
    # `no_evidence` is the one verdict that cites nothing, because it *is* the
    # absence of evidence. Excluding it here is what lets "we did not look" be
    # printed honestly rather than being pushed into a claim to satisfy a gate.
    uncited = sorted(
        c
        for c, entry in reconciliation.items()
        if entry.get("verdict") != "no_evidence" and not entry.get("evidence")
    )
    if uncited:
        failures.append(
            GateFailure(
                gate="C7",
                detail=(
                    f"{len(uncited)} live-state verdict(s) cite no evidence: "
                    + ", ".join(uncited[:8])
                    + ("…" if len(uncited) > 8 else "")
                ),
                repair_targets=("reconciliation",),
            )
        )

    for check_id in sorted(reconciliation):
        bad = sorted(set(reconciliation[check_id].get("evidence") or []) - evidence_ids)
        if bad:
            failures.append(
                GateFailure(
                    gate="C7",
                    detail=(
                        f"{check_id}'s live-state verdict cites {len(bad)} evidence id(s) "
                        "that are not in this run's command log: " + ", ".join(bad[:5])
                    ),
                    repair_targets=("reconciliation",),
                )
            )

    unknown_reconciled = sorted(set(reconciliation) - known)
    if unknown_reconciled:
        failures.append(
            GateFailure(
                gate="C7",
                detail=(
                    f"live-state verdict(s) written for {len(unknown_reconciled)} check(s) "
                    "that are not in this project's ledger: "
                    + ", ".join(unknown_reconciled[:8])
                ),
                repair_targets=("reconciliation",),
            )
        )

    # ── C6 no fabricated commands ───────────────────────────────────────────
    for label, text, target in _prose_fields(
        check_analysis=check_analysis,
        pillar_analysis=pillar_analysis,
        themes=themes,
        remediation_plan=remediation_plan,
        executive_summary=executive_summary,
        reconciliation=reconciliation,
    ):
        for problem in scan_prose(label, text):
            failures.append(GateFailure(gate="C6", detail=problem, repair_targets=(target,)))

    return failures


# ── verify_document: C4, C5, C6 (the appendix), C8 ───────────────────────────


def parse_rendered(content: str) -> dict[str, Any]:
    """Read the emitted Markdown back as structure.

    Deliberately a second, independent reading of the document rather than a
    re-inspection of the objects that produced it. Comparing the renderer's
    input against itself would prove nothing; comparing what a *reader* will
    see against the ledger is the check worth having, and it catches renderer
    bugs as well as prose ones.

    The parser recognises exactly the shapes `render_markdown` emits, which is
    the same contract `frontend/src/lib/report-markdown-plugin.ts` already
    depends on — so a change that breaks this parser breaks the frontend too,
    and failing loudly here is the cheaper way to find out.
    """
    pillars: dict[str, list[str]] = {}
    resource_rows: dict[str, int] = {}
    severity_table: dict[str, dict[str, int]] = {}

    current_pillar: str | None = None
    current_check: str | None = None
    in_summary_table = False
    in_resource_table = False

    for raw in content.splitlines():
        line = raw.strip()

        if line.startswith("## "):
            heading = line[3:].strip()
            in_summary_table = heading == "Pillar Summary"
            in_resource_table = False
            current_check = None
            if heading in NON_PILLAR_SECTIONS:
                current_pillar = None
            else:
                current_pillar = heading
                pillars.setdefault(heading, [])
            continue

        if line.startswith("### "):
            # A `###` inside Remediation Plan is a wave, not a check —
            # `current_pillar` is None there, which is what keeps waves out of
            # the check counts.
            current_check = None
            in_resource_table = False
            continue

        if current_pillar is not None and current_check is None:
            meta = _CHECK_META_RE.match(line)
            if meta:
                current_check = meta.group(1)
                pillars[current_pillar].append(current_check)
                resource_rows[current_check] = 0
                continue

        if line == _RESOURCE_HEADER:
            in_resource_table = True
            continue

        if in_resource_table:
            if line.startswith("|") and line.endswith("|"):
                # Skip the alignment row that follows every header.
                if not set(line.replace("|", "").replace(" ", "")) <= {"-", ":"}:
                    if current_check is not None:
                        resource_rows[current_check] += 1
            else:
                in_resource_table = False

        if in_summary_table and line.startswith("|") and line.endswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            # The header row (`Pillar`) and the alignment row (`---`) are
            # the only two non-data rows this table has.
            if len(cells) == 5 and cells[0] not in ("Pillar", "---"):
                try:
                    severity_table[cells[0]] = {
                        col: int(cells[i + 1]) for i, col in enumerate(_SEVERITY_COLUMNS)
                    }
                except ValueError:
                    # A non-numeric cell is itself a defect; recorded as an
                    # absent row so C5 reports the mismatch rather than
                    # crashing the verifier.
                    continue

    return {
        "pillars": pillars,
        "resource_rows": resource_rows,
        "severity_table": severity_table,
    }


# ── C6, second half: the commands the document is allowed to print ───────────
# `_FORBIDDEN_PROSE` above keeps a model from writing a command. It cannot be
# the whole rule any more, because the evidence appendix legitimately contains
# commands — the ones that actually ran.
#
# So the rule is strengthened rather than relaxed: model prose still may not
# contain a command shape at all, and the *document* may contain one only
# inside the appendix and only byte-identical to an entry in the command log.
# The renderer builds that section straight from the log, so this holds by
# construction today; the gate is what keeps it holding after someone edits
# the renderer, which is precisely when a fabricated command would otherwise
# reach a customer unnoticed.

_FENCE_BLOCK_RE = re.compile(r"^(?:```|~~~)[^\n]*\n(.*?)^(?:```|~~~)", re.MULTILINE | re.DOTALL)


def evidence_section_of(content: str) -> str:
    """The Evidence Appendix's body, or "" if the document has none.

    A line scan rather than a Markdown parse, matching `parse_rendered`'s own
    posture: it recognises exactly the shapes `render_markdown` emits, so a
    change that breaks this reading breaks the renderer's contract too and
    should fail loudly here.
    """
    lines = content.splitlines()
    body: list[str] = []
    inside = False
    for line in lines:
        if line.startswith("## "):
            inside = line[3:].strip() == EVIDENCE_SECTION
            continue
        if inside:
            body.append(line)
    return "\n".join(body)


def _verify_evidence_commands(
    *, content: str, command_log: list[dict[str, Any]]
) -> list[GateFailure]:
    """Every command the appendix prints really ran. Fatal.

    Fenced blocks rather than inline code spans, because a `bq query`
    statement contains backticks — BigQuery requires them around a dataset
    identifier (see `integrations/cloud_cli_guards.py`), and an inline span cannot
    hold one. Rendering those as inline code would break the document and
    silently truncate the command this gate is comparing.
    """
    section = evidence_section_of(content)
    if not section:
        return []
    ran = {str(entry.get("command") or "").strip() for entry in command_log}
    failures: list[GateFailure] = []
    for match in _FENCE_BLOCK_RE.finditer(section):
        printed = match.group(1).strip()
        if printed and printed not in ran:
            failures.append(
                GateFailure(
                    gate="C6",
                    detail=(
                        "the evidence appendix prints a command that is not in this "
                        f"run's command log: {printed[:120]!r}"
                    ),
                )
            )
    return failures


def verify_document(
    *,
    index: dict[str, dict[str, Any]],
    payload: dict[str, Any],
    content: str,
    ledger_digest: str | None = None,
    command_log: list[dict[str, Any]] | None = None,
) -> list[GateFailure]:
    """C4, C5, C8 and C6's appendix rule, against the finished Markdown.
    Failures here are fatal.

    Nothing a model could regenerate would fix a document whose section count
    disagrees with the database, because the model does not emit sections. A
    failure means the renderer is wrong, and a wrong renderer must not produce
    a customer-facing artifact.
    """
    failures: list[GateFailure] = []
    parsed = parse_rendered(content)

    # ── C8 the ledger did not move ──────────────────────────────────────────
    # The counts are computed from the database before anything live is read,
    # and nothing the cloud returns may alter them: a report generated with
    # live context must carry exactly the same numbers as one generated
    # without it. C4 and C5 below cannot see this on their own — they compare
    # the document against `payload`, so a mutated payload would reconcile
    # perfectly with a document rendered from it. Only the frozen digest
    # catches that.
    #
    # `report_nodes.render` raises on the same condition one node earlier, and
    # that layer is the one that actually fires: refusing to render at all is
    # strictly better than rendering and then failing. This is kept, and
    # tested directly, for the reason `cloud_cli_guards`'s G2b `;` rule is —
    # it is the check that has to hold if the earlier one is ever removed.
    if ledger_digest is not None and digest(payload) != ledger_digest:
        failures.append(
            GateFailure(
                gate="C8",
                detail=(
                    "the ledger changed after it was frozen — the document's counts no "
                    "longer describe the findings the report was built from"
                ),
            )
        )

    failures += _verify_evidence_commands(content=content, command_log=command_log or [])

    # ── C4 structure ────────────────────────────────────────────────────────
    expected_by_pillar: dict[str, list[str]] = {}
    for check_id, entry in index.items():
        expected_by_pillar.setdefault(entry["pillar"], []).append(check_id)

    rendered_pillars = parsed["pillars"]
    for pillar, expected in expected_by_pillar.items():
        rendered = rendered_pillars.get(pillar)
        if rendered is None:
            failures.append(
                GateFailure(
                    gate="C4",
                    detail=f"pillar {pillar!r} has {len(expected)} check(s) but no section rendered",
                )
            )
            continue
        if sorted(rendered) != sorted(expected):
            missing = sorted(set(expected) - set(rendered))
            extra = sorted(set(rendered) - set(expected))
            failures.append(
                GateFailure(
                    gate="C4",
                    detail=(
                        f"pillar {pillar!r} rendered {len(rendered)} check section(s), "
                        f"ledger has {len(expected)}"
                        + (f"; missing {', '.join(missing[:5])}" if missing else "")
                        + (f"; unexpected {', '.join(extra[:5])}" if extra else "")
                    ),
                )
            )

    for pillar in sorted(set(rendered_pillars) - set(expected_by_pillar)):
        failures.append(
            GateFailure(
                gate="C4",
                detail=f"rendered a pillar section {pillar!r} that is not in the ledger",
            )
        )

    for check_id, entry in index.items():
        rendered_rows = parsed["resource_rows"].get(check_id)
        if rendered_rows is None:
            # Already reported by the section check above; not worth a second
            # failure naming the same cause.
            continue
        if rendered_rows != entry["resource_count"]:
            failures.append(
                GateFailure(
                    gate="C4",
                    detail=(
                        f"{check_id} rendered {rendered_rows} resource row(s), "
                        f"ledger has {entry['resource_count']}"
                    ),
                )
            )

    # ── C5 severity reconciliation ──────────────────────────────────────────
    expected_counts = {
        pillar: Counter(g["severity"] for g in groups)
        for pillar, groups in payload["pillars"].items()
    }
    rendered_counts = parsed["severity_table"]

    for pillar, counts in expected_counts.items():
        row = rendered_counts.get(pillar)
        if row is None:
            failures.append(
                GateFailure(gate="C5", detail=f"Pillar Summary has no row for {pillar!r}")
            )
            continue
        for column in _SEVERITY_COLUMNS:
            if row.get(column, 0) != counts.get(column, 0):
                failures.append(
                    GateFailure(
                        gate="C5",
                        detail=(
                            f"Pillar Summary says {pillar!r} has {row.get(column, 0)} "
                            f"{column} check(s), ledger has {counts.get(column, 0)}"
                        ),
                    )
                )

    for pillar in sorted(set(rendered_counts) - set(expected_counts)):
        failures.append(
            GateFailure(gate="C5", detail=f"Pillar Summary has a row for unknown pillar {pillar!r}")
        )

    return failures
