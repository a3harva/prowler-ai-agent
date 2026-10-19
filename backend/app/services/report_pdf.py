"""PDF rendering for assessment reports.

The template uses a neutral project palette and system fonts. It intentionally
contains no external assets, logos, or organization-specific content.

Same discipline `report_render.py` holds itself to: pure with respect to
Vertex and the database — testable with a plain dict, no network, no
credential. Consumes the exact same finalized `payload`/`narratives`/
`explanations`/`executive_summary` the worker already builds for the
Markdown report; never calls Gemini itself, so there is no path for
remediation text to reach the model here either.
"""

from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import Any

import weasyprint
from jinja2 import Environment
from markupsafe import Markup, escape

from app.models.finding import Severity
from app.services import report_render
from app.services.report_snippets import strip_outer_fence
from app.services.reports import build_check_index

_APP_DIR = Path(__file__).resolve().parent.parent
_TEMPLATES_DIR = _APP_DIR / "templates"
_CSS_PATH = _TEMPLATES_DIR / "report_pdf.css"

# Most-severe-first, matching report_render.py's own _SEVERITY_COLUMNS — kept
# as a separate literal rather than imported, since importing from
# report_render.py here would pull in the whole Markdown-rendering module for
# one tuple; four strings duplicated once is cheaper than that coupling.
_SEVERITY_COLUMNS = ("critical", "high", "medium", "low")

# Most-severe-first ordinal, for the remediation plan's "highest severity"
# column. Same ordering `report_render` uses, from the same enum.
_SEVERITY_RANK = {s.value: i for i, s in enumerate(Severity)}

# autoescape=True is load-bearing, not a default left in place: description,
# risk, and resource-name text come verbatim from Prowler's CSV output and
# are untrusted — unescaped `<`/`&` in any of it would corrupt the rendered
# HTML rather than just looking odd, the same class of risk `_resource_table`
# in report_render.py guards against for Markdown with its own `|` escaping.
_ENV = Environment(autoescape=True)

_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")


def _md_inline(text: str) -> Markup:
    """Minimal, safe inline-markdown: only `**bold**`, nothing else.

    Prowler's remediation text sometimes carries literal `**bold**` markers
    (the same source the Markdown report renders as real emphasis, since
    react-markdown interprets the whole document as Markdown) — printed
    unconverted here it would show raw asterisks, which is exactly what the
    first branded-template render did. Escapes first, then re-marks only
    the `**...**` spans as `<strong>` — the untrusted text is neutralised by
    `escape()` before any tag is added, so this is exactly as safe against a
    hostile Prowler field as autoescaping it outright would be.
    """
    escaped = str(escape(text))
    return Markup(_BOLD_RE.sub(r"<strong>\1</strong>", escaped))


_ENV.filters["md_inline"] = _md_inline

_TEMPLATE = _ENV.from_string(
    """\
{% macro reconciliation_table(rows) %}
<table class="summary">
<tr><th>Check</th><th>Finding</th><th>Severity</th><th>Resources</th><th>Live state</th><th>Evidence</th></tr>
{% for row in rows %}
<tr>
  <td><code>{{ row.check_id }}</code></td>
  <td>{{ row.check_title }}</td>
  <td><span class="sev-pill sev-{{ row.severity }}">{{ row.severity|capitalize }}</span></td>
  <td class="count">{{ row.resource_count }}</td>
  <td>{{ row.label }}</td>
  <td>{% for e in row.evidence %}<code>{{ e }}</code>{% if not loop.last %} · {% endif %}{% else %}&mdash;{% endfor %}</td>
</tr>
{% endfor %}
</table>
{% endmacro %}
<!doctype html>
<html>
<head><meta charset="utf-8"><title>{{ project_id }} — GCP Infrastructure Assessment Report</title></head>
<body>

<!-- Running header/footer content — rendered once here, WeasyPrint copies it
     onto every page's margin boxes via `position: running(...)` / the CSS
     `content: element(...)` rules in report_pdf.css. Not shown inline. -->
<div class="page-header-title">{{ project_id }} — GCP Infrastructure Assessment Report</div>
<div class="page-footer-left">
  <div class="doc-title">{{ project_id }} — GCP Infrastructure Assessment Report</div>
  <div class="doc-client">prowler agent</div>
</div>
<div class="page-footer-right">{{ generated }}</div>

<div class="cover">
  <h1>GCP Infrastructure Assessment Report</h1>
  <p class="subtitle">{{ project_id }} · Scan #{{ scan_id }} · {{ generated }}</p>
</div>

<h2>Executive Summary</h2>
{% if live_context_note %}
<p class="live-context">{{ live_context_note|md_inline }}</p>
{% endif %}
<p>{{ executive_summary|md_inline }}</p>

<h2>Pillar Summary</h2>
<table class="summary">
<tr><th>Pillar</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>
{% for pillar, counts in severity_counts.items() %}
<tr>
  <td>{{ pillar }}</td>
  {% for col in severity_columns %}
  <td class="count {{ col }}{% if not counts.get(col) %} zero{% endif %}">{{ counts.get(col, 0) }}</td>
  {% endfor %}
</tr>
{% endfor %}
</table>

{% if themes %}
<h2>Key Themes</h2>
{% for theme in themes %}
<h3>{{ theme.title }}</h3>
{% if theme.narrative %}<p>{{ theme.narrative|md_inline }}</p>{% endif %}
{% if theme.refs %}
<p class="refs">Related checks: {% for ref in theme.refs %}<code>{{ ref }}</code>{% if not loop.last %} · {% endif %}{% endfor %}</p>
<p class="refs">Affected resources: {{ theme.resource_count }} across {{ theme.service_count }} {{ "service" if theme.service_count == 1 else "services" }}</p>
{% endif %}
{% endfor %}
{% endif %}

{% if reduced_rows or raised_rows %}
<h2>Live-State Reconciliation</h2>
{% if reduced_rows %}
<h3>Findings live state has reduced or closed</h3>
<p>Live state shows these are already controlled, or that the exposure cannot occur at
all. Each is backed by a command in the evidence appendix. They remain in the counts
above &mdash; nothing here changes what the scan found &mdash; but they are where the
cheapest progress is.</p>
{{ reconciliation_table(reduced_rows) }}
{% endif %}
{% if raised_rows %}
<h3>Findings live state has raised</h3>
<p>Live state shows what these protect matters more than their recorded severity
suggests. Consider them earlier in the plan than their severity alone would place
them.</p>
{{ reconciliation_table(raised_rows) }}
{% endif %}
{% endif %}

{% if waves %}
<h2>Remediation Plan</h2>
<table class="summary plan">
<tr><th>Wave</th><th>Focus</th><th>Checks</th><th>Resources</th><th>Highest severity</th></tr>
{% for wave in waves %}
<tr>
  <td class="count">{{ loop.index }}</td>
  <td>{{ wave.label }}</td>
  <td class="count">{{ wave.check_count }}</td>
  <td class="count">{{ wave.resource_count }}</td>
  <td><span class="sev-pill sev-{{ wave.severity }}">{{ wave.severity|capitalize }}</span></td>
</tr>
{% endfor %}
</table>
{% for wave in waves %}
<h3>Wave {{ loop.index }} — {{ wave.label }}</h3>
{% if wave.rationale %}<p>{{ wave.rationale|md_inline }}</p>{% endif %}
{% if wave.refs %}
<p class="refs">Checks in this wave: {% for ref in wave.refs %}<code>{{ ref }}</code>{% if not loop.last %} · {% endif %}{% endfor %}</p>
{% endif %}
{% endfor %}
{% endif %}

{% for pillar, groups in pillars.items() %}
<h2>{{ pillar }}</h2>
{% if narratives.get(pillar) %}<p>{{ narratives[pillar]|md_inline }}</p>{% endif %}
{% if pillar_analysis.get(pillar) %}
<p><strong>Analysis</strong><br>{{ pillar_analysis[pillar]|md_inline }}</p>
{% endif %}
{% for group in groups %}
<h3>{{ group.check_title }}</h3>
<p class="check-meta">
  <code>{{ group.check_id }}</code> ·
  <span class="sev-pill sev-{{ group.severity }}">{{ group.severity|capitalize }}</span>
  {%- if group.categories %} · {{ group.categories }}{% endif %}
</p>
{% if explanations.get(group.check_id) %}
<p><strong>What this means</strong><br>{{ explanations[group.check_id]|md_inline }}</p>
{% endif %}
{% if check_context.get(group.check_id) %}
<p><strong>Why this matters here</strong><br>{{ check_context[group.check_id]|md_inline }}</p>
{% endif %}
{% if reconciliation.get(group.check_id) %}
{% set live = reconciliation[group.check_id] %}
<p class="live-context"><strong>Live context &mdash; {{ live.label }}</strong>
{%- if live.evidence %} · evidence {% for e in live.evidence %}<code>{{ e }}</code>{% if not loop.last %} · {% endif %}{% endfor %}{% endif %}
{%- if live.statement %}<br>{{ live.statement|md_inline }}{% endif %}</p>
{% endif %}
<p><strong>Affected resources</strong></p>
<table class="resources">
<tr><th>Resource</th><th>Region</th><th>Detail</th><th>Status</th></tr>
{% for r in group.resources %}
<tr>
  <td><code>{{ r.resource_name }}</code></td>
  <td>{{ r.region }}</td>
  <td>{{ r.status_extended or "" }}</td>
  <td>
    {% if r.muted %}
    <span class="status-pill status-muted">Accepted Risk — {{ r.mute_reason }}</span>
    {% else %}
    <span class="status-pill status-open">Open</span>
    {% endif %}
  </td>
</tr>
{% endfor %}
</table>
{% if group.remediation_text %}
<p><strong>Remediation</strong><br>{{ group.remediation_text|md_inline }}</p>
{% endif %}
{% if group.remediation_cli_inner %}
<p><strong>Command line</strong></p>
<pre>{{ group.remediation_cli_inner }}</pre>
{% endif %}
{% if group.remediation_terraform_inner %}
<p><strong>Terraform</strong></p>
<pre>{{ group.remediation_terraform_inner }}</pre>
{% endif %}
{% endfor %}
{% endfor %}

{% if evidence_rows %}
<h2>Evidence Appendix</h2>
<p>Every read-only command run against the live project while this report was written,
in the order they were attempted. Commands that failed or were refused are listed too
&mdash; what could not be read is part of what this report knows.</p>
{% for row in evidence_rows %}
<p class="refs"><strong>{{ row.evidence_id }}</strong> &mdash; {{ row.outcome }}
{%- if row.why %}<br><em>Why:</em> {{ row.why }}{% endif %}
{%- if row.when %}<br><em>Run at:</em> {{ row.when }}{% endif %}</p>
<pre>{{ row.command }}</pre>
{% endfor %}
{% endif %}

{% if notes %}
<div class="notes">
{% for note in notes %}
<p><em>{{ note }}</em></p>
{% endfor %}
</div>
{% endif %}
</body>
</html>
"""
)


def _snippet_inner(content: str | None) -> str | None:
    """Reduces a CLI/Terraform snippet to the text a `<pre>` block should
    show — stripping one layer of fencing if Prowler supplied it pre-fenced,
    same normalization `report_render.py`'s Markdown path uses, so the
    Markdown and PDF renderings of the same finding never disagree on the
    command text a customer is about to run."""
    body = (content or "").strip()
    if not body:
        return None
    return strip_outer_fence(body) or body


def _theme_rows(themes: list[dict[str, Any]], index: dict[str, Any]) -> list[dict[str, Any]]:
    """Themes with their arithmetic already done.

    Computed here rather than in the template for the same reason the fence
    stripping is: a Jinja template is the wrong place for the rule that the
    model never supplies a number. Mirrors
    `report_render._themes_section` exactly, and both read the same index, so
    the Markdown and the PDF cannot disagree about a count.
    """
    rows = []
    for theme in themes:
        refs = [c for c in (theme.get("refs") or []) if c in index]
        if not refs:
            continue
        rows.append(
            {
                "title": theme.get("title", "Theme"),
                "narrative": theme.get("narrative", ""),
                "refs": refs,
                "resource_count": sum(index[c]["resource_count"] for c in refs),
                "service_count": len({index[c]["service_name"] for c in refs if index[c]["service_name"]}),
            }
        )
    return rows


def _wave_rows(waves: list[dict[str, Any]], index: dict[str, Any]) -> list[dict[str, Any]]:
    """Waves with their arithmetic already done. Mirrors
    `report_render._plan_section`."""
    rows = []
    for wave in waves:
        refs = [c for c in (wave.get("refs") or []) if c in index]
        rows.append(
            {
                "label": wave.get("label", "Unlabelled wave"),
                "rationale": wave.get("rationale", ""),
                "refs": refs,
                "check_count": len(refs),
                "resource_count": sum(index[c]["resource_count"] for c in refs),
                "severity": min(
                    (index[c]["severity"] for c in refs),
                    key=lambda s: _SEVERITY_RANK[s],
                    default="low",
                ),
            }
        )
    return [w for w in rows if w["refs"]]


def _reconciliation_rows(
    reconciliation: dict[str, Any], index: dict[str, Any], verdicts: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Reconciliation rows with their labels already resolved.

    The labels come from `report_render.VERDICT_LABELS` rather than a second
    mapping here, for the reason `live_context_note` is imported rather than
    re-worded: the Markdown and the PDF are built from the same objects so
    they cannot disagree, and a duplicated label table is exactly how they
    would start to.
    """
    rows = []
    for check_id, entry in (reconciliation or {}).items():
        if entry.get("verdict") not in verdicts or check_id not in index:
            continue
        meta = index[check_id]
        rows.append(
            {
                "check_id": check_id,
                "check_title": meta["check_title"],
                "severity": meta["severity"],
                "resource_count": meta["resource_count"],
                "label": report_render.VERDICT_LABELS[entry["verdict"]],
                "evidence": list(entry.get("evidence") or []),
            }
        )
    return rows


def _per_check_reconciliation(
    reconciliation: dict[str, Any], index: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    """The per-finding live-context line, keyed by check_id.

    Every check in the ledger, `no_evidence` included — the Markdown renders
    that line unconditionally and the PDF has to say the same thing, or a
    reader comparing the two artifacts finds a finding that was checked in one
    and silent in the other.
    """
    out: dict[str, dict[str, Any]] = {}
    for check_id, entry in (reconciliation or {}).items():
        if check_id not in index:
            continue
        verdict = entry.get("verdict") or "no_evidence"
        out[check_id] = {
            "label": report_render.VERDICT_LABELS.get(
                verdict, report_render.VERDICT_LABELS["no_evidence"]
            ),
            "statement": (entry.get("statement") or "").strip(),
            "evidence": list(entry.get("evidence") or []),
        }
    return out


def _evidence_rows(live_context: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The evidence appendix, from the same log the Markdown appendix reads
    and through the same two formatters."""
    return [
        {
            "evidence_id": str(entry.get("evidence_id") or "?"),
            "command": str(entry.get("command") or "").strip(),
            "why": " ".join(str(entry.get("why") or "").split()),
            "when": report_render.evidence_when(entry),
            "outcome": report_render.evidence_outcome(entry),
        }
        for entry in ((live_context or {}).get("command_log") or [])
    ]


def render_pdf_html(
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

    # Pre-compute the fence-stripped snippet text per group so the template
    # itself stays free of that logic — Jinja templates are the wrong place
    # for the double-fence-defect-prevention rule to live.
    pillars: dict[str, list[dict[str, Any]]] = {}
    for pillar, groups in payload["pillars"].items():
        enriched = []
        for group in groups:
            g = dict(group)
            g["remediation_cli_inner"] = _snippet_inner(group.get("remediation_cli"))
            g["remediation_terraform_inner"] = _snippet_inner(group.get("remediation_terraform"))
            enriched.append(g)
        pillars[pillar] = enriched

    notes: list[str] = []
    if payload.get("muted_excluded_count"):
        notes.append(
            f"{payload['muted_excluded_count']} muted finding(s) are excluded from this "
            "report. They have been reviewed and accepted as risks, and are not part of "
            "the remediation work described here."
        )
    if payload.get("skipped_finding_count"):
        notes.append(
            f"{payload['skipped_finding_count']} finding(s) are not covered because they "
            "were recorded before remediation detail was captured. Re-scan this project to "
            "include them."
        )

    # Deep-mode extras. Absent for a standard report, and every lookup in
    # the template tolerates that.
    analysis = analysis or {}
    index = build_check_index(payload)

    return _TEMPLATE.render(
        project_id=project_id,
        scan_id=scan_id,
        generated=generated,
        executive_summary=executive_summary.strip(),
        pillars=pillars,
        narratives=narratives,
        explanations=explanations,
        notes=notes,
        severity_counts=payload.get("severity_counts", {}),
        severity_columns=_SEVERITY_COLUMNS,
        themes=_theme_rows(analysis.get("themes") or [], index),
        waves=_wave_rows(analysis.get("remediation_plan") or [], index),
        pillar_analysis=analysis.get("pillar_analysis") or {},
        check_context=analysis.get("check_context") or {},
        # The identical sentence the Markdown banner renders, from
        # `report_render` rather than re-derived here. The two artifacts are
        # built from the same objects precisely so they cannot drift, and a
        # second copy of this wording is exactly how they would.
        live_context_note=report_render.live_context_note(live_context),
        reconciliation=_per_check_reconciliation(analysis.get("reconciliation") or {}, index),
        reduced_rows=_reconciliation_rows(
            analysis.get("reconciliation") or {}, index, report_render.REDUCED_VERDICTS
        ),
        raised_rows=_reconciliation_rows(
            analysis.get("reconciliation") or {}, index, ("amplifies",)
        ),
        evidence_rows=_evidence_rows(live_context),
    )


def render_pdf_bytes(
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
) -> bytes:
    html = render_pdf_html(
        project_id=project_id,
        scan_id=scan_id,
        payload=payload,
        narratives=narratives,
        explanations=explanations,
        executive_summary=executive_summary,
        generated_at=generated_at,
        analysis=analysis,
        live_context=live_context,
    )
    # The template intentionally uses no relative assets. The stylesheet is
    # loaded separately so PDF output cannot disclose local asset paths.
    return weasyprint.HTML(string=html, base_url=str(_TEMPLATES_DIR)).write_pdf(
        stylesheets=[weasyprint.CSS(filename=str(_CSS_PATH))]
    )
