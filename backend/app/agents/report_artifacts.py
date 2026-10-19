"""What each model node is allowed to return, and how it is normalised.

Two things live here, deliberately together: the Gemini `response_schema` for
every structured call, and the coercion that turns whatever comes back into
the plain dicts the gates and the renderer expect.

**Schemas are declared, not merely described.** A malformed shape is then the
API's problem to reject rather than ours to parse around — the same reasoning
`integrations/gemini.py` already applies to the standard report path, and the
uppercase type names are that API's spelling, not a typo.

**Every coercion is total.** A node must not raise on a model that returned a
slightly odd shape, because the graph's answer to bad output is the repair
loop, and a node that dies never reaches it. So a missing key becomes an empty
string, a non-list becomes an empty list, and a `check_id` that is not a
string is dropped. The gates then see the shape they expect and report what is
actually missing, which is a far better failure than a `KeyError` in a Celery
log.
"""

from __future__ import annotations

from typing import Any

# ── response schemas ─────────────────────────────────────────────────────────

_STR = {"type": "STRING"}
_STR_ARRAY = {"type": "ARRAY", "items": {"type": "STRING"}}

# survey: the investigation strategy. Prose only — this node steers the run,
# it does not produce anything that reaches the document.
SURVEY_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "strategy": _STR,
        "focus_areas": _STR_ARRAY,
        "notes": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {"topic": _STR, "note": _STR},
                "required": ["topic", "note"],
            },
        },
    },
    "required": ["strategy"],
}

# correlate: themes that span checks, each anchored to real check_ids.
THEMES_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "themes": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {"title": _STR, "narrative": _STR, "refs": _STR_ARRAY},
                "required": ["title", "narrative", "refs"],
            },
        }
    },
    "required": ["themes"],
}

# plan_remediation: waves. `refs` must partition the ledger — gate C3.
PLAN_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "waves": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {"label": _STR, "rationale": _STR, "refs": _STR_ARRAY},
                "required": ["label", "rationale", "refs"],
            },
        }
    },
    "required": ["waves"],
}

# compose: one pillar's prose. Extends the standard path's PILLAR_RESPONSE_
# SCHEMA with the two fields the deep report adds.
COMPOSE_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "pillar_narrative": _STR,
        "pillar_analysis": _STR,
        "findings": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "check_id": _STR,
                    "explanation": _STR,
                    "why_here": _STR,
                },
                "required": ["check_id", "explanation", "why_here"],
            },
        },
    },
    "required": ["pillar_narrative", "pillar_analysis", "findings"],
}

# reconcile: one verdict per ledger check, against the live evidence. The
# enum is declared rather than described for the reason the critique's is —
# routing and grouping on a verdict has to be a lookup, not an interpretation
# of prose — and `evidence` is what gate C7 checks.
VERDICTS = ("confirms", "contradicts", "moot", "amplifies", "no_evidence")

# The one verdict that legitimately cites nothing, because it *is* the absence
# of evidence. Every other verdict without a citation is a C7 failure.
NO_EVIDENCE = "no_evidence"

# What a check the model said nothing about renders as. Written here rather
# than in the renderer because the coercion fills it in, and a reader must be
# able to tell "we looked and it still holds" from "we never looked" — the
# distinction the whole feature exists to make.
NOT_INVESTIGATED = "This finding was not checked against the project's live state."

RECONCILE_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "verdicts": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "check_id": _STR,
                    "verdict": {"type": "STRING", "enum": list(VERDICTS)},
                    "statement": _STR,
                    "evidence": _STR_ARRAY,
                },
                "required": ["check_id", "verdict", "statement", "evidence"],
            },
        }
    },
    "required": ["verdicts"],
}

SUMMARY_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {"executive_summary": _STR},
    "required": ["executive_summary"],
}

# critique: the judge's verdict. `verdict` is constrained to two values so the
# routing decision is a lookup rather than an interpretation of prose.
CRITIQUE_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "verdict": {"type": "STRING", "enum": ["accept", "revise"]},
        "confidence": {"type": "STRING", "enum": ["high", "medium", "low"]},
        "assessment": _STR,
        "issues": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "severity": {"type": "STRING", "enum": ["blocking", "advisory"]},
                    "target": _STR,
                    "problem": _STR,
                },
                "required": ["severity", "target", "problem"],
            },
        },
    },
    "required": ["verdict", "confidence", "assessment", "issues"],
}


# ── coercion ─────────────────────────────────────────────────────────────────


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _refs(value: Any, known: set[str]) -> list[str]:
    """String check_ids only, de-duplicated, order preserved.

    Filtering to `known` here rather than leaving it to gate C2 is not
    belt-and-braces — it is what makes the *renderer's* arithmetic safe, since
    `_theme_facts` and the plan table index straight into the ledger. C2 still
    runs, and still reports an unknown ref, because a model citing a check
    that is not in this project is worth knowing about even once the ref has
    been dropped.
    """
    if not isinstance(value, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item in known and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def coerce_themes(result: dict[str, Any], known: set[str]) -> list[dict[str, Any]]:
    themes = result.get("themes")
    if not isinstance(themes, list):
        return []
    out = []
    for raw in themes:
        if not isinstance(raw, dict):
            continue
        refs = _refs(raw.get("refs"), known)
        if not refs:
            # A theme citing nothing is not a correlation, it is a sentence.
            # Dropped rather than rendered, since the section's whole claim is
            # that these checks are connected.
            continue
        out.append(
            {
                "title": _text(raw.get("title")) or "Untitled theme",
                "narrative": _text(raw.get("narrative")),
                "refs": refs,
            }
        )
    return out


def coerce_plan(result: dict[str, Any], known: set[str]) -> list[dict[str, Any]]:
    """Waves, with each check kept in the FIRST wave that claims it.

    De-duplicating across waves here means the common model error — listing a
    check in both "do this first" and "then harden" — is corrected rather than
    bounced through a repair round. Gate C3 still catches a check that appears
    in *no* wave, which is the error that actually loses work and which no
    amount of coercion can invent an answer for.
    """
    waves = result.get("waves")
    if not isinstance(waves, list):
        return []
    claimed: set[str] = set()
    out = []
    for raw in waves:
        if not isinstance(raw, dict):
            continue
        refs = [c for c in _refs(raw.get("refs"), known) if c not in claimed]
        claimed.update(refs)
        out.append(
            {
                "label": _text(raw.get("label")) or "Unlabelled wave",
                "rationale": _text(raw.get("rationale")),
                "refs": refs,
            }
        )
    # A wave left empty by de-duplication has nothing to say.
    return [w for w in out if w["refs"]]


def coerce_compose(
    result: dict[str, Any], pillar_checks: set[str]
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """One pillar's output -> (pillar prose, per-check prose).

    `pillar_checks` is the set of checks belonging to *this* pillar, and
    entries outside it are discarded. That filter is what keeps gate C1's
    "analysis for a check that is not in the ledger" branch unreachable in
    practice: a model that answers about a neighbouring pillar's check has its
    answer dropped here, where the pillar is known, rather than surfacing
    later as an unattributable key.
    """
    pillar_prose = {
        "narrative": _text(result.get("pillar_narrative")),
        "analysis": _text(result.get("pillar_analysis")),
    }
    checks: dict[str, dict[str, str]] = {}
    findings = result.get("findings")
    if isinstance(findings, list):
        for raw in findings:
            if not isinstance(raw, dict):
                continue
            check_id = raw.get("check_id")
            if not isinstance(check_id, str) or check_id not in pillar_checks:
                continue
            checks[check_id] = {
                "explanation": _text(raw.get("explanation")),
                "why_here": _text(raw.get("why_here")),
            }
    return pillar_prose, checks


def coerce_reconciliation(
    result: dict[str, Any], known: set[str]
) -> dict[str, dict[str, Any]]:
    """Verdicts keyed by check_id, with every ledger check present.

    **Every check the model omitted is filled in as `no_evidence`.** That is
    the coercion carrying the same weight the renderer's ledger loop does
    elsewhere: a check the model simply forgot must render as "not checked"
    rather than vanishing, because the reader cannot tell a silent gap from a
    finding live state confirmed, and telling those two apart is the entire
    point of this section.

    Citations are **not** filtered against the log, which is the one place
    this differs from `_refs`. An invented `evidence_id` is dropped there
    because the renderer indexes into the ledger with it; here it is only
    printed, so keeping it lets gate C7 name the fabricated id instead of
    reporting the vaguer "this verdict cites nothing".
    """
    verdicts = result.get("verdicts")
    out: dict[str, dict[str, Any]] = {}
    if isinstance(verdicts, list):
        for raw in verdicts:
            if not isinstance(raw, dict):
                continue
            check_id = raw.get("check_id")
            if not isinstance(check_id, str) or check_id not in known:
                continue
            verdict = raw.get("verdict")
            evidence = [
                e.strip()
                for e in (raw.get("evidence") or [])
                if isinstance(e, str) and e.strip()
            ]
            out[check_id] = {
                # An unrecognised verdict is not guessed at. `no_evidence` is
                # the only safe default: it under-claims, and every other
                # value is a claim about the world this entry has not earned.
                "verdict": verdict if verdict in VERDICTS else NO_EVIDENCE,
                "statement": _text(raw.get("statement")),
                "evidence": list(dict.fromkeys(evidence)),
            }
    for check_id in known:
        out.setdefault(
            check_id,
            {"verdict": NO_EVIDENCE, "statement": NOT_INVESTIGATED, "evidence": []},
        )
    return out


def coerce_critique(result: dict[str, Any]) -> dict[str, Any]:
    """Normalise the verdict. Anything unrecognised reads as `accept`.

    Failing open is right here and only here: the critique is advisory by
    design, the deterministic gates have already passed by the time it runs,
    and a malformed verdict must not be able to burn the revision budget on a
    document nothing is actually wrong with.
    """
    verdict = result.get("verdict")
    issues = result.get("issues")
    return {
        "verdict": verdict if verdict in ("accept", "revise") else "accept",
        "confidence": result.get("confidence")
        if result.get("confidence") in ("high", "medium", "low")
        else "low",
        "assessment": _text(result.get("assessment")),
        "issues": [
            {
                "severity": i.get("severity") if i.get("severity") in ("blocking", "advisory")
                else "advisory",
                "target": _text(i.get("target")),
                "problem": _text(i.get("problem")),
            }
            for i in (issues if isinstance(issues, list) else [])
            if isinstance(i, dict)
        ],
    }
