"""Fence/snippet normalization shared by every report renderer.

Split out of `report_render.py` so the PDF renderer (`report_pdf.py`) can
reuse the exact same fence-handling instead of re-deriving it — the
double-fencing defect this logic exists to prevent (see `strip_outer_fence`'s
docstring) must not be able to recur independently in a second output format.
"""

from __future__ import annotations

import re

FENCE_RE = re.compile(r"^\s*(?:```|~~~)")


def strip_outer_fence(body: str) -> str | None:
    """If `body` is exactly one fenced block, return its contents; else None.

    Prowler is inconsistent about fencing and the inconsistency is invisible
    until rendered: in scan 12 all 295 Terraform snippets arrived pre-fenced
    and all 328 CLI snippets bare. Rather than trusting either shape, the
    fence is normalised — stripped if present, then re-added exactly once —
    so the output is identical whichever way the scanner supplies it, and a
    future Prowler that flips the convention needs no change here.
    """
    lines = body.splitlines()
    if len(lines) < 2 or not FENCE_RE.match(lines[0]):
        return None
    closing = None
    for i in range(len(lines) - 1, 0, -1):
        if FENCE_RE.match(lines[i]):
            closing = i
            break
    if closing is None or closing == 0:
        return None
    inner = "\n".join(lines[1:closing]).strip("\n")
    # A second opening fence inside means this is several blocks, not one
    # wrapper — leave that alone rather than mangling it.
    if FENCE_RE.search("\n".join(lines[1:closing]) or "") and any(
        FENCE_RE.match(line) for line in lines[1:closing]
    ):
        return None
    return inner or None
