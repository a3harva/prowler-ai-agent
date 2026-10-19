"""Skill documents the report agent is given, loaded from Markdown files.

**Files rather than Python string literals, deliberately.** A skill is prose
that a reviewer can read and diff without inspecting application code.

Read **once at import**, not per call. The text is embedded in the model's
system prefix, and the whole point of that prefix is that it is byte-identical
on every request so the provider's cache can hold it; re-reading the file per
call cannot change the bytes but does put a filesystem read on the hot path of
every model round.

`COPY . .` in the Dockerfile carries these into the image with everything else,
so no packaging entry is needed — `test_skills.py` asserts the file is
readable from an installed layout rather than trusting that.
"""

from __future__ import annotations

import functools
import pathlib

SKILLS_DIR = pathlib.Path(__file__).parent


@functools.lru_cache(maxsize=None)
def load(name: str) -> str:
    """The named skill's text, cached for the life of the process.

    Raises rather than returning a placeholder when the file is missing. A
    silently-empty skill is the worst outcome available: the agent still runs,
    still calls the tool, and burns its budget rediscovering the rules the file
    was supposed to have told it — with nothing in the trace to say why.
    """
    path = SKILLS_DIR / f"{name}.md"
    return path.read_text(encoding="utf-8").strip()


GCLOUD = load("gcloud")
