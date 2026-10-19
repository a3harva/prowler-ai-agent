"""Root logger configuration, so the app's own log lines reach the container.

**The gap this closes is the API process, not the worker.** Without it:

| Process | App `logger.info` in `docker compose logs`? |
|---|---|
| `worker` | **yes** — `gemini_agent call model=… latency_ms=… cached=…` is there |
| `api` | **no** — uvicorn's own eleven startup lines and nothing else |

Celery hijacks the root logger at worker start (`worker_hijack_root_logger`,
on by default) and sets its level from `--loglevel`, so every app logger
propagates into Celery's handler for free. Uvicorn does no such thing: its
logging config touches only `uvicorn`, `uvicorn.error` and `uvicorn.access`,
and leaves the root logger exactly as Python ships it — no handlers, level
WARNING. An app `logger.info` in the API process is therefore discarded
outright, and a `logger.warning` escapes only through `logging.lastResort`,
unformatted and with no timestamp or logger name.

That is not an even split of the pain. **The chat agent answers a turn in the
API process** — the tool loop is synchronous and a person is waiting, see
`docker-compose.local.yml` — so `gemini_agent`'s per-call model, latency and
token lines, the ones that diagnose a slow or failed chat turn, are exactly the
ones being dropped.

**The worker is deliberately left alone.** Configuring root here at import time
would install a handler that Celery then replaces during its own startup — at
best redundant, at worst duplicated lines if that behaviour ever changes. It
already works; the fix belongs only where the hole is.

**No new `CONFIG_KEYS` entry.** `config.py` fails startup when any key in that
list is missing, so adding one breaks every existing `.env.local` — the same
reason `MAX_INVESTIGATION_ROUNDS` and `THINKING_LEVEL` are module constants.
`LOG_LEVEL` is read straight from the process environment instead, where an
absent value simply means the default.
"""

from __future__ import annotations

import logging
import os
import sys

DEFAULT_LEVEL = "INFO"

# Read from the process environment, never through `app.config` — see the
# module docstring. Absent means DEFAULT_LEVEL, so nothing breaks by omission.
LEVEL_ENV_VAR = "LOG_LEVEL"

FORMAT = "[%(asctime)s: %(levelname)s/%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Libraries that are informative at WARNING and a flood at INFO. Root going to
# INFO turns INFO on for *everything*, so without this the one line worth
# reading arrives buried in per-request httpx and google.auth chatter — which
# is its own way of not reaching the reader.
#
# `sqlalchemy.engine` is the loudest of them by far: at INFO it prints every
# statement and every parameter set, so a single findings page becomes hundreds
# of lines. It is also the one most worth turning back on by hand when you are
# actually debugging a query.
NOISY_LOGGERS = (
    "httpx",
    "httpcore",
    "urllib3",
    "google.auth",
    "google_genai",
    "sqlalchemy.engine",
    "opentelemetry",
)

# Marks the handler as ours, so a second call recognises its own work. Uvicorn
# `--reload` re-imports the application module on every change, which is enough
# to stack a duplicate handler per edit and print every line twice, then three
# times, then four.
_MARKER = "_prowler_root_handler"


def _resolve_level(level: str | int | None) -> int:
    if level is None:
        level = os.environ.get(LEVEL_ENV_VAR) or DEFAULT_LEVEL
    if isinstance(level, int):
        return level
    resolved = logging.getLevelName(str(level).strip().upper())
    # getLevelName returns the string "Level X" for anything it does not know,
    # and a bad LOG_LEVEL must not be the reason the API starts logging nothing.
    return resolved if isinstance(resolved, int) else logging.INFO


def configure_logging(level: str | int | None = None) -> logging.Logger:
    """Attach one stderr handler to the root logger, at `level`.

    Idempotent, and safe to call from a process whose logging somebody else
    owns: **if the root logger already has handlers, none is added.** That is
    what makes the function harmless under Celery (whose handler is already
    there and is the one that should win) while still doing its job under
    uvicorn (where there is nothing). The noisy-logger levels are applied
    either way, since they are true regardless of who owns the handler.
    """
    root = logging.getLogger()
    resolved = _resolve_level(level)

    ours = [h for h in root.handlers if getattr(h, _MARKER, False)]
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(FORMAT, datefmt=DATE_FORMAT))
        setattr(handler, _MARKER, True)
        root.addHandler(handler)
        root.setLevel(resolved)
    elif ours:
        # Our own handler from a previous call — re-level it rather than
        # stacking a second one.
        for handler in ours:
            handler.setLevel(logging.NOTSET)
        root.setLevel(resolved)

    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(max(resolved, logging.WARNING))

    return root
