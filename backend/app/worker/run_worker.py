"""Entrypoint for the worker container. Starts **two** Celery worker processes
with disjoint queues and supervises them:

    scans    →  -Q celery   --concurrency=MAX_CONCURRENT_SCANS
    reports  →  -Q reports  --concurrency=MAX_CONCURRENT_REPORTS

Each pool size is the whole queuing mechanism for its own workload: a task
occupies a slot for its entire run, so a submission beyond the budget sits in
Redis until a slot frees up, with no extra application code required. Both
numbers come from `app/config.py` rather than from a flag in
docker-compose.yml, where they would silently drift from the value the loader
actually resolves.

**Why the earlier single-process design was abandoned.** Until this change one
process consumed both queues at `MAX_CONCURRENT_SCANS + 1`, and this docstring
recorded the split below as the known fix, considered and rejected in favour of
keeping one process. Two things were wrong with what it bought:

- *The scan ceiling was a ceiling plus one.* Prefork slots are not queue-affine
  — a child takes whatever is next on any queue it subscribes to, so nothing
  stopped two scan tasks occupying both slots. Locally that meant two Prowler
  containers against a Colima VM sized for one.
- *The +1 stopped being enough.* It was sized for a report that was a handful
  of model calls. A deep report now opens a recon container and spends minutes
  on sequential cloud API calls inside it (see `app/agents/cloud_context.py`),
  so a report occupying a scan-capable slot holds it for a scan's worth of
  time. Locally, where the scan budget is one, a submitted scan could sit
  behind a report for minutes.

Disjoint queues fix both at once: neither workload can occupy the other's
capacity, and `MAX_CONCURRENT_SCANS` is an exact ceiling again. The cost is one
extra Celery parent process in a VM that is already the binding constraint,
so memory use must be measured rather than assumed.

**One container, two processes, and they live and die together.** If either
child exits — for any reason, including an OOM kill — the supervisor stops the
other and exits with that child's status, so the container fails visibly rather
than degrading into a half-worker that accepts reports and silently never runs
a scan. That also keeps orphan reaping unambiguous: a restart is always a
restart of *both*, so `celery_app._reap_cloud_cli_orphans` can safely assume
nothing in this container holds a recon container or a Redis slot when the
reports worker comes up. `WORKER_ROLE` is exported to each child so that hook
knows which of the two it is running in.
"""

import os
import signal
import subprocess
import sys
import time
from typing import Any

SCANS = "scans"
REPORTS = "reports"
ROLES = (SCANS, REPORTS)

ROLE_ENV_VAR = "WORKER_ROLE"

# role -> (queue, the config key holding its concurrency)
_ROLE_QUEUES: dict[str, tuple[str, str]] = {
    SCANS: ("celery", "MAX_CONCURRENT_SCANS"),
    REPORTS: ("reports", "MAX_CONCURRENT_REPORTS"),
}

# How long a child gets to finish after the supervisor asks it to stop, before
# it is killed. Celery's own warm shutdown waits for running tasks, and a scan
# can run for SCAN_TIMEOUT_SECONDS — waiting that long on the way out would
# make `docker compose stop` look hung, so the supervisor asks once, waits a
# grace period, then kills. Docker's own SIGKILL deadline is 10s by default,
# so this stays under it.
SHUTDOWN_GRACE_SECONDS = 8.0

# The supervisor has nothing to do between child exits; this is only how
# quickly it notices one.
POLL_INTERVAL_SECONDS = 0.5


def celery_argv(role: str, settings: Any) -> list[str]:
    """The argv for one role's Celery worker.

    Pure, so the queue/concurrency contract can be asserted without starting
    Celery — which is the only way to test that the scan worker does not
    subscribe to the reports queue.
    """
    try:
        queue, concurrency_key = _ROLE_QUEUES[role]
    except KeyError:
        raise ValueError(f"unknown worker role: {role!r}") from None
    # A configured 0 would mean "consume this queue but never run anything",
    # which is indistinguishable at runtime from the worker being wedged.
    concurrency = max(1, int(settings[concurrency_key]))
    return [
        "celery", "-A", "app.worker.celery_app", "worker",
        "--loglevel=info",
        f"--concurrency={concurrency}",
        "--pool=prefork",
        "-Q", queue,
        # Distinct node names: two workers sharing one would collide in the
        # control bus and in Flower, and `celery inspect` could no longer tell
        # you which of the two is busy.
        "-n", f"{role}@%h",
    ]


def child_env(role: str, environ: dict[str, str] | None = None) -> dict[str, str]:
    """The environment one child runs with — the parent's, plus its role."""
    base = dict(os.environ if environ is None else environ)
    base[ROLE_ENV_VAR] = role
    return base


def stop_children(children: dict[str, Any], *, grace: float = SHUTDOWN_GRACE_SECONDS) -> None:
    """Ask every still-running child to stop, then kill whatever is left.

    Never raises: this runs on the way out, and a child that has already exited
    (or whose pid was reaped by something else) must not turn a clean shutdown
    into a traceback.
    """
    for child in children.values():
        if child.poll() is None:
            try:
                child.terminate()
            except OSError:
                pass
    deadline = time.monotonic() + grace
    for child in children.values():
        remaining = max(0.0, deadline - time.monotonic())
        try:
            child.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            try:
                child.kill()
            except OSError:
                pass
        except OSError:
            pass


def supervise(children: dict[str, Any], *, poll: float = POLL_INTERVAL_SECONDS) -> int:
    """Block until one child exits, stop the rest, return that child's status.

    Returns the *first* exit status seen rather than the worst, because the
    first is the one that says why the container is going down; the others are
    consequences of the shutdown this function performs.
    """
    while True:
        for role, child in children.items():
            status = child.poll()
            if status is not None:
                print(
                    f"[run_worker] {role} worker exited with {status}; "
                    "stopping the other worker",
                    file=sys.stderr,
                    flush=True,
                )
                stop_children(children)
                return status if status >= 0 else 128 - status
        time.sleep(poll)


def main() -> int:
    from app.config import get_settings

    settings = get_settings()
    children: dict[str, subprocess.Popen] = {}
    for role in ROLES:
        argv = celery_argv(role, settings)
        print(f"[run_worker] starting {role}: {' '.join(argv)}", file=sys.stderr, flush=True)
        children[role] = subprocess.Popen(argv, env=child_env(role))

    def _forward(signum: int, _frame: Any) -> None:
        # Celery's own SIGTERM handling is the warm shutdown we want, so the
        # signal is passed through rather than translated. The supervisor keeps
        # polling afterwards and exits through the normal path once a child
        # does.
        for child in children.values():
            if child.poll() is None:
                try:
                    child.send_signal(signum)
                except OSError:
                    pass

    signal.signal(signal.SIGTERM, _forward)
    signal.signal(signal.SIGINT, _forward)

    return supervise(children)


if __name__ == "__main__":
    raise SystemExit(main())
