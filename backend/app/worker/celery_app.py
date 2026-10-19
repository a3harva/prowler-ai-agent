import logging
import os

from celery import Celery
from celery.signals import worker_ready

from app.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

celery_app = Celery(
    "prowler_agent",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

# Reports get their own queue so their latency does not depend on scan traffic,
# and their own worker *process* so their capacity does not
# either. Routing alone was never sufficient: a prefork slot is held for the
# whole of a task, so one process consuming both queues lets a deep report —
# which now holds its slot for a recon container's lifetime — occupy a
# scan-capable slot for minutes. `app/worker/run_worker.py` starts one worker
# per queue; this mapping is what puts each task on the right one.
celery_app.conf.task_routes = {
    "reports.*": {"queue": "reports"},
    "scans.*": {"queue": "celery"},
}


@worker_ready.connect
def _reap_cloud_cli_orphans(**_kwargs) -> None:
    """Reclaim recon containers and slots left behind by a worker that was killed.

    A recon container is torn down by its own session's `__exit__`, so the only
    way one survives is a worker that never got to run it — a SIGKILL, an OOM,
    a `docker compose rm -f`. The container's `sleep` ceiling makes it exit on
    its own, but an *exited* container still holds its name, so a worker killed
    repeatedly would eventually collide on one.

    The container's Redis slot is reclaimed too, and that is the half that
    actually unblocks the next report: an orphaned container is invisible, but
    the slot it never released holds `MAX_CONCURRENT_CLI_SESSIONS` down by one
    for thirty minutes, which locally means every deep report in that window
    loses live context.

    Bound to `worker_ready` rather than to a periodic task because the only
    thing that creates orphans is a worker dying, and the only moment one can
    be reaped safely is before any new session opens: at steady state a running
    container belongs to a live run, and reaping on a timer would kill it.

    **Skipped in the scan worker.** Since the worker split there are two
    processes, and only the reports one ever opens a recon container. Reaping
    from the scan worker would be a live process destroying another live
    process's container — exactly the hazard the `worker_ready` binding exists
    to avoid — and it happens to be the case whenever the scan worker restarts
    for its own reasons. The test is for the scan role specifically rather than
    for the reports role, so a worker started by hand with no `WORKER_ROLE`
    (one process, both queues, the pre-split shape) still reaps.

    Never raises, and each half is guarded on its own so that a Docker daemon
    that is unreachable does not also cost the slot reclamation, which needs
    only Redis. A worker that cannot reach either must still start and serve
    reports; scans will fail on their own with a message that names the real
    problem.
    """
    from app.worker.run_worker import ROLE_ENV_VAR, SCANS

    if os.environ.get(ROLE_ENV_VAR) == SCANS:
        return

    try:
        settings = get_settings()
        if settings["CLOUD_CLI_ENABLED"].strip().lower() not in ("1", "true", "yes"):
            return
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not read settings to reap recon orphans: %s", exc)
        return

    try:
        from app.integrations.cloud_cli_runner import reap_orphaned_containers

        removed = reap_orphaned_containers(docker_host=settings["DOCKER_HOST"])
        if removed:
            logger.warning("reaped %d orphaned recon container(s): %s", len(removed), removed)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not reap orphaned recon containers: %s", exc)

    try:
        import redis

        from app.agents.cloud_context import reap_orphaned_slots

        client = redis.from_url(settings.redis_url, decode_responses=True)
        freed = reap_orphaned_slots(client)
        if freed:
            logger.warning("released %d orphaned recon slot(s): %s", len(freed), freed)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not release orphaned recon slots: %s", exc)


# Registers @celery_app.task-decorated functions. Imported at the bottom,
# after celery_app exists, so app.worker.tasks (which imports celery_app back)
# doesn't hit a partially-initialized module.
from app.worker import tasks  # noqa: E402,F401
