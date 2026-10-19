"""The report agent's door onto live cloud state.

Ties four things together that are deliberately separate underneath: the guard
chain (`cloud_cli_guards`, pure policy), the sandboxed container
(`cloud_cli_runner`, pure mechanism), a run-scoped Redis cache, and the
Langfuse trace. Nothing here decides what may run and nothing here starts a
container — this is the layer that knows about *one report run*.

**Why a registry keyed on the graph thread rather than a value in state.**
A `CloudContext` owns a live container and a Redis connection, so it is not
JSON-serialisable and cannot live in `ReportGraphState` — LangGraph checkpoints
that state to Postgres after every node. It also cannot be passed as an
argument, because a node's signature is `(state) -> update`. So the task opens
one, registers it under the run's thread id, and the nodes look it up. A node
that finds nothing registered degrades to "live context unavailable", which is
exactly the behaviour wanted in tests, with the kill switch off, and on a
resumed run in a process that never opened one.

**The cache is run-scoped, not global, and that is a correctness property.**
Live state changes. A global cache would let `repair` re-read a command and get
different bytes from the ones the paragraph it is repairing was written from —
a report contradicting itself with no diff to explain it. Keyed on the thread
id, every read inside one run sees one consistent snapshot, and a resumed run
re-reads from Redis instead of GCP.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import time
from collections.abc import Iterator
from typing import Any

import redis

from app import observability
from app.integrations import cloud_cli_guards as guards
from app.integrations.cloud_cli_runner import (
    BudgetExhausted,
    CloudCliLaunchError,
    CloudCliSession,
)

logger = logging.getLogger(__name__)

# A little longer than a run's own wall clock, so a resumed run still finds its
# snapshot but a cache key cannot outlive the report it belongs to.
CACHE_TTL_SECONDS = guards.MAX_CLI_WALL_CLOCK_SECONDS * 4

# The semaphore's TTL is the crash net: a worker SIGKILLed mid-run releases
# nothing, so without an expiry one dead run would hold a slot forever. Sized
# well above the command wall-clock limit so a slow-but-alive run is never evicted while
# still holding its container.
SLOT_TTL_SECONDS = guards.MAX_CLI_WALL_CLOCK_SECONDS * 3

_CONTEXTS: dict[str, "CloudContext"] = {}


def register(thread_id: str, context: "CloudContext") -> None:
    _CONTEXTS[str(thread_id)] = context


def unregister(thread_id: str) -> None:
    _CONTEXTS.pop(str(thread_id), None)


def context_for(thread_id: str | None) -> "CloudContext | None":
    return _CONTEXTS.get(str(thread_id)) if thread_id else None


# ── the Redis slot ───────────────────────────────────────────────────────────


class NoSlotAvailable(RuntimeError):
    """Every recon container slot is held by another run.

    A separate type from `CloudCliLaunchError` because the cause and the cure
    differ: a launch failure is broken configuration, this is contention, and a
    report that hits it should say "live context unavailable: all slots busy"
    rather than implying the feature is misconfigured.
    """


def acquire_slot(redis_client, *, thread_id: str, limit: int) -> str | None:
    """`SET NX EX` across `limit` numbered keys; returns the key it won.

    Numbered keys rather than a counter, because a counter that is incremented
    and then never decremented (a killed worker) drifts upward permanently and
    has no per-holder TTL to recover from. One key per slot means each slot
    expires on its own.
    """
    for n in range(limit):
        key = f"cli:slot:{n}"
        if redis_client.set(key, thread_id, nx=True, ex=SLOT_TTL_SECONDS):
            return key
    return None


def release_slot(redis_client, key: str | None, *, thread_id: str) -> None:
    """Release only if we still hold it.

    The check matters: if this run's slot already expired and another run took
    it, a blind `DELETE` would free somebody else's container slot while their
    container is still running, and the cap would silently stop being a cap.
    """
    if not key:
        return
    try:
        if redis_client.get(key) == thread_id:
            redis_client.delete(key)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not release cli slot %s: %s", key, exc)


def reap_orphaned_slots(redis_client) -> list[str]:
    """Delete every container slot key. Returns the keys it removed.

    `open_cloud_context` releases its slot in a `finally`, so the only way a
    slot survives its run is a worker that was killed while holding it — and
    then it stays held for `SLOT_TTL_SECONDS`, which is thirty minutes. Locally,
    where `MAX_CONCURRENT_CLI_SESSIONS` is 1, that is thirty minutes in which
    every deep report renders the "live context unavailable" banner because the
    only slot belongs to a process that no longer exists. Reaping the container
    without reaping its slot fixes the visible half of that and leaves the half
    that actually blocks the next report.

    Safe only at report-worker startup, and for the same reason the container
    reaper is safe there: that is the one moment at which no run in this process
    can hold a slot, and `run_worker.py` stops both worker processes together,
    so a restart is never partial. A slot still held at that moment therefore
    belongs to nobody.
    """
    keys = sorted(str(k) for k in redis_client.scan_iter(match="cli:slot:*"))
    if keys:
        redis_client.delete(*keys)
    return keys


# ── the per-run context ──────────────────────────────────────────────────────


class CloudContext:
    """One report run's access to live state.

    Not a context manager itself — `open_cloud_context` is. Keeping the
    acquire/release dance in one function means the container, the Redis slot
    and the registry entry cannot be released in the wrong order or half
    released, which is the failure a hand-rolled `try/finally` at each call site
    would eventually produce.
    """

    def __init__(
        self,
        *,
        session: CloudCliSession,
        redis_client,
        thread_id: str,
        project_id: str,
        target_sa_email: str,
    ) -> None:
        self.session = session
        self.redis = redis_client
        self.thread_id = str(thread_id)
        self.project_id = project_id
        self.target_sa_email = target_sa_email
        # Set by `recon` once the `project` playbook step has returned its
        # `parent`, and only if that parent is an organization the probe says
        # is readable. Stays None otherwise, which is what makes an org-scoped
        # run a no-op rather than a command against the wrong scope.
        self.organization_id: str | None = None
        # The evidence record. Every attempt lands here — successes, refusals
        # and failures alike — because a report that quietly omits the command
        # that failed is exactly the report this feature exists to prevent.
        self.log: list[dict[str, Any]] = []

    # ── cache ────────────────────────────────────────────────────────────────

    def _cache_key(self, binary: str, args: list[str]) -> str:
        digest = hashlib.sha256(
            json.dumps([binary, args], separators=(",", ":")).encode()
        ).hexdigest()
        return f"cli:{self.thread_id}:{digest}"

    def _cached(self, key: str) -> dict | None:
        try:
            raw = self.redis.get(key)
        except Exception as exc:  # noqa: BLE001
            # A cache that is down costs money and time, never correctness.
            logger.warning("cli cache read failed: %s", exc)
            return None
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def _store(self, key: str, payload: dict) -> None:
        try:
            self.redis.set(key, json.dumps(payload, default=str), ex=CACHE_TTL_SECONDS)
        except Exception as exc:  # noqa: BLE001
            logger.warning("cli cache write failed: %s", exc)

    # ── the one entry point ──────────────────────────────────────────────────

    def run(
        self,
        *,
        binary: str,
        args: list[str],
        why: str,
        pillar: str | None = None,
        org_scoped: bool = False,
    ) -> dict[str, Any]:
        """Guard, then cache, then execute. Returns the model's view.

        A rejection, a cache hit, a permission error and a timeout are all
        **returns**, never raises — the model reads the reason and corrects
        itself, which is the whole design of the failure-communication rule.
        The single exception is `BudgetExhausted`, and even that is caught here
        and turned into a message telling the model to finish with what it has.

        **`org_scoped` is not reachable from a model.** `dispatch_readonly`
        never sets it; only an org-scoped playbook step does, and the id it
        swaps in comes from `self.organization_id`, which was read out of the
        validated project's `parent`. The scanner service account can see other
        customers' organizations, so the id a command runs against
        must never be something a caller chose.
        """
        args = [str(a) for a in (args or [])]
        why = str(why or "").strip()

        try:
            checked = guards.check_command(
                binary,
                args,
                project_id=self.project_id,
                target_sa_email=self.target_sa_email,
                organization_id=self.organization_id if org_scoped else None,
            )
        except guards.GuardRejection as exc:
            payload = guards.rejection_payload(exc, binary=binary, args=args)
            payload["why"] = why
            self._record(payload, kind="rejected")
            with observability.observation(
                f"cloud · rejected · {exc.rejected_by}",
                as_type="tool",
                input={"binary": binary, "args": args, "why": why},
            ) as span:
                span.update(level="WARNING", status_message=exc.reason, output=payload)
            return payload

        key = self._cache_key(binary, args)
        hit = self._cached(key)
        if hit is not None:
            # Charged to neither budget: a cache hit made no API call and took
            # no container time, and charging for it would make a resumed run
            # cost more than the run it resumed.
            hit = dict(hit, cached=True, why=why)
            self._record(hit, kind="cache_hit")
            with observability.observation(
                f"cloud · {checked.display}", as_type="tool", input={"why": why}
            ) as span:
                span.update(output=hit, metadata={"cache": "hit"})
            return hit

        with observability.observation(
            f"cloud · {checked.display}",
            as_type="tool",
            input={"binary": binary, "args": args, "why": why, "pillar": pillar},
        ) as span:
            try:
                result = self.session.run(
                    checked.argv, display=checked.display, pillar=pillar
                )
            except BudgetExhausted as exc:
                payload = {
                    "ok": False,
                    "budget_exhausted": True,
                    "reason": str(exc),
                    "command": checked.display,
                    "why": why,
                }
                self._record(payload, kind="budget")
                span.update(level="WARNING", status_message=str(exc), output=payload)
                return payload

            payload = {
                "ok": result.ok,
                "command": checked.display,
                "why": why,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                # Verbatim. A permission error is the most informative thing
                # this feature can learn, and flattening it into "failed" is
                # what makes a report's silence unreadable.
                "stderr": result.stderr,
                "truncated": result.truncated,
                "duration_ms": result.duration_ms,
                "cached": False,
            }
            # Only successes are cached. Caching a failure would make a
            # transient 503 stick for the rest of the run, and the run is
            # exactly the window in which a retry might work.
            if result.ok:
                self._store(key, payload)
            self._record(payload, kind="ran")
            span.update(
                output=payload,
                level=None if result.ok else "WARNING",
                metadata={
                    "cache": "miss",
                    "exit_code": result.exit_code,
                    "truncated": result.truncated,
                    "commands_run": self.session.commands_run,
                },
            )
            return payload

    # ── the evidence record ──────────────────────────────────────────────────

    def _record(self, payload: dict, *, kind: str) -> None:
        """Append to the command log and stamp an `evidence_id`.

        The id is positional (`E1`, `E2`, …) rather than a hash, because it is
        cited in prose a model writes and then checked by a gate: a short,
        obviously-sequential token is one a model reproduces reliably, and a
        64-character digest is one it will silently truncate.
        """
        entry = dict(payload)
        entry["evidence_id"] = f"E{len(self.log) + 1}"
        entry["kind"] = kind
        entry["at"] = time.time()
        self.log.append(entry)
        payload["evidence_id"] = entry["evidence_id"]


# ── lifecycle ────────────────────────────────────────────────────────────────


class Unavailable(RuntimeError):
    """Live context could not be opened. Carries the reason the banner names."""


@contextlib.contextmanager
def open_cloud_context(
    *,
    settings,
    thread_id: str,
    project_id: str,
    target_sa_email: str,
    redis_client=None,
) -> Iterator["CloudContext | None"]:
    """Acquire a slot, start the container, register the context — or yield None.

    **Yields `None` rather than raising when live context cannot be had.** Deep
    mode shipped and was correct before any of this existed, so failing a
    customer-facing document because the kill switch is off, or every slot is
    busy, or the daemon is unreachable, would be a regression against a pipeline
    that works. The caller reads `unavailable_reason` off the exception-free
    path and renders the banner. It is degraded, never silent.

    Release order is the reverse of acquisition and every step is
    unconditional: unregister so no node can reach a dead container, tear the
    container down, then release the slot last — releasing the slot first would
    let another run start a container while ours is still shutting down, which
    is precisely the moment the cap is supposed to hold.
    """
    reason = _unavailable_reason(settings)
    if reason:
        logger.warning("live context unavailable: %s", reason)
        yield None
        return

    if redis_client is None:
        redis_client = redis.from_url(settings.redis_url, decode_responses=True)

    limit = max(1, int(settings["MAX_CONCURRENT_CLI_SESSIONS"]))
    slot: str | None = None
    session: CloudCliSession | None = None
    try:
        try:
            slot = acquire_slot(redis_client, thread_id=str(thread_id), limit=limit)
        except Exception as exc:  # noqa: BLE001
            raise Unavailable(f"could not reach Redis to reserve a slot: {exc}") from exc
        if slot is None:
            raise NoSlotAvailable(
                f"all {limit} recon container slot(s) are in use by other reports"
            )

        try:
            token = access_token_for(target_sa_email)
        except Exception as exc:  # noqa: BLE001
            # Impersonation failing is a real, nameable condition — the worker's
            # own credential lacking `serviceAccountTokenCreator` on the
            # scanner SA is the likeliest cause — and it must reach the reader
            # as a reason rather than as an empty section.
            raise Unavailable(
                f"could not obtain a token for {target_sa_email}: {exc}"
            ) from exc

        try:
            session = CloudCliSession(
                image=settings["CLOUD_CLI_IMAGE"],
                docker_host=settings["DOCKER_HOST"],
                access_token=token,
                run_id=_container_suffix(thread_id),
            ).__enter__()
        except CloudCliLaunchError as exc:
            raise Unavailable(f"the recon container could not start: {exc}") from exc

        context = CloudContext(
            session=session,
            redis_client=redis_client,
            thread_id=str(thread_id),
            project_id=project_id,
            target_sa_email=target_sa_email,
        )
        register(thread_id, context)
        logger.info(
            "live context open thread=%s project=%s slot=%s", thread_id, project_id, slot
        )
        try:
            yield context
        finally:
            unregister(thread_id)
            session.close()
            session = None
    except (Unavailable, NoSlotAvailable) as exc:
        logger.warning("live context unavailable: %s", exc)
        yield None
    finally:
        if session is not None:
            session.close()
        release_slot(redis_client, slot, thread_id=str(thread_id))


def access_token_for(target_sa_email: str) -> str:
    """A short-lived access token for the project's scanner service account.

    The same `impersonated_credentials` path `integrations/gemini.py::
    _credentials` uses for Vertex, and for the same reason: the base credential
    stays ADC (a developer login locally, the metadata server on a GCE host) and no
    key file exists anywhere. Minted **in the worker** so the container never
    holds anything refreshable — see `build_container_command` for why gcloud
    cannot use a mounted ADC file the way the scanner does.

    `cloud-platform` rather than a narrower scope: the token's ceiling is the
    scanner service account's own IAM, which is read-only on the projects it
    scans, and a narrower scope would silently drop whichever read the playbook
    needed next without saying which.
    """
    import google.auth
    from google.auth import impersonated_credentials
    from google.auth.transport.requests import Request as AuthRequest

    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    source, _ = google.auth.default(scopes=scopes)
    creds = impersonated_credentials.Credentials(
        source_credentials=source,
        target_principal=target_sa_email,
        target_scopes=scopes,
        lifetime=3600,
    )
    creds.refresh(AuthRequest())
    return creds.token


def _unavailable_reason(settings) -> str | None:
    """The reasons that are known before anything is acquired.

    Checked up front so the common "switched off" case costs no Redis round
    trip and produces the same banner shape as a launch failure does.
    """
    if str(settings["CLOUD_CLI_ENABLED"]).strip().lower() not in ("1", "true", "yes"):
        return "live cloud context is switched off for this deployment (CLOUD_CLI_ENABLED)"
    if not str(settings["CLOUD_CLI_IMAGE"]).strip():
        return "no cloud CLI image is configured"
    return None


def _container_suffix(thread_id: str) -> str:
    """A container name is a Docker identifier, and a thread id is not.

    `RPT-b24a9d` is fine; a future thread id with a character Docker refuses
    would fail the launch rather than the naming, which reads as a broken image
    rather than a broken name. Hashed rather than sanitised so the mapping stays
    injective — two thread ids must never collide on one container name.
    """
    safe = "".join(c for c in str(thread_id) if c.isalnum() or c in "-_")
    return (safe or "run")[:24] + "-" + hashlib.sha256(str(thread_id).encode()).hexdigest()[:8]
