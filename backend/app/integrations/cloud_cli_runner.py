"""Executes guarded read-only cloud commands in a locked-down sibling container.

The same sibling-container shape as `prowler_runner`, and for the same reason: a
worker restart must not take a long-running investigation's tooling down with
it, and the worker image must not grow a 340 MB SDK it uses on one code path.

**One container serves a whole run, not one per command.** A report's
investigation issues tens of commands; paying container start-up per command
would dominate the run, and `gcloud`'s credential handshake would be repeated
every time. The session is a context manager so the container is torn down on
the failure path as well as the success one.

**Nothing here decides what may run.** Every argv reaching `run` has already
passed the chain in `cloud_cli_guards`, project and identity included — this
module's job is the sandbox and the budgets, not the policy.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import subprocess
import time
import uuid

from app.integrations.cloud_cli_guards import (
    CLI_COMMAND_TIMEOUT_SECONDS,
    MAX_CLI_COMMANDS_PER_PILLAR,
    MAX_CLI_COMMANDS_PER_RUN,
    MAX_CLI_OUTPUT_BYTES,
    MAX_CLI_WALL_CLOCK_SECONDS,
)

logger = logging.getLogger(__name__)

CONTAINER_NAME_PREFIX = "cloud-cli-"

# The sandbox, as one list so a test can assert on it rather than on a string.
# Every entry is a separate boundary: an immutable rootfs, no capabilities, no
# privilege escalation, and caps on memory, CPU and process count so a runaway
# command cannot starve a concurrent Prowler scan on the same 8 GiB host.
SANDBOX_FLAGS = [
    "--read-only",
    "--tmpfs", "/tmp",
    # gcloud writes its configuration and credential cache here; with a
    # read-only rootfs it has nowhere else to go, and CLOUDSDK_CONFIG below
    # points it at this tmpfs rather than at the image's root-owned default.
    "--tmpfs", "/config",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    # A non-root uid that owns nothing in the image. Both writable paths are
    # tmpfs, so no ownership in the image has to accommodate it.
    "--user", "1000:1000",
    "--memory=512m",
    "--cpus=1",
    "--pids-limit=64",
]


class CloudCliLaunchError(RuntimeError):
    """The container could not be started — before any command ran."""


class BudgetExhausted(RuntimeError):
    """A bound in `cloud_cli_guards` was reached. Never a crash: the caller
    turns this into a message telling the model to finish with what it has."""


@dataclasses.dataclass
class CommandResult:
    ok: bool
    exit_code: int | None
    stdout: str
    stderr: str
    truncated: bool
    duration_ms: int
    command: str


def _docker_env(*, docker_host: str) -> dict[str, str]:
    env = os.environ.copy()
    env["DOCKER_HOST"] = docker_host
    return env


def build_container_command(
    *, container_name: str, image: str, access_token: str
) -> list[str]:
    """Pure and side-effect free, so the sandbox can be proven without a daemon.

    **No `-v /var/run/docker.sock`, ever.** Mounting the socket is effectively
    host root, and this container runs argv the model composed. The scanner
    needs no socket either; nothing in this product does except the worker.

    **No credential is mounted at all, and this is where the design departs
    from `prowler_runner` deliberately.** The scanner mounts an ADC file and
    points `GOOGLE_APPLICATION_CREDENTIALS` at it, which works because Prowler
    is a Python program using Google's client libraries — and that variable is
    a *client library* convention. `gcloud` is not a client library: with only
    that variable set it refuses every command with

        ERROR: You do not currently have an active account selected.

    which reads as a permissions problem and is not one. Verified against a real
    project before the token route was written.

    So the impersonation happens in the **worker**, using the same
    `impersonated_credentials` path `integrations/gemini.py` already uses, and
    the container is handed the resulting short-lived access token in
    `CLOUDSDK_AUTH_ACCESS_TOKEN`. That is strictly less privilege than mounting
    a credential: the token is the scanner service account's, expires in an
    hour, cannot be refreshed, and cannot be exchanged for any other identity.
    The container has no way to obtain a different one, which is the same
    boundary `--impersonate-service-account` was providing and a narrower one.

    A consequence worth stating: **`--impersonate-service-account` is no longer
    injected** for `gcloud`. Passing it on top of a token that already *is* the
    target service account asks that account to impersonate itself, which needs
    `roles/iam.serviceAccountTokenCreator` on itself and fails. G3 still refuses
    the caller from supplying one, so the identity remains unnameable.
    """
    cmd = ["docker", "run", "-d", "--name", container_name, *SANDBOX_FLAGS]

    cmd += [
        # gcloud reads this in place of a credentialed account. It is a bearer
        # token in an environment variable, which is why it is minted per run
        # with a bounded lifetime rather than being a mounted key file.
        "-e", f"CLOUDSDK_AUTH_ACCESS_TOKEN={access_token}",
        "-e", "CLOUDSDK_CONFIG=/config",
        "-e", "CLOUDSDK_CORE_DISABLE_PROMPTS=1",
        image,
        # The container has no work of its own; it exists to be `docker exec`ed
        # into. `sleep` with an explicit ceiling rather than `tail -f /dev/null`
        # so a container orphaned by a killed worker dies on its own even if
        # nothing ever reaps it.
        "sleep", str(MAX_CLI_WALL_CLOCK_SECONDS + 120),
    ]
    return cmd


def build_exec_command(*, container_name: str, argv: list[str]) -> list[str]:
    """`docker exec` argv. The command's own tokens stay separate elements —
    there is no shell inside the container either."""
    return ["docker", "exec", container_name, *argv]


class CloudCliSession:
    """One container, one report run, with the run's budgets attached.

    The budgets live on the session rather than on the runner because they are
    per-run quantities: "40 commands" is a statement about one report, and a
    module-level counter would leak between concurrent reports in the same
    worker process.
    """

    def __init__(
        self,
        *,
        image: str,
        docker_host: str,
        access_token: str = "",
        run_id: str | None = None,
    ) -> None:
        self.image = image
        self.docker_host = docker_host
        self.access_token = access_token
        self.container_name = CONTAINER_NAME_PREFIX + (run_id or uuid.uuid4().hex[:12])
        self.container_id: str | None = None
        self.commands_run = 0
        # Per-pillar as well as per-run, because the run bound alone does not
        # stop the first pillar spending the whole budget and leaving the other
        # four to reason with nothing. The caller names the pillar; an unnamed
        # command counts only against the run.
        self.commands_by_pillar: dict[str, int] = {}
        self.started_at = 0.0

    # ── lifecycle ────────────────────────────────────────────────────────────

    def __enter__(self) -> "CloudCliSession":
        env = _docker_env(docker_host=self.docker_host)
        cmd = build_container_command(
            container_name=self.container_name,
            image=self.image,
            access_token=self.access_token,
        )
        launch = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
        if launch.returncode != 0:
            raise CloudCliLaunchError(
                launch.stderr.strip() or launch.stdout.strip() or "docker run failed"
            )
        self.container_id = launch.stdout.strip()
        self.started_at = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Torn down on the failure path too — the whole reason this is a context
        # manager. Never raises: a teardown that masked the run's own exception
        # would hide the thing worth reading.
        self.close()

    def close(self) -> None:
        if self.container_id is None and self.container_name is None:
            return
        env = _docker_env(docker_host=self.docker_host)
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            capture_output=True, text=True, env=env, check=False,
        )
        self.container_id = None

    # ── budgets ──────────────────────────────────────────────────────────────

    def remaining_commands(self, pillar: str | None = None) -> int:
        run_left = MAX_CLI_COMMANDS_PER_RUN - self.commands_run
        if pillar is None:
            return max(0, run_left)
        pillar_left = MAX_CLI_COMMANDS_PER_PILLAR - self.commands_by_pillar.get(pillar, 0)
        return max(0, min(run_left, pillar_left))

    def _check_budget(self, pillar: str | None) -> None:
        if pillar is not None and self.commands_by_pillar.get(pillar, 0) >= MAX_CLI_COMMANDS_PER_PILLAR:
            raise BudgetExhausted(
                f"command budget exhausted for {pillar!r} "
                f"({MAX_CLI_COMMANDS_PER_PILLAR} commands) — reason with what you already have"
            )
        if self.commands_run >= MAX_CLI_COMMANDS_PER_RUN:
            raise BudgetExhausted(
                f"command budget exhausted for this run ({MAX_CLI_COMMANDS_PER_RUN} "
                "commands) — reason with what you already have"
            )
        elapsed = time.monotonic() - self.started_at
        if elapsed >= MAX_CLI_WALL_CLOCK_SECONDS:
            raise BudgetExhausted(
                f"time budget exhausted for this run ({MAX_CLI_WALL_CLOCK_SECONDS}s) "
                "— reason with what you already have"
            )

    # ── execution ────────────────────────────────────────────────────────────

    def run(
        self, argv: list[str], *, display: str | None = None, pillar: str | None = None
    ) -> CommandResult:
        """Execute one already-guarded argv and return its capped output.

        A non-zero exit is a **result**, not an exception. A permission error is
        the single most informative thing this feature can learn — it is the
        difference between "the agent saw no org policies" and "the agent was
        not allowed to look" — so `stderr` comes back verbatim rather than
        flattened into "failed". The recon node reads it and records the
        gap in the report.
        """
        self._check_budget(pillar)
        command = display or " ".join(argv)
        env = _docker_env(docker_host=self.docker_host)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                build_exec_command(container_name=self.container_name, argv=argv),
                capture_output=True,
                text=True,
                env=env,
                timeout=CLI_COMMAND_TIMEOUT_SECONDS,
                check=False,
            )
            exit_code: int | None = completed.returncode
            stdout, stderr = completed.stdout, completed.stderr
        except subprocess.TimeoutExpired:
            exit_code = None
            stdout = ""
            stderr = f"command exceeded the {CLI_COMMAND_TIMEOUT_SECONDS}s per-command timeout"

        self.commands_run += 1
        if pillar is not None:
            self.commands_by_pillar[pillar] = self.commands_by_pillar.get(pillar, 0) + 1
        duration_ms = int((time.monotonic() - started) * 1000)

        # Truncation is flagged rather than silent, the posture `_paged` already
        # takes in agent_tools: a partial answer reported as complete is how a
        # report ends up asserting something nobody checked.
        truncated = len(stdout.encode()) > MAX_CLI_OUTPUT_BYTES
        if truncated:
            stdout = stdout.encode()[:MAX_CLI_OUTPUT_BYTES].decode(errors="ignore")

        logger.info(
            "cloud_cli command=%r exit=%s ms=%d truncated=%s",
            command, exit_code, duration_ms, truncated,
        )
        return CommandResult(
            ok=exit_code == 0,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr.strip(),
            truncated=truncated,
            duration_ms=duration_ms,
            command=command,
        )


def reap_orphaned_containers(*, docker_host: str) -> list[str]:
    """Remove recon containers left behind by a worker that was killed.

    The `sleep` ceiling means an orphan exits on its own, but an *exited*
    container still holds a name and a disk layer, so a worker that is killed
    repeatedly would otherwise accumulate them until a name collides.
    """
    env = _docker_env(docker_host=docker_host)
    listing = subprocess.run(
        ["docker", "ps", "-aq", "--filter", f"name={CONTAINER_NAME_PREFIX}"],
        capture_output=True, text=True, env=env, check=False,
    )
    ids = [line.strip() for line in listing.stdout.splitlines() if line.strip()]
    if ids:
        subprocess.run(
            ["docker", "rm", "-f", *ids],
            capture_output=True, text=True, env=env, check=False,
        )
    return ids
