"""Launches the pinned Prowler image as a sibling container on the same
Docker daemon the worker itself runs under (Colima locally, stock Docker on
a Linux host) — never as a child process, so a worker restart or crash does not
take a running scan down with it.

`project_id` and `target_sa_email` reach this module only as plain function
arguments sourced from a validated `projects` row (see services/scans.py) —
never as raw request input, and never folded into a shell string. Every
subprocess call here passes an argv list with `shell=False` (the default),
so there is no shell for user-influenced text to be interpolated into in the
first place.
"""

from __future__ import annotations

import dataclasses
import os
import subprocess

# Prowler's own exit-code convention (not a generic "0 = ok" convention):
# 0   — scan ran fine, every check passed
# 3   — scan ran fine, at least one check FAILed — the normal outcome for
#       many projects, not an application-level failure
# any other code — the tool itself errored (bad credentials, crash, ...)
# Treating this outcome as an application failure would discard valid scanner
# output whenever a finding is present.
PROWLER_SUCCESS_EXIT_CODES = frozenset({0, 3})


class ScanLaunchError(RuntimeError):
    """The `docker run` invocation itself failed — before the scan container
    ever started (bad DOCKER_HOST, image not pulled, daemon unreachable)."""


@dataclasses.dataclass(frozen=True)
class ScanRunResult:
    container_id: str
    exit_code: int | None
    timed_out: bool
    log_text: str


def _docker_env(*, docker_host: str) -> dict[str, str]:
    env = os.environ.copy()
    env["DOCKER_HOST"] = docker_host
    return env


def build_docker_run_command(
    *,
    container_name: str,
    prowler_image: str,
    host_output_dir: str,
    project_id: str,
    target_sa_email: str,
    gcloud_adc_path: str,
) -> list[str]:
    """Pure and side-effect free so the launch path can be proven not to
    interpolate caller-supplied text without ever touching a real Docker
    daemon: every argument lands as its own argv element, not as a
    substring of a shell command."""
    cmd = ["docker", "run", "-d", "--name", container_name]

    # LOCAL ONLY. On a GCE host this is empty — the attached service account
    # is reached through the metadata server and nothing is mounted.
    if gcloud_adc_path:
        cmd += [
            "-v", f"{gcloud_adc_path}:/home/prowler/adc.json:ro",
            "-e", "GOOGLE_APPLICATION_CREDENTIALS=/home/prowler/adc.json",
        ]

    cmd += [
        "-v", f"{host_output_dir}:/home/prowler/output",
        prowler_image,
        "gcp",
        "--project-ids", project_id,
        "--impersonate-service-account", target_sa_email,
        "--output-directory", "/home/prowler/output",
        "--output-filename", "scan",
        "--output-formats", "csv", "json-ocsf", "html",
    ]
    return cmd


def launch_scan(
    *,
    scan_id: int,
    project_id: str,
    target_sa_email: str,
    prowler_image: str,
    docker_host: str,
    reports_path: str,
    host_reports_path: str,
    gcloud_adc_path: str,
) -> str:
    """Starts the sibling container and returns its id immediately — the
    caller marks the scan `running` off this return, before the (possibly
    multi-minute) wait in `wait_for_scan` begins, so "running" is a state the
    UI actually observes rather than one that only exists for an instant
    right before the terminal state."""
    container_name = f"prowler-scan-{scan_id}"
    worker_output_dir = os.path.join(reports_path, str(scan_id))
    host_output_dir = os.path.join(host_reports_path, str(scan_id))
    os.makedirs(worker_output_dir, exist_ok=True)

    env = _docker_env(docker_host=docker_host)
    cmd = build_docker_run_command(
        container_name=container_name,
        prowler_image=prowler_image,
        host_output_dir=host_output_dir,
        project_id=project_id,
        target_sa_email=target_sa_email,
        gcloud_adc_path=gcloud_adc_path,
    )

    launch = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
    if launch.returncode != 0:
        raise ScanLaunchError(launch.stderr.strip() or launch.stdout.strip() or "docker run failed")
    return launch.stdout.strip()


def kill_and_remove_container(*, container_id: str, docker_host: str) -> None:
    """Best-effort teardown for a cancelled scan. Both calls are allowed to
    fail quietly — `docker kill` errors if the container already exited
    (exactly the orphaned case this exists for: the scan finished hours ago
    and nothing was left to reap it), and `docker rm -f` is what actually
    removes it either way. Never raises: this runs from a cleanup task with
    no user waiting on it, and a container name collision on the next scan
    submission is a `docker run` failure surfaced through the normal launch
    path, not something this function needs to prevent."""
    env = _docker_env(docker_host=docker_host)
    subprocess.run(["docker", "kill", container_id], env=env, capture_output=True, check=False)
    subprocess.run(["docker", "rm", "-f", container_id], env=env, capture_output=True, check=False)


def wait_for_scan(
    *,
    container_id: str,
    docker_host: str,
    reports_path: str,
    scan_id: int,
    timeout_seconds: int,
) -> ScanRunResult:
    """Blocks the calling Celery worker thread until the container exits or
    `timeout_seconds` elapses — that thread occupancy, via the worker's own
    concurrency setting, is what makes additional submissions queue rather
    than run unbounded."""
    worker_output_dir = os.path.join(reports_path, str(scan_id))
    # launch_scan already creates this directory, but wait_for_scan doesn't
    # rely on being called right after it (see tasks.py's ScanLaunchError
    # branch, which never reaches this function at all) — cheap enough not
    # to assume the caller got the order right.
    os.makedirs(worker_output_dir, exist_ok=True)
    env = _docker_env(docker_host=docker_host)

    timed_out = False
    exit_code: int | None = None
    try:
        wait = subprocess.run(
            ["docker", "wait", container_id],
            capture_output=True, text=True, env=env, timeout=timeout_seconds, check=False,
        )
        exit_code = int(wait.stdout.strip()) if wait.stdout.strip() else None
    except subprocess.TimeoutExpired:
        timed_out = True
        subprocess.run(["docker", "kill", container_id], env=env, capture_output=True, check=False)

    logs = subprocess.run(["docker", "logs", container_id], capture_output=True, text=True, env=env, check=False)
    log_text = logs.stdout + logs.stderr

    with open(os.path.join(worker_output_dir, "prowler.log"), "w") as f:
        f.write(log_text)

    subprocess.run(["docker", "rm", "-f", container_id], env=env, capture_output=True, check=False)

    return ScanRunResult(
        container_id=container_id,
        exit_code=exit_code,
        timed_out=timed_out,
        log_text=log_text,
    )


def summarize_failure(*, exit_code: int | None, timed_out: bool, log_text: str) -> str:
    """Return a safe public failure summary without persisting raw tool logs."""
    if timed_out:
        return "scan exceeded its time ceiling and was terminated"
    return f"scan failed with exit code {exit_code}" if exit_code is not None else "scan failed"
