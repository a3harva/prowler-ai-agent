"""The scan/report worker split.

A report must not be able to occupy a scan-capable slot, and the scan ceiling
must be exactly `MAX_CONCURRENT_SCANS` rather than one more than it. Both are
properties of the two argvs `run_worker` builds, so they are asserted against
the argv rather than by starting Celery: a test that started two real workers
would prove nothing about queue affinity without also submitting real tasks and
waiting on real containers.
"""

import subprocess

import pytest

from app.worker import run_worker as rw

SETTINGS = {"MAX_CONCURRENT_SCANS": "2", "MAX_CONCURRENT_REPORTS": "3"}


def _flag(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


# ── the queues are disjoint ──────────────────────────────────────────────────


def test_the_scan_worker_does_not_consume_the_reports_queue():
    """A running report cannot delay a submitted scan, because the process with
    the scan slots is not subscribed to the queue reports arrive on."""
    argv = rw.celery_argv(rw.SCANS, SETTINGS)
    assert _flag(argv, "-Q") == "celery"
    assert "reports" not in _flag(argv, "-Q").split(",")


def test_the_report_worker_does_not_consume_the_scan_queue():
    """And the converse: a running scan cannot delay a submitted report."""
    argv = rw.celery_argv(rw.REPORTS, SETTINGS)
    assert _flag(argv, "-Q") == "reports"
    assert "celery" not in _flag(argv, "-Q").split(",")


def test_every_routed_queue_has_exactly_one_worker_that_consumes_it():
    """Guards the pairing rather than either half of it: a queue named in
    `task_routes` with no consumer is a task that silently never runs, and a
    queue with two consumers is the pre-split shape coming back."""
    from app.worker.celery_app import celery_app

    routed = {route["queue"] for route in celery_app.conf.task_routes.values()}
    consumed: dict[str, list[str]] = {}
    for role in rw.ROLES:
        for queue in _flag(rw.celery_argv(role, SETTINGS), "-Q").split(","):
            consumed.setdefault(queue, []).append(role)

    assert routed == set(consumed)
    assert all(len(roles) == 1 for roles in consumed.values()), consumed


# ── the ceilings are exact, and independent ──────────────────────────────────


def test_the_scan_ceiling_is_the_configured_number_not_one_more():
    """The defect this guards against. The single-process worker ran at
    MAX_CONCURRENT_SCANS + 1 and prefork slots are not queue-affine, so two
    scans could take both."""
    argv = rw.celery_argv(rw.SCANS, SETTINGS)
    assert "--concurrency=2" in argv
    assert "--concurrency=3" not in argv


def test_reports_get_their_own_budget_not_a_share_of_the_scan_one():
    assert "--concurrency=3" in rw.celery_argv(rw.REPORTS, SETTINGS)


def test_changing_the_report_budget_does_not_move_the_scan_budget():
    other = {"MAX_CONCURRENT_SCANS": "2", "MAX_CONCURRENT_REPORTS": "9"}
    assert rw.celery_argv(rw.SCANS, SETTINGS) == rw.celery_argv(rw.SCANS, other)


def test_a_configured_zero_still_runs_one():
    """Zero would consume the queue and never execute anything, which at runtime
    is indistinguishable from a wedged worker."""
    argv = rw.celery_argv(rw.SCANS, {"MAX_CONCURRENT_SCANS": "0", "MAX_CONCURRENT_REPORTS": "1"})
    assert "--concurrency=1" in argv


def test_an_unknown_role_is_refused_rather_than_defaulted():
    with pytest.raises(ValueError, match="unknown worker role"):
        rw.celery_argv("everything", SETTINGS)


# ── the two workers are distinguishable ──────────────────────────────────────


def test_the_two_workers_get_different_node_names():
    """Sharing a node name collides in Celery's control bus, and `celery
    inspect` could no longer say which of the two is busy."""
    names = {_flag(rw.celery_argv(role, SETTINGS), "-n") for role in rw.ROLES}
    assert len(names) == len(rw.ROLES)


def test_each_child_is_told_which_role_it_is():
    """`celery_app._reap_cloud_cli_orphans` reads this to decide whether it is
    allowed to reap."""
    env = rw.child_env(rw.REPORTS, {"PATH": "/usr/bin"})
    assert env[rw.ROLE_ENV_VAR] == rw.REPORTS
    assert env["PATH"] == "/usr/bin"


def test_no_argv_contains_a_shell_metacharacter():
    """Mirrors test_prowler_runner.py. Nothing here is user-supplied today, but
    the argv is execed, and the assertion is what keeps it that way."""
    for role in rw.ROLES:
        for token in rw.celery_argv(role, SETTINGS):
            assert not set(token) & set(";|&$><`\n"), token


# ── supervision: the two processes live and die together ─────────────────────


class _FakeChild:
    def __init__(self, status=None, *, stubborn=False):
        self._status = status
        self._stubborn = stubborn
        self.terminated = False
        self.killed = False

    def poll(self):
        return self._status

    def terminate(self):
        self.terminated = True
        if not self._stubborn:
            self._status = -15

    def kill(self):
        self.killed = True
        self._status = -9

    def wait(self, timeout=None):
        if self._status is None:
            raise subprocess.TimeoutExpired("celery", timeout)
        return self._status


def test_one_child_exiting_stops_the_other():
    """A half-worker that accepts reports and silently never runs a scan is
    worse than a container that fails visibly."""
    dead, alive = _FakeChild(status=1), _FakeChild()
    status = rw.supervise({rw.SCANS: dead, rw.REPORTS: alive}, poll=0)
    assert status == 1
    assert alive.terminated


def test_a_child_that_ignores_terminate_is_killed():
    stubborn = _FakeChild(stubborn=True)
    rw.stop_children({rw.REPORTS: stubborn}, grace=0)
    assert stubborn.terminated and stubborn.killed


def test_a_child_killed_by_a_signal_reports_a_shell_style_status():
    """An OOM-killed child polls as -9; exiting 0 there would tell Docker the
    container stopped cleanly."""
    oomed = _FakeChild(status=-9)
    assert rw.supervise({rw.REPORTS: oomed}, poll=0) == 137


def test_stopping_an_already_dead_child_does_not_raise():
    rw.stop_children({rw.SCANS: _FakeChild(status=0)}, grace=0)
