"""Root logger configuration.

Every test restores the root logger it found, because pytest's own capture
plugin owns handlers on it and a test that leaves one behind changes what every
later test sees.
"""

from __future__ import annotations

import logging

import pytest

from app import logging_config as lc


@pytest.fixture
def bare_root():
    """Call it to get a root logger with no handlers — the shape uvicorn leaves.

    A factory rather than a plain fixture on purpose. pytest's logging plugin
    re-installs its capture handler on the root logger *between* fixture setup
    and the test body, so a fixture that clears handlers during setup hands the
    test a root that is populated again by the time it runs — and
    `configure_logging`, seeing handlers, correctly declines to add its own.
    Every test in this file failed that way before the clearing moved into the
    body.
    """
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    saved_noisy = {name: logging.getLogger(name).level for name in lc.NOISY_LOGGERS}

    def _clear():
        logging.getLogger().handlers = []
        return root

    try:
        yield _clear
    finally:
        root.handlers = saved_handlers
        root.setLevel(saved_level)
        for name, level in saved_noisy.items():
            logging.getLogger(name).setLevel(level)


def _ours(root):
    return [h for h in root.handlers if getattr(h, lc._MARKER, False)]


# ── the actual defect: an app INFO line reaching stderr ──────────────────────


def test_an_app_info_line_is_emitted_after_configuring(bare_root, capsys):
    """The whole point. Before this, `logger.info` in the API process went
    nowhere and `logger.warning` escaped only through logging.lastResort."""
    root = bare_root()
    lc.configure_logging()
    logging.getLogger("app.integrations.gemini_agent").info("call latency_ms=51900")

    err = capsys.readouterr().err
    assert "call latency_ms=51900" in err
    assert "app.integrations.gemini_agent" in err
    assert "INFO" in err


def test_nothing_is_emitted_before_configuring(bare_root, capsys):
    """The negative control. Without it this file could pass because something
    else in the process had already configured logging."""
    root = bare_root()
    logging.getLogger("app.integrations.gemini_agent").info("call latency_ms=51900")
    assert "latency_ms" not in capsys.readouterr().err


def test_one_handler_is_attached_to_a_bare_root(bare_root):
    root = bare_root()
    lc.configure_logging()
    assert len(_ours(root)) == 1
    assert root.level == logging.INFO


# ── idempotence: uvicorn --reload re-imports the app module on every edit ────


def test_calling_twice_does_not_stack_a_second_handler(bare_root, capsys):
    """`--reload` re-imports `app.api.main` per edit, so a non-idempotent
    configure prints every line twice, then three times, then four."""
    root = bare_root()
    lc.configure_logging()
    lc.configure_logging()
    lc.configure_logging()

    assert len(_ours(root)) == 1
    logging.getLogger("app.services.agent").info("once")
    assert capsys.readouterr().err.count("once") == 1


def test_a_repeat_call_can_still_change_the_level(bare_root):
    root = bare_root()
    lc.configure_logging(level="DEBUG")
    assert root.level == logging.DEBUG
    lc.configure_logging(level="INFO")
    assert root.level == logging.INFO
    assert len(_ours(root)) == 1


# ── it must not fight a process whose logging somebody else owns ─────────────


def test_an_existing_handler_is_left_alone(bare_root):
    """Celery hijacks the root logger at worker start and its handler is the
    one that should win. Adding ours next to it would duplicate every line."""
    root = bare_root()
    celerys = logging.StreamHandler()
    root.addHandler(celerys)

    lc.configure_logging()

    assert root.handlers == [celerys]
    assert _ours(root) == []


def test_noisy_loggers_are_quieted_even_when_we_add_no_handler(bare_root):
    """The levels are true regardless of who owns the handler, so they are
    applied on both paths."""
    root = bare_root()
    root.addHandler(logging.StreamHandler())
    lc.configure_logging()
    assert logging.getLogger("sqlalchemy.engine").level == logging.WARNING


# ── root at INFO turns INFO on for every library, not just ours ──────────────


def test_the_loud_libraries_are_held_at_warning(bare_root):
    """Without this the one line worth reading arrives buried in per-request
    httpx and google.auth chatter — its own way of not reaching the reader."""
    root = bare_root()
    lc.configure_logging()
    for name in lc.NOISY_LOGGERS:
        assert logging.getLogger(name).level == logging.WARNING, name


def test_sqlalchemy_statement_logging_stays_off(bare_root, capsys):
    """At INFO it prints every statement and every bound parameter, so one
    findings page becomes hundreds of lines."""
    root = bare_root()
    lc.configure_logging()
    logging.getLogger("sqlalchemy.engine").info("SELECT findings.id FROM findings")
    assert "SELECT findings.id" not in capsys.readouterr().err


def test_a_warning_from_a_noisy_library_still_gets_through(bare_root, capsys):
    """Quieted, not silenced — a library warning is usually the real problem."""
    root = bare_root()
    lc.configure_logging()
    logging.getLogger("httpx").warning("connection pool is full")
    assert "connection pool is full" in capsys.readouterr().err


def test_debug_does_not_secretly_re_enable_the_noisy_ones(bare_root):
    """`max(resolved, WARNING)` is what holds this: asking for DEBUG globally
    must not turn every SQL statement back on as a side effect."""
    root = bare_root()
    lc.configure_logging(level="DEBUG")
    assert root.level == logging.DEBUG
    assert logging.getLogger("sqlalchemy.engine").level == logging.WARNING


# ── level resolution ─────────────────────────────────────────────────────────


def test_the_level_comes_from_the_environment_when_not_passed(bare_root, monkeypatch):
    root = bare_root()
    monkeypatch.setenv(lc.LEVEL_ENV_VAR, "warning")
    lc.configure_logging()
    assert root.level == logging.WARNING


def test_the_default_is_info_when_the_environment_says_nothing(bare_root, monkeypatch):
    root = bare_root()
    monkeypatch.delenv(lc.LEVEL_ENV_VAR, raising=False)
    lc.configure_logging()
    assert root.level == logging.INFO


def test_an_unparseable_level_falls_back_rather_than_logging_nothing(bare_root, monkeypatch):
    """A typo in LOG_LEVEL must not be the reason the API goes silent — which
    is what `logging.getLevelName` returning the string 'Level BANANAS' would
    otherwise cause."""
    root = bare_root()
    monkeypatch.setenv(lc.LEVEL_ENV_VAR, "BANANAS")
    lc.configure_logging()
    assert root.level == logging.INFO


def test_an_empty_level_is_treated_as_absent(bare_root, monkeypatch):
    root = bare_root()
    monkeypatch.setenv(lc.LEVEL_ENV_VAR, "")
    lc.configure_logging()
    assert root.level == logging.INFO


def test_a_numeric_level_is_accepted(bare_root):
    root = bare_root()
    lc.configure_logging(level=logging.ERROR)
    assert root.level == logging.ERROR


# ── it is not a config key, and must never become one ────────────────────────


def test_log_level_is_not_a_config_key():
    """`config.py` fails startup when any CONFIG_KEYS entry is missing, so
    adding one breaks every existing .env.local. Same reasoning as
    MAX_INVESTIGATION_ROUNDS and THINKING_LEVEL."""
    from app.config import CONFIG_KEYS

    assert lc.LEVEL_ENV_VAR not in CONFIG_KEYS


def test_the_api_configures_logging_at_import(bare_root):
    """The wiring, not just the function. Imported for the side effect, which
    is the whole reason the call sits at module level in api/main.py."""
    root = bare_root()
    import importlib

    import app.api.main as main

    importlib.reload(main)
    assert len(_ours(root)) == 1
