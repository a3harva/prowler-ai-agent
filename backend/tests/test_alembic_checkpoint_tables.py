"""LangGraph's checkpoint tables must be invisible to Alembic autogenerate.

`PostgresSaver.setup()` creates four tables the application's `Base.metadata`
knows nothing about. Without the `include_name` filter in `alembic/env.py`,
the next `alembic revision --autogenerate` proposes dropping all four — the
same failure mode as an index declared only in a migration, arriving from a
new direction. Dropping a checkpoint table discards
every in-flight report's resume state.

AGENTS.md says to re-run autogenerate on a clean tree before trusting it; an
empty migration is the only real proof metadata and database agree. This is that step, made automatic, because the
tables it protects only appear after a deep report has run — so a human
following the checklist on a fresh machine would never see the problem.
"""

from __future__ import annotations

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from app.agents.checkpointer import CHECKPOINT_TABLES, dsn_from
from app.models import Base


def _env_table_list():
    """The copy in `alembic/env.py`, read as source.

    Imported by execution rather than by `import` because `env.py` is not a
    module on the path — Alembic runs it as a script, and it calls
    `get_settings()` at import time.
    """
    import ast
    from pathlib import Path

    env = Path(__file__).resolve().parent.parent / "alembic" / "env.py"
    tree = ast.parse(env.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "LANGGRAPH_TABLES" for t in node.targets
        ):
            return set(ast.literal_eval(node.value))
    raise AssertionError("LANGGRAPH_TABLES not found in alembic/env.py")


def _include_name(name, type_, parent_names):
    """The same predicate `alembic/env.py` installs."""
    return not (type_ == "table" and name in _env_table_list())


def test_the_two_table_lists_agree():
    """`env.py` duplicates the list rather than importing it, so a migration
    run does not depend on the agent package importing cleanly. Duplication is
    only safe while something checks the copies match."""
    assert _env_table_list() == set(CHECKPOINT_TABLES)


def test_autogenerate_ignores_the_checkpoint_tables(db_engine):
    """Create the checkpoint tables for real, then prove autogenerate is silent.

    Uses `PostgresSaver.setup()` rather than hand-written DDL so the test
    tracks whatever the library actually creates — if a future version adds a
    fifth table, this fails, which is exactly when someone needs to know.
    """
    saver = pytest.importorskip("langgraph.checkpoint.postgres")
    from psycopg_pool import ConnectionPool

    from app.config import get_settings

    pool = ConnectionPool(
        conninfo=dsn_from(get_settings().test_database_url),
        min_size=1,
        max_size=2,
        kwargs={"autocommit": True, "prepare_threshold": 0},
        open=False,
    )
    pool.open()
    try:
        saver.PostgresSaver(pool).setup()
    finally:
        pool.close()

    with db_engine.connect() as connection:
        context = MigrationContext.configure(
            connection, opts={"include_name": _include_name, "compare_type": False}
        )
        diff = compare_metadata(context, Base.metadata)

    dropped = {
        op[1].name if hasattr(op[1], "name") else op[1]
        for op in diff
        if isinstance(op, tuple) and op and op[0] == "remove_table"
    }
    assert not (dropped & set(CHECKPOINT_TABLES)), (
        "autogenerate proposed dropping LangGraph's checkpoint tables — the "
        "include_name filter in alembic/env.py is not working"
    )


def test_without_the_filter_autogenerate_would_drop_them(db_engine):
    """The negative control.

    A test that only asserts "autogenerate is quiet" passes just as happily
    when the tables were never created. This proves the filter is what makes
    it quiet, so the first test cannot rot into a tautology.
    """
    with db_engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": False})
        diff = compare_metadata(context, Base.metadata)

    dropped = {
        op[1].name if hasattr(op[1], "name") else op[1]
        for op in diff
        if isinstance(op, tuple) and op and op[0] == "remove_table"
    }
    assert set(CHECKPOINT_TABLES) <= dropped, (
        "the checkpoint tables were expected to exist and be reported as orphans "
        "without the filter — run test_autogenerate_ignores_the_checkpoint_tables first"
    )
