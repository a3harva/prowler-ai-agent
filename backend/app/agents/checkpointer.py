"""The `PostgresSaver` factory, and the DSN translation it needs.

**Two Postgres drivers now live in this image and that is deliberate.** The
application is sync SQLAlchemy on `psycopg2` (the data layer is
one colour because `app/services/` is shared between FastAPI and Celery).
`langgraph-checkpoint-postgres` is built on `psycopg` 3 and cannot use
psycopg2. They coexist cleanly — different import names, different connection
objects, no shared state — but two things follow that are easy to get wrong:

1. `DATABASE_URL` is a SQLAlchemy URL (`postgresql+psycopg2://...`). psycopg3
   parses a libpq DSN and rejects the `+psycopg2` dialect suffix. `dsn_from()`
   strips it.
2. `psycopg[binary]` is pinned explicitly in `pyproject.toml`. Without the
   binary extra, psycopg3 needs a system `libpq`, which this image does not
   install — psycopg2-binary bundles its own statically, so its presence
   proves nothing about psycopg3's. Omitting the extra fails at first connect
   with "no pq wrapper available", long after the build succeeded.

**The four tables this creates are invisible to Alembic** — see
`alembic/env.py`. `setup()` creates `checkpoints`, `checkpoint_blobs`,
`checkpoint_writes` and `checkpoint_migrations`, none of which are in
`Base.metadata`, so autogenerate would propose dropping all four.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager

from langgraph.checkpoint.postgres import PostgresSaver
from psycopg_pool import ConnectionPool

logger = logging.getLogger(__name__)

# Every table langgraph-checkpoint-postgres creates. Duplicated in
# `alembic/env.py` rather than imported, because importing this module there
# would drag psycopg3 and langgraph into the migration environment for the
# sake of one frozenset — and a migration run must not depend on the agent
# package importing cleanly. `tests/test_alembic_checkpoint_tables.py` asserts
# the two copies agree.
CHECKPOINT_TABLES = frozenset(
    {"checkpoints", "checkpoint_blobs", "checkpoint_writes", "checkpoint_migrations"}
)


def dsn_from(database_url: str) -> str:
    """SQLAlchemy URL -> libpq DSN.

    Only the dialect suffix differs for the URLs this application uses, so the
    translation is a single replace rather than a URL parse. Any other
    `postgresql+driver://` form is normalised the same way.
    """
    if database_url.startswith("postgresql+"):
        scheme, _, rest = database_url.partition("://")
        return f"postgresql://{rest}"
    return database_url


@contextmanager
def checkpointer_for(database_url: str):
    """A `PostgresSaver` over its own short-lived connection pool.

    Scoped to one graph run rather than memoized at module level on purpose:
    this is used from a Celery prefork worker, and a pool created before the
    fork would be shared across children with predictably bad results. A
    report takes minutes and opens at most two connections, so the cost of
    building a pool per run is not worth engineering around.

    `setup()` is idempotent — it runs its own migration table — so calling it
    on every run is correct rather than merely tolerable, and means a fresh
    database needs no separate provisioning step.
    """
    pool = ConnectionPool(
        conninfo=dsn_from(database_url),
        min_size=1,
        max_size=2,
        # langgraph writes with server-side cursors disabled and expects
        # autocommit; the saver manages its own transactions.
        kwargs={"autocommit": True, "prepare_threshold": 0},
        open=False,
    )
    pool.open()
    try:
        saver = PostgresSaver(pool)
        saver.setup()
        yield saver
    finally:
        pool.close()
