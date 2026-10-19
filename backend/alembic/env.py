from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.config import get_settings
from app.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

config.set_main_option("sqlalchemy.url", get_settings().database_url)

# ── tables Alembic must not manage ───────────────────────────────────────────
# langgraph-checkpoint-postgres creates these itself, via its own migration
# table, the first time a deep report runs. They are not in `Base.metadata`,
# so without this filter the next `--autogenerate` proposes dropping all four
# — the same failure mode as an index declared only in a migration, arriving
# from a new direction. Deleting a checkpoint table drops
# every in-flight report's resume state.
#
# Duplicated from `app/agents/checkpointer.py::CHECKPOINT_TABLES` rather than
# imported: a migration run must not depend on the agent package (and hence
# psycopg3 and langgraph) importing cleanly. `tests/test_alembic_checkpoint_
# tables.py` asserts the two copies agree.
LANGGRAPH_TABLES = {
    "checkpoints",
    "checkpoint_blobs",
    "checkpoint_writes",
    "checkpoint_migrations",
}


def include_name(name, type_, parent_names) -> bool:
    """Keep LangGraph's checkpoint tables out of autogenerate entirely.

    Filtering by *name* rather than by object matters: `include_object` is
    only consulted for objects Alembic could reflect into metadata, whereas a
    table present in the database and absent from the model is exactly the
    case that produces a spurious `drop_table`. `include_name` is the hook
    that sees it.
    """
    if type_ == "table" and name in LANGGRAPH_TABLES:
        return False
    return True


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_name=include_name,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_name=include_name,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
