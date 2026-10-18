"""The startup lock shared with the Rust service — the Python half of a race-free startup.

The Rust backend (`crates/copilot-startup`, `crates/copilot-migrate`) runs the same startup steps as
`copilot.py`'s `lifespan`: the schema (Rust migrations on the Alembic-head baseline, or adopting a
database Alembic brought there) and the seeding (connectors, roles, catalogs, system users,
templates, portal settings, scheduler rows). None of the seeded tables has a unique key, so two
processes checking-then-inserting at the same moment would both insert, and Alembic creating the
schema while the Rust runner creates the baseline would leave neither. While both backends run next
to each other (`docker-compose.rust.yml`), each takes this one MySQL named lock before those steps
and releases it after: an empty database gets one schema and one set of rows, whichever process
starts first, and the other then finds everything in place.

The name is computed by MySQL on both sides (`LOCK_NAME_SQL`, the same text as Rust's
`copilot_migrate::lock::LOCK_NAME_SQL`). MySQL drops the lock with its connection, so a process that
dies holding it strands nothing. A wait longer than `STARTUP_LOCK_WAIT_SECONDS` stops the start
rather than seed beside a process that may still be at it.
"""

from loguru import logger
from sqlalchemy import text

from app.db.db_session import sync_engine

# Scoped to the database: `copilot_startup:` and the SHA-1 of its name (56 characters).
LOCK_NAME_SQL = "CONCAT('copilot_startup:', SHA1(DATABASE()))"
# Alembic's run from an empty database takes a minute or two on a slow host.
STARTUP_LOCK_WAIT_SECONDS = 600


class StartupLock:
    """The lock, held by a connection of its own until `release()`."""

    def __init__(self, connection):
        self._connection = connection

    @classmethod
    def acquire(cls, wait_seconds: int = STARTUP_LOCK_WAIT_SECONDS) -> "StartupLock":
        connection = sync_engine.connect()
        got = connection.execute(text(f"SELECT GET_LOCK({LOCK_NAME_SQL}, :wait)"), {"wait": wait_seconds}).scalar()
        # A named lock is not transactional: end the implicit transaction, so this connection
        # holds no snapshot while the steps run on others.
        connection.commit()
        if got != 1:
            connection.close()
            raise RuntimeError(
                f"another CoPilot process (Rust or Python) held the startup lock of this database for {wait_seconds} s: "
                "it is migrating or seeding it, or hangs doing so",
            )
        logger.info("Startup lock taken")
        return cls(connection)

    def release(self) -> None:
        try:
            self._connection.execute(text(f"SELECT RELEASE_LOCK({LOCK_NAME_SQL})"))
            self._connection.commit()
        except Exception as e:  # noqa: BLE001
            # Never hand a connection that may still hold the lock back to the pool.
            logger.warning(f"Could not release the startup lock, discarding its connection: {e}")
            self._connection.invalidate()
        finally:
            self._connection.close()
