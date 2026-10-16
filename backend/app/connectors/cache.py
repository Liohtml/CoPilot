"""Process-wide cache for connector credentials (#1072, level 4).

Level 2 established the number that reframes this whole effort: **every
statement on this deployment costs ~135ms regardless of what it does** (p50
134.2–134.8ms across four sessions and 3,317 queries). The lever is the *number*
of round-trips per request, not the SQL inside them.

With the per-request user lookup fixed (level 3), the largest remaining consumer
is the connector credential read: 244 queries in one session, **3.4 per
request**, and rising as more integrations land. `get_connector_info_from_db` is
called from 89 sites across 22 modules — every outbound call to Wazuh, Graylog,
Velociraptor, Cortex, InfluxDB, Shuffle, Talon… first asks the database where to
go and with what key.

The cost is worse than the call count suggests. `Connectors.history_logs` is
declared `lazy="selectin"`, so each of those reads fires a *second* statement
against `connectorhistory` — and nothing in the codebase reads `history_logs`
off this path. Caching removes both.

There are **two** funnels into this table, and caching only one leaves roughly a
quarter of the reads in place. `app/utils.py:get_connector_attribute` has a
further 88 call sites and reads the same row for a single column, addressed
either by name or — in a handful of places — by id. Both now read through here;
the id map below is what lets the id form share the same entries.

**Why this is safe to cache when most things are not:** connector configuration
is deployment-wide (one row per tool, no tenant dimension — see CLAUDE.md,
"Connector credentials are global") and changes only when an operator changes it.
Every write path is in `ConnectorServices` and invalidates this cache
immediately after its commit. The TTL is a backstop for the one case
invalidation cannot see — someone editing the table directly — not the primary
correctness mechanism.

**Across processes.** With the Rust service in front (`crates/`), connector
rows are written by two processes, and neither can reach the other's cache.
So each one *checks*: before serving a cached row, a process whose last look at
the table is older than `CONNECTOR_CACHE_CHECK_SECONDS` (5 s) reads every row
once — a single small statement — and drops the cached rows that no longer
match. A row is served only if MySQL confirmed it, by its load or by a check, no
earlier than the last check began. After any committed write, by either
backend, the startup sync or someone with a MySQL shell, no process serves the
old row for longer than the interval plus one query, and the writer forgets it
at once (`invalidate()` after its commit). The Rust cache
(`crates/copilot-db/src/connectors.rs`) follows the same rule. `0` turns the
check off (the TTL alone then bounds staleness).

Two deliberate non-features:

* **Misses are not cached.** A `None` means the connector row does not exist yet;
  remembering that would make a newly-added connector invisible for the whole
  TTL. The same reasoning applies to the user cache in `app/auth/utils.py`.
* **Nothing is pre-warmed.** The first caller of each connector pays one lookup.
  Pre-warming would put 20+ queries into startup to save them from a request
  that may never come.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any
from typing import Dict
from typing import Optional

from loguru import logger


def _ttl_seconds() -> int:
    """Read at import; `0` disables the cache, which is how you A/B it."""
    raw = os.getenv("CONNECTOR_CACHE_TTL_SECONDS", "600")
    try:
        return max(int(raw), 0)
    except ValueError:
        logger.warning(f"CONNECTOR_CACHE_TTL_SECONDS={raw!r} is not an integer; falling back to 600s")
        return 600


TTL_SECONDS = _ttl_seconds()


def _check_seconds() -> float:
    """Read at import; `0` turns the cross-process change check off."""
    raw = os.getenv("CONNECTOR_CACHE_CHECK_SECONDS", "5")
    try:
        return max(float(int(raw)), 0.0)
    except ValueError:
        logger.warning(f"CONNECTOR_CACHE_CHECK_SECONDS={raw!r} is not an integer; falling back to 5s")
        return 5.0


CHECK_SECONDS = _check_seconds()

# `time.monotonic`, not `datetime.utcnow`: an NTP step backwards would otherwise
# leave an entry that never expires, and credentials are the wrong thing to be
# wrong about indefinitely.
#
# Each entry is `(loaded_at, confirmed_at, payload)`: when its load began (the
# TTL counts from there), and the latest moment MySQL confirmed the row — its
# load, or a change check that found it unchanged.
_entries: Dict[str, tuple[float, float, Dict[str, Any]]] = {}
_locks: Dict[str, asyncio.Lock] = {}

# When the last successful change check began (`None` before the first).
_checked_at: Optional[float] = None
_check_lock = asyncio.Lock()

# `connector_id` → `connector_name`, for the minority of call sites that address
# a connector by id (`get_connector_attribute(connector_id=10, …)`). Kept
# separately from `_entries` and *not* subject to the TTL: a row's id and name
# are its identity and only change when the row is recreated, which happens in
# the startup sync — and that calls `invalidate_all()`.
_names_by_id: Dict[int, str] = {}

_hits = 0
_misses = 0
_invalidations = 0
_checks = 0
_stale_dropped = 0


def _copy(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Hand out a copy, never the stored dict.

    Callers today only read (`attributes["connector_url"]` and friends), but a
    future one that mutates its result would otherwise silently corrupt every
    subsequent caller's credentials. A shallow copy of ~19 scalars costs
    microseconds against a 135ms round-trip; `history_logs` is a list nobody
    reads, so it is copied by reference on purpose.
    """
    return dict(payload)


def _peek(connector_name: str) -> Optional[Dict[str, Any]]:
    """A pure lookup: no counters, no locking. Not the entry point."""
    if TTL_SECONDS == 0:
        return None

    entry = _entries.get(connector_name)
    if entry is None:
        return None

    loaded_at, confirmed_at, payload = entry
    if time.monotonic() - loaded_at >= TTL_SECONDS:
        # Expired: drop it rather than leave it for the next caller to re-check.
        _entries.pop(connector_name, None)
        return None
    if CHECK_SECONDS > 0 and _checked_at is not None and confirmed_at < _checked_at:
        # Loaded before the last check began and not confirmed by it (a load
        # that raced the check): MySQL may hold something newer.
        _entries.pop(connector_name, None)
        return None

    return _copy(payload)


async def _read_rows() -> Dict[str, Dict[str, Any]]:
    """Every connector row's columns, keyed by name (the lowest id wins, as
    `select(...).where(name == …).first()` picks it). One statement, on its own
    session so that the caller's transaction snapshot cannot hide a change."""
    from sqlalchemy import select

    from app.connectors.models import Connectors
    from app.db.db_session import AsyncSessionLocal

    table = Connectors.__table__
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(table).order_by(table.c.id))
        rows = result.mappings().all()
    current: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        current.setdefault(row["connector_name"], dict(row))
    return current


def _check_due() -> bool:
    if TTL_SECONDS == 0 or CHECK_SECONDS <= 0:
        return False
    return _checked_at is None or time.monotonic() - _checked_at >= CHECK_SECONDS


async def revalidate() -> None:
    """The cross-process change check (see the module docstring).

    Reads the table once and drops every cached row that differs from its row
    (or whose row is gone). A failed read drops everything: a credential that
    cannot be confirmed is not served.
    """
    global _checked_at, _checks, _stale_dropped

    if not _check_due():
        return
    async with _check_lock:
        if not _check_due():
            return
        started = time.monotonic()
        _checks += 1
        try:
            current = await _read_rows()
        except Exception as e:  # noqa: BLE001 - fail closed, whatever the driver raised
            logger.warning(f"Connector cache check failed ({e}); dropping cached rows")
            _stale_dropped += len(_entries)
            _entries.clear()
            return
        for name, (loaded_at, _confirmed, payload) in list(_entries.items()):
            row = current.get(name)
            if row is None or any(payload.get(column) != value for column, value in row.items()):
                _entries.pop(name, None)
                _stale_dropped += 1
                logger.debug(f"Connector cache: {name} changed in the database; dropped")
            else:
                _entries[name] = (loaded_at, started, payload)
        _checked_at = started


def lock_for(connector_name: str) -> asyncio.Lock:
    """Serialise cold lookups of one connector.

    Without this the fan-outs built earlier in #1072 stampede: `/status/sidebar`
    runs 14 indicator builders concurrently and several ask for the same
    connector, so a cold cache turns into 14 identical queries instead of one.
    Per name, so a slow Velociraptor lookup never blocks a Graylog one.
    """
    lock = _locks.get(connector_name)
    if lock is None:
        lock = asyncio.Lock()
        _locks[connector_name] = lock
    return lock


async def get_or_load(connector_name: str, loader) -> Optional[Dict[str, Any]]:
    """Read through the cache, loading at most once per connector.

    The read-through lives here rather than at the call site so that one place
    owns all three invariants — the double-check under the lock, the decision
    not to cache a miss, and the hit/miss accounting. Doing it by hand at the
    call site got the last one wrong immediately: the recheck inside the lock
    counted a *second* miss for the same request, understating the hit ratio
    that is the whole point of measuring this.

    Args:
        connector_name: the cache key, and the name the loader will look up.
        loader: an async callable returning the payload dict, or None if the
            connector does not exist.
    """
    global _hits, _misses

    await revalidate()
    cached = _peek(connector_name)
    if cached is not None:
        _hits += 1
        return cached

    async with lock_for(connector_name):
        # Someone may have loaded it while we waited. Still a hit for this
        # caller — it never reached the database.
        cached = _peek(connector_name)
        if cached is not None:
            _hits += 1
            return cached

        _misses += 1
        started = time.monotonic()
        payload = await loader()
        if payload is None:
            # Deliberately not cached — a missing row usually means "not created
            # yet", and remembering it would hide the connector for a whole TTL.
            return None

        if TTL_SECONDS > 0:
            _entries[connector_name] = (started, started, _copy(payload))
        remember_id(payload.get("id"), connector_name)
        return _copy(payload)


def remember_id(connector_id: Optional[int], connector_name: str) -> None:
    """Record the id → name mapping seen on a load."""
    if connector_id is not None:
        _names_by_id[connector_id] = connector_name


def name_for_id(connector_id: int) -> Optional[str]:
    """The connector's name, if this process has ever loaded that row."""
    return _names_by_id.get(connector_id)


def invalidate(connector_name: Optional[str]) -> None:
    """Forget one connector. Called after every committed write to its row."""
    global _invalidations

    if not connector_name:
        return
    if _entries.pop(connector_name, None) is not None:
        _invalidations += 1
        logger.debug(f"Connector cache invalidated for {connector_name}")


def invalidate_all() -> None:
    """Forget everything — used by the startup sync and by the tests.

    The id map goes too: the startup sync is the one place that deletes and
    recreates connector rows, so it is also the one place an id could come back
    attached to a different name.
    """
    global _invalidations

    _invalidations += len(_entries)
    _entries.clear()
    _names_by_id.clear()


def reset_stats() -> None:
    """Test seam. Production never needs this; the counters are cumulative."""
    global _hits, _misses, _invalidations, _checks, _stale_dropped, _checked_at

    _hits = _misses = _invalidations = _checks = _stale_dropped = 0
    _checked_at = None


def stats() -> Dict[str, Any]:
    """Surfaced in the performance session log, so the next session measures it."""
    looked_up = _hits + _misses
    return {
        "entries": len(_entries),
        "hits": _hits,
        "misses": _misses,
        "invalidations": _invalidations,
        "hit_ratio": round(_hits / looked_up, 4) if looked_up else None,
        "ttl_seconds": TTL_SECONDS,
        "checks": _checks,
        "stale_dropped": _stale_dropped,
        "check_seconds": CHECK_SECONDS,
    }
