"""Process-wide cache of resolved Customer Portal branding.

``resolve_effective_branding`` reads the global settings row and a customer's
override row — both carrying a LONGTEXT base64 logo — and it runs on every portal
boot and login, every logo fetch and every branded PDF report. Branding changes only
when an operator saves it, which makes it safe to cache the same way connector
credentials are (``app/connectors/cache.py``):

* every write path invalidates right after its commit (``update_portal_settings``,
  ``set_customer_branding``, ``remove_customer_branding``);
* the TTL is only a backstop for edits that bypass those paths (the table edited
  directly).

Invalidation is always *all* entries, never one customer: a change to the global
defaults changes the resolved branding of every customer that inherits a field.

**Across processes.** With the Rust service in front (``crates/``), the branding
tables are written by two processes, and neither can reach the other's cache. So
each one *checks*: before serving a cached entry, a process whose last look at the
tables is older than ``BRANDING_CACHE_CHECK_SECONDS`` (5 s) reads their fingerprint —
one small statement: every row's id, customer, switch, title, MIME type and colour,
and the logo's length and CRC-32, computed by MySQL so no logo is transferred — and
drops every entry when it differs from the one it read last time. A load that began
before a check or an invalidation dropped the entries is not stored. So after any
committed write, by either backend or with a MySQL shell, no process serves the old
branding for longer than the interval plus one query; the writer forgets it at once.
The Rust cache (``crates/copilot-customer-portal/src/branding/cache.rs``) follows the
same rule with the same statement. ``0`` turns the check off (the TTL alone then
bounds staleness).

``BRANDING_CACHE_TTL_SECONDS=0`` disables the cache.
"""

import os
import time
from typing import Awaitable
from typing import Callable
from typing import Dict
from typing import Optional
from typing import Tuple

from loguru import logger

from app.customer_portal.schema.branding import EffectiveBranding


def _ttl_seconds() -> int:
    raw = os.getenv("BRANDING_CACHE_TTL_SECONDS", "600")
    try:
        return max(int(raw), 0)
    except ValueError:
        logger.warning(f"BRANDING_CACHE_TTL_SECONDS={raw!r} is not an integer; falling back to 600s")
        return 600


def _check_seconds() -> float:
    """Read at import; ``0`` turns the cross-process change check off."""
    raw = os.getenv("BRANDING_CACHE_CHECK_SECONDS", "5")
    try:
        return max(float(int(raw)), 0.0)
    except ValueError:
        logger.warning(f"BRANDING_CACHE_CHECK_SECONDS={raw!r} is not an integer; falling back to 5s")
        return 5.0


TTL_SECONDS = _ttl_seconds()
CHECK_SECONDS = _check_seconds()

# customer_code (None = the global defaults) -> (stored at, resolved branding).
# `time.monotonic`, not wall time: a clock step backwards must not keep an entry forever.
_entries: Dict[Optional[str], Tuple[float, EffectiveBranding]] = {}

# Bumped whenever the entries are dropped: a load that began before is not stored.
_epoch = 0
# When the last change check began, and the fingerprint it read.
_checked_at: Optional[float] = None
_fingerprint: Optional[tuple] = None


def _drop_entries() -> None:
    global _epoch
    _entries.clear()
    _epoch += 1


async def _check(fingerprint: Callable[[], Awaitable[tuple]]) -> None:
    """Drop every entry when the branding tables changed since the last check (at most one per interval)."""
    global _checked_at, _fingerprint
    began = time.monotonic()
    if _checked_at is not None and began - _checked_at < CHECK_SECONDS:
        return
    current = await fingerprint()
    if _checked_at is not None and _checked_at > began:
        return  # a check that began later has already run
    if current != _fingerprint:
        _drop_entries()
    _checked_at, _fingerprint = began, current


async def get_or_load(
    customer_code: Optional[str],
    loader: Callable[[], Awaitable[EffectiveBranding]],
    fingerprint: Optional[Callable[[], Awaitable[tuple]]] = None,
) -> EffectiveBranding:
    """Resolved branding for ``customer_code``, loading it at most once per TTL.

    ``fingerprint`` reads the tables' fingerprint for the change check; without it
    the check is skipped. Hands out a copy, so a caller that mutates its result
    cannot change what the next caller sees.
    """
    if TTL_SECONDS:
        if fingerprint is not None and CHECK_SECONDS:
            await _check(fingerprint)
        entry = _entries.get(customer_code)
        if entry is not None and time.monotonic() - entry[0] < TTL_SECONDS:
            return entry[1].model_copy()

    epoch = _epoch
    branding = await loader()
    if TTL_SECONDS and epoch == _epoch:
        _entries[customer_code] = (time.monotonic(), branding.model_copy())
    return branding


def invalidate_all() -> None:
    """Forget every entry. Call after committing any write to either branding table."""
    _drop_entries()
