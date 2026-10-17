"""Resolved Customer Portal branding is cached in-process and dropped on every write.

Run with: cd backend && python -m pytest tests/test_branding_cache.py
"""

import asyncio
import os
from unittest.mock import AsyncMock
from unittest.mock import patch

import pytest

os.environ.setdefault("JWT_SECRET", "test-only-secret-not-the-compromised-default")

import app.customer_portal.routes.branding as branding_routes  # noqa: E402
import app.customer_portal.routes.settings as settings_routes  # noqa: E402
from app.customer_portal.schema.branding import EffectiveBranding  # noqa: E402
from app.customer_portal.services import branding as branding_service  # noqa: E402
from app.customer_portal.services import branding_cache  # noqa: E402


@pytest.fixture(autouse=True)
def _empty_cache():
    branding_cache.invalidate_all()
    yield
    branding_cache.invalidate_all()


def _resolve(customer_code="ACME", title="Acme"):
    """Resolve through the real service with the table reads (and the change check's) mocked; returns (result, global_read)."""
    global_read = AsyncMock(return_value=None)
    override = AsyncMock(return_value=None)
    with patch.object(branding_service, "get_global_settings", global_read), patch.object(
        branding_service,
        "get_branding_override",
        override,
    ), patch.object(branding_service, "build_effective_branding", lambda g, o, c: EffectiveBranding(title=title)), patch.object(
        branding_service,
        "branding_fingerprint",
        AsyncMock(return_value=()),
    ):
        result = asyncio.run(branding_service.resolve_effective_branding(AsyncMock(), customer_code))
    return result, global_read


def test_second_resolution_is_served_from_the_cache():
    _resolve()
    _, second_read = _resolve()
    second_read.assert_not_awaited()


def test_customers_are_cached_separately():
    _resolve("ACME")
    _, other_read = _resolve("OTHER")
    other_read.assert_awaited_once()


def test_invalidate_all_forces_a_reload():
    _resolve(title="Before")
    branding_cache.invalidate_all()
    result, read = _resolve(title="After")
    read.assert_awaited_once()
    assert result.title == "After"


def test_callers_get_a_copy():
    first, _ = _resolve()
    first.title = "mutated by a caller"
    second, _ = _resolve()
    assert second.title == "Acme"


def test_ttl_zero_disables_the_cache():
    with patch.object(branding_cache, "TTL_SECONDS", 0):
        _resolve()
        _, read = _resolve()
    read.assert_awaited_once()


def test_every_write_route_invalidates_after_its_commit():
    # A write path that forgets to invalidate serves the old branding for a whole TTL.
    import inspect

    for route in (
        settings_routes.update_portal_settings,
        settings_routes.patch_portal_settings,
        branding_routes.set_customer_branding,
        branding_routes.remove_customer_branding,
    ):
        source = inspect.getsource(route)
        commit, invalidate = source.find("session.commit()"), source.find("branding_cache.invalidate_all()")
        assert -1 < commit < invalidate, f"{route.__name__} must invalidate the branding cache after committing"


# --- the cross-process change check ---------------------------------------------------


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _resolve_checked(fingerprint_value, title="Acme", customer_code="ACME"):
    """Resolve with a fingerprint callable answering `fingerprint_value`; returns (result, global_read, fingerprint)."""
    fingerprint = AsyncMock(return_value=fingerprint_value)
    global_read = AsyncMock(return_value=None)
    with patch.object(branding_service, "get_global_settings", global_read), patch.object(
        branding_service,
        "get_branding_override",
        AsyncMock(return_value=None),
    ), patch.object(branding_service, "build_effective_branding", lambda g, o, c: EffectiveBranding(title=title)), patch.object(
        branding_service,
        "branding_fingerprint",
        fingerprint,
    ):
        result = asyncio.run(branding_service.resolve_effective_branding(AsyncMock(), customer_code))
    return result, global_read, fingerprint


@pytest.fixture
def clock():
    fake = _Clock()
    with patch.object(branding_cache.time, "monotonic", fake), patch.object(branding_cache, "CHECK_SECONDS", 5.0):
        branding_cache._checked_at = None
        branding_cache._fingerprint = None
        yield fake
    branding_cache._checked_at = None
    branding_cache._fingerprint = None


def test_the_tables_are_checked_at_most_once_per_interval(clock):
    _, _, first = _resolve_checked(("v1",))
    first.assert_awaited_once()
    clock.now += 4
    _, read, second = _resolve_checked(("v1",))
    second.assert_not_awaited()
    read.assert_not_awaited()


def test_a_write_by_another_process_is_seen_after_the_interval(clock):
    _resolve_checked(("v1",), title="Before")
    clock.now += 2
    result, read, _ = _resolve_checked(("v2",), title="After")
    assert result.title == "Before", "within the interval the cached entry is served"
    read.assert_not_awaited()
    clock.now += 5
    result, read, fingerprint = _resolve_checked(("v2",), title="After")
    fingerprint.assert_awaited_once()
    read.assert_awaited_once()
    assert result.title == "After"


def test_an_unchanged_fingerprint_keeps_the_entries(clock):
    _resolve_checked(("v1",))
    clock.now += 6
    _, read, fingerprint = _resolve_checked(("v1",))
    fingerprint.assert_awaited_once()
    read.assert_not_awaited()


def test_a_load_that_raced_an_invalidation_is_not_stored(clock):
    async def racing_load():
        branding_cache.invalidate_all()  # a write committed while this load ran
        return EffectiveBranding(title="Stale")

    asyncio.run(branding_cache.get_or_load("ACME", racing_load, AsyncMock(return_value=("v1",))))
    assert "ACME" not in branding_cache._entries


def test_check_zero_turns_the_check_off(clock):
    with patch.object(branding_cache, "CHECK_SECONDS", 0.0):
        _, _, fingerprint = _resolve_checked(("v1",))
    fingerprint.assert_not_awaited()


def test_the_fingerprint_reads_both_tables_without_the_logos():
    sql = str(branding_service.BRANDING_FINGERPRINT)
    assert "customer_portal_settings" in sql and "customer_portal_branding" in sql
    assert "CRC32(logo_base64)" in sql and "CHAR_LENGTH(logo_base64)" in sql
    assert " logo_base64," not in sql, "the logo itself must not leave MySQL"
