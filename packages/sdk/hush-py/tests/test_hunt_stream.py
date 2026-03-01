"""Tests for clawdstrike.hunt.stream module."""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

import pytest

from clawdstrike.hunt.errors import WatchError
from clawdstrike.hunt.stream import StreamAlertItem, StreamEventItem, stream, stream_all
from clawdstrike.hunt.types import (
    Alert,
    EventSourceType,
    NormalizedVerdict,
    RuleSeverity,
    TimelineEvent,
    TimelineEventKind,
    WatchConfig,
)


def _make_event() -> TimelineEvent:
    return TimelineEvent(
        timestamp=datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        source=EventSourceType.TETRAGON,
        kind=TimelineEventKind.PROCESS_EXEC,
        verdict=NormalizedVerdict.ALLOW,
        summary="ls executed",
    )


def _make_alert() -> Alert:
    return Alert(
        rule_name="test-rule",
        severity=RuleSeverity.HIGH,
        title="Test Alert",
        triggered_at=datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        evidence=(_make_event(),),
        description="test description",
    )


def _make_config() -> WatchConfig:
    return WatchConfig(
        nats_url="nats://localhost:4222",
        rules=(),
        max_window=timedelta(seconds=60),
    )


class TestStream:
    """Tests for the stream function."""

    def test_import_succeeds(self) -> None:
        """Verify the module and function are importable."""
        assert callable(stream)

    @pytest.mark.asyncio
    async def test_raises_without_nats(self) -> None:
        """stream should raise WatchError if nats-py is not installed."""
        try:
            import nats  # noqa: F401

            pytest.skip("nats-py is installed; cannot test missing-package path")
        except ImportError:
            pass

        config = _make_config()
        with pytest.raises(WatchError, match="nats-py"):
            async for _ in stream(config):
                pass

    def test_stream_is_async_generator_function(self) -> None:
        """stream should be an async generator function."""
        assert inspect.isasyncgenfunction(stream)


class TestStreamAll:
    """Tests for the stream_all function."""

    def test_import_succeeds(self) -> None:
        """Verify the module and function are importable."""
        assert callable(stream_all)

    @pytest.mark.asyncio
    async def test_raises_without_nats(self) -> None:
        """stream_all should raise WatchError if nats-py is not installed."""
        try:
            import nats  # noqa: F401

            pytest.skip("nats-py is installed; cannot test missing-package path")
        except ImportError:
            pass

        config = _make_config()
        with pytest.raises(WatchError, match="nats-py"):
            async for _ in stream_all(config):
                pass

    def test_stream_all_is_async_generator_function(self) -> None:
        """stream_all should be an async generator function."""
        assert inspect.isasyncgenfunction(stream_all)


class TestStreamItems:
    """Tests for StreamAlertItem and StreamEventItem dataclasses."""

    def test_stream_alert_item_construction(self) -> None:
        alert = _make_alert()
        item = StreamAlertItem(type="alert", alert=alert)
        assert item.type == "alert"
        assert item.alert.rule_name == "test-rule"

    def test_stream_event_item_construction(self) -> None:
        event = _make_event()
        item = StreamEventItem(type="event", event=event)
        assert item.type == "event"
        assert item.event.summary == "ls executed"

    def test_stream_items_are_frozen(self) -> None:
        event = _make_event()
        item = StreamEventItem(type="event", event=event)
        with pytest.raises(AttributeError):
            item.type = "alert"  # type: ignore[misc]
