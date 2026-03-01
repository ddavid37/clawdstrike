"""Tests for clawdstrike.hunt.export module."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clawdstrike.hunt.errors import ExportError
from clawdstrike.hunt.export import (
    ElasticAdapter,
    SplunkHECAdapter,
    WebhookAdapter,
    to_csv,
    to_stix,
)
from clawdstrike.hunt.types import (
    Alert,
    EventSourceType,
    IocEntry,
    IocMatch,
    IocType,
    NormalizedVerdict,
    RuleSeverity,
    TimelineEvent,
    TimelineEventKind,
)


def _make_event(**kwargs) -> TimelineEvent:
    defaults = dict(
        timestamp=datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        source=EventSourceType.TETRAGON,
        kind=TimelineEventKind.PROCESS_EXEC,
        verdict=NormalizedVerdict.ALLOW,
        summary="ls executed",
    )
    defaults.update(kwargs)
    return TimelineEvent(**defaults)


def _make_alert(**kwargs) -> Alert:
    defaults = dict(
        rule_name="test-rule",
        severity=RuleSeverity.HIGH,
        title="Test Alert",
        triggered_at=datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        evidence=(_make_event(),),
        description="test description",
    )
    defaults.update(kwargs)
    return Alert(**defaults)


def _mock_httpx_response(status_code: int = 200):
    """Create a mock httpx response."""
    resp = MagicMock()
    resp.status_code = status_code
    return resp


def _make_mock_client(status_code: int = 200) -> AsyncMock:
    """Create a mock httpx.AsyncClient context manager."""
    mock_resp = _mock_httpx_response(status_code)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


class TestWebhookAdapter:
    """Tests for WebhookAdapter."""

    def test_construction(self) -> None:
        adapter = WebhookAdapter("https://example.com/hook", {"X-Api-Key": "secret"})
        assert adapter.url == "https://example.com/hook"
        assert adapter.headers == {"X-Api-Key": "secret"}

    @pytest.mark.asyncio
    async def test_export_posts_json(self) -> None:
        mock_client = _make_mock_client(200)

        with patch("httpx.AsyncClient", return_value=mock_client):
            adapter = WebhookAdapter("https://example.com/hook")
            await adapter.export([_make_alert()])

            mock_client.post.assert_called_once()
            call_kwargs = mock_client.post.call_args
            assert call_kwargs[0][0] == "https://example.com/hook"
            assert "application/json" in call_kwargs[1]["headers"]["Content-Type"]

    @pytest.mark.asyncio
    async def test_export_raises_on_error(self) -> None:
        mock_client = _make_mock_client(500)

        with patch("httpx.AsyncClient", return_value=mock_client):
            adapter = WebhookAdapter("https://example.com/hook")
            with pytest.raises(ExportError, match="Webhook export failed"):
                await adapter.export([_make_event()])


class TestSplunkHECAdapter:
    """Tests for SplunkHECAdapter."""

    @pytest.mark.asyncio
    async def test_auth_header_format(self) -> None:
        mock_client = _make_mock_client(200)

        with patch("httpx.AsyncClient", return_value=mock_client):
            adapter = SplunkHECAdapter(
                "https://splunk.example.com:8088/services/collector", "my-token"
            )
            await adapter.export([_make_event()])

            call_kwargs = mock_client.post.call_args
            assert call_kwargs[1]["headers"]["Authorization"] == "Splunk my-token"

    @pytest.mark.asyncio
    async def test_hec_event_format_with_index(self) -> None:
        mock_client = _make_mock_client(200)

        with patch("httpx.AsyncClient", return_value=mock_client):
            adapter = SplunkHECAdapter(
                "https://splunk.example.com:8088/services/collector",
                "my-token",
                "security",
            )
            await adapter.export([_make_event()])

            call_kwargs = mock_client.post.call_args
            body = call_kwargs[1]["content"]
            parsed = json.loads(body.split("\n")[0])
            assert "event" in parsed
            assert parsed["index"] == "security"


class TestElasticAdapter:
    """Tests for ElasticAdapter."""

    @pytest.mark.asyncio
    async def test_bulk_ndjson_format(self) -> None:
        mock_client = _make_mock_client(200)

        with patch("httpx.AsyncClient", return_value=mock_client):
            adapter = ElasticAdapter(
                "https://elastic.example.com:9200", "hunt-events"
            )
            await adapter.export([_make_event()])

            call_kwargs = mock_client.post.call_args
            assert call_kwargs[0][0] == "https://elastic.example.com:9200/_bulk"
            assert call_kwargs[1]["headers"]["Content-Type"] == "application/x-ndjson"

            lines = call_kwargs[1]["content"].strip().split("\n")
            assert len(lines) == 2
            action = json.loads(lines[0])
            assert action["index"]["_index"] == "hunt-events"

    @pytest.mark.asyncio
    async def test_auth_header(self) -> None:
        mock_client = _make_mock_client(200)

        with patch("httpx.AsyncClient", return_value=mock_client):
            adapter = ElasticAdapter(
                "https://elastic.example.com:9200", "hunt-events", "my-api-key"
            )
            await adapter.export([_make_event()])

            call_kwargs = mock_client.post.call_args
            assert call_kwargs[1]["headers"]["Authorization"] == "ApiKey my-api-key"

    @pytest.mark.asyncio
    async def test_raises_on_error(self) -> None:
        mock_client = _make_mock_client(403)

        with patch("httpx.AsyncClient", return_value=mock_client):
            adapter = ElasticAdapter(
                "https://elastic.example.com:9200", "hunt-events"
            )
            with pytest.raises(ExportError, match="Elasticsearch export failed"):
                await adapter.export([_make_alert()])


class TestToStix:
    """Tests for to_stix function."""

    def test_valid_bundle_from_alerts(self) -> None:
        bundle = to_stix([_make_alert()])
        assert bundle["type"] == "bundle"
        assert str(bundle["id"]).startswith("bundle--")
        objects = bundle["objects"]
        assert len(objects) == 1
        assert objects[0]["type"] == "indicator"
        assert objects[0]["spec_version"] == "2.1"
        assert objects[0]["pattern_type"] == "clawdstrike"
        assert objects[0]["name"] == "Test Alert"

    def test_includes_ioc_matches(self) -> None:
        ioc_entry = IocEntry(
            indicator="evil.example.com",
            ioc_type=IocType.DOMAIN,
            description="Known C2 domain",
        )
        ioc_match = IocMatch(
            event=_make_event(),
            matched_iocs=(ioc_entry,),
            match_field="summary",
        )

        bundle = to_stix([_make_alert()], [ioc_match])
        objects = bundle["objects"]
        assert len(objects) == 2
        assert objects[1]["pattern_type"] == "stix"
        assert "domain-name:value" in objects[1]["pattern"]

    def test_empty_alerts_returns_empty_objects(self) -> None:
        bundle = to_stix([])
        assert bundle["objects"] == []


class TestToCSV:
    """Tests for to_csv function."""

    def test_events_csv(self) -> None:
        csv = to_csv([_make_event(), _make_event(summary="cat /etc/passwd")])
        lines = csv.split("\n")
        assert len(lines) == 3
        assert lines[0] == "timestamp,source,kind,verdict,summary,process,action_type"
        assert "ls executed" in lines[1]
        assert "cat /etc/passwd" in lines[2]

    def test_alerts_csv(self) -> None:
        csv = to_csv([_make_alert()])
        lines = csv.split("\n")
        assert len(lines) == 2
        assert lines[0] == "rule_name,severity,title,triggered_at,description,evidence_count"
        assert "test-rule" in lines[1]

    def test_empty_returns_empty_string(self) -> None:
        assert to_csv([]) == ""
