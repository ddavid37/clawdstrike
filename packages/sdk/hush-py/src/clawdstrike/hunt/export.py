"""Export adapters for Hunt SDK -- webhook, Splunk HEC, Elasticsearch, STIX, CSV."""

from __future__ import annotations

import json
import uuid
from typing import Protocol, Union, runtime_checkable

from clawdstrike.hunt.errors import ExportError
from clawdstrike.hunt.types import Alert, IocEntry, IocMatch, TimelineEvent


@runtime_checkable
class ExportAdapter(Protocol):
    """Protocol for export adapters."""

    async def export(self, items: list[Union[Alert, TimelineEvent]]) -> None:
        pass


class WebhookAdapter:
    """Export items via HTTP POST to a webhook URL."""

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.headers = headers or {}

    async def export(self, items: list[Union[Alert, TimelineEvent]]) -> None:
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for WebhookAdapter: pip install httpx"
            )
        body = json.dumps([_item_to_json(item) for item in items])
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.url,
                content=body,
                headers={"Content-Type": "application/json", **self.headers},
            )
            if resp.status_code >= 400:
                raise ExportError(f"Webhook export failed: {resp.status_code}")


class SplunkHECAdapter:
    """Export items to Splunk via the HTTP Event Collector."""

    def __init__(self, url: str, token: str, index: str | None = None) -> None:
        self.url = url
        self.token = token
        self.index = index

    async def export(self, items: list[Union[Alert, TimelineEvent]]) -> None:
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for SplunkHECAdapter: pip install httpx"
            )
        events: list[str] = []
        for item in items:
            data = _item_to_json(item)
            event: dict = {"event": data}
            if self.index:
                event["index"] = self.index
            events.append(json.dumps(event))
        body = "\n".join(events)
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.url,
                content=body,
                headers={
                    "Authorization": f"Splunk {self.token}",
                    "Content-Type": "application/json",
                },
            )
            if resp.status_code >= 400:
                raise ExportError(f"Splunk HEC export failed: {resp.status_code}")


class ElasticAdapter:
    """Export items to Elasticsearch via the _bulk API."""

    def __init__(self, url: str, index: str, api_key: str | None = None) -> None:
        self.url = url
        self.index = index
        self.api_key = api_key

    async def export(self, items: list[Union[Alert, TimelineEvent]]) -> None:
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for ElasticAdapter: pip install httpx"
            )
        lines: list[str] = []
        for item in items:
            lines.append(json.dumps({"index": {"_index": self.index}}))
            lines.append(json.dumps(_item_to_json(item)))
        body = "\n".join(lines) + "\n"
        headers: dict[str, str] = {"Content-Type": "application/x-ndjson"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.url}/_bulk", content=body, headers=headers
            )
            if resp.status_code >= 400:
                raise ExportError(
                    f"Elasticsearch export failed: {resp.status_code}"
                )


def to_stix(
    alerts: list[Alert], ioc_matches: list[IocMatch] | None = None
) -> dict:
    """Convert alerts and optional IOC matches to a STIX 2.1 bundle."""
    objects: list[dict] = []
    for alert in alerts:
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": alert.triggered_at.isoformat(),
                "modified": alert.triggered_at.isoformat(),
                "name": alert.title,
                "description": alert.description,
                "pattern_type": "clawdstrike",
                "pattern": f"[alert:rule_name = '{_escape_stix_value(alert.rule_name)}']",
                "valid_from": alert.triggered_at.isoformat(),
                "labels": [alert.severity.value],
            }
        )
    if ioc_matches:
        for match in ioc_matches:
            for ioc in match.matched_iocs:
                objects.append(
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": f"indicator--{uuid.uuid4()}",
                        "created": match.event.timestamp.isoformat(),
                        "modified": match.event.timestamp.isoformat(),
                        "name": f"IOC: {ioc.indicator}",
                        "description": ioc.description
                        or f"IOC match: {ioc.indicator}",
                        "pattern_type": "stix",
                        "pattern": _ioc_to_stix_pattern(ioc),
                        "valid_from": match.event.timestamp.isoformat(),
                    }
                )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def to_csv(items: list[Union[Alert, TimelineEvent]]) -> str:
    """Convert items to CSV string. Auto-detects Alert vs TimelineEvent."""
    if not items:
        return ""
    first = items[0]
    if isinstance(first, Alert):
        headers = [
            "rule_name",
            "severity",
            "title",
            "triggered_at",
            "description",
            "evidence_count",
        ]
        rows = [
            ",".join(
                [
                    _csv_escape(a.rule_name),  # type: ignore[union-attr]
                    _csv_escape(a.severity.value),  # type: ignore[union-attr]
                    _csv_escape(a.title),  # type: ignore[union-attr]
                    _csv_escape(a.triggered_at.isoformat()),  # type: ignore[union-attr]
                    _csv_escape(a.description),  # type: ignore[union-attr]
                    str(len(a.evidence)),  # type: ignore[union-attr]
                ]
            )
            for a in items
        ]
        return "\n".join([",".join(headers)] + rows)
    else:
        headers = [
            "timestamp",
            "source",
            "kind",
            "verdict",
            "summary",
            "process",
            "action_type",
        ]
        rows = [
            ",".join(
                [
                    _csv_escape(e.timestamp.isoformat()),  # type: ignore[union-attr]
                    _csv_escape(e.source.value),  # type: ignore[union-attr]
                    _csv_escape(e.kind.value),  # type: ignore[union-attr]
                    _csv_escape(e.verdict.value),  # type: ignore[union-attr]
                    _csv_escape(e.summary),  # type: ignore[union-attr]
                    _csv_escape(e.process or ""),  # type: ignore[union-attr]
                    _csv_escape(e.action_type or ""),  # type: ignore[union-attr]
                ]
            )
            for e in items
        ]
        return "\n".join([",".join(headers)] + rows)


def _item_to_json(item: Union[Alert, TimelineEvent]) -> dict:
    if isinstance(item, Alert):
        return {
            "type": "alert",
            "rule_name": item.rule_name,
            "severity": item.severity.value,
            "title": item.title,
            "triggered_at": item.triggered_at.isoformat(),
            "description": item.description,
            "evidence_count": len(item.evidence),
        }
    return {
        "type": "event",
        "timestamp": item.timestamp.isoformat(),
        "source": item.source.value,
        "kind": item.kind.value,
        "verdict": item.verdict.value,
        "summary": item.summary,
        "process": item.process,
        "action_type": item.action_type,
    }


def _escape_stix_value(value: str) -> str:
    """Escape backslashes, single quotes, and brackets for STIX patterns."""
    return value.replace("\\", "\\\\").replace("'", "\\'").replace("]", "\\]")


def _ioc_to_stix_pattern(ioc: IocEntry) -> str:
    ioc_type_val = ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type)
    escaped = _escape_stix_value(ioc.indicator)
    mapping = {
        "sha256": f"[file:hashes.'SHA-256' = '{escaped}']",
        "sha1": f"[file:hashes.'SHA-1' = '{escaped}']",
        "md5": f"[file:hashes.MD5 = '{escaped}']",
        "domain": f"[domain-name:value = '{escaped}']",
        "ipv4": f"[ipv4-addr:value = '{escaped}']",
        "ipv6": f"[ipv6-addr:value = '{escaped}']",
        "url": f"[url:value = '{escaped}']",
    }
    return mapping.get(ioc_type_val, f"[x-clawdstrike:value = '{escaped}']")


def _csv_escape(value: str) -> str:
    if "," in value or '"' in value or "\n" in value:
        return '"' + value.replace('"', '""') + '"'
    return value


__all__ = [
    "ExportAdapter",
    "WebhookAdapter",
    "SplunkHECAdapter",
    "ElasticAdapter",
    "to_stix",
    "to_csv",
]
