"""Clawdstrike Hunt — threat hunting and timeline analysis."""

from __future__ import annotations

from clawdstrike.hunt.errors import (
    CorrelationError,
    HuntAlertError,
    HuntError,
    IocError,
    IoError,
    ParseError,
    PlaybookError,
    QueryError,
    ReportError,
    WatchError,
)
from clawdstrike.hunt.correlate import (
    CorrelationEngine,
    correlate,
    load_rules_from_files,
    parse_rule,
    validate_rule,
)
from clawdstrike.hunt.ioc import (
    IocDatabase,
    detect_ioc_type,
)
from clawdstrike.hunt.local import default_local_dirs, hunt, query_local_files
from clawdstrike.hunt.query import (
    matches_query,
    parse_query_verdict,
)
from clawdstrike.hunt.report import (
    build_report,
    collect_evidence,
    evidence_from_alert,
    evidence_from_events,
    evidence_from_ioc_matches,
    sign_report,
    verify_report,
)
from clawdstrike.hunt.testing import TestResult, event, test_rule
from clawdstrike.hunt.replay import ReplayResult, replay
from clawdstrike.hunt.decorator import guarded
from clawdstrike.hunt.dataframe import (
    alerts_to_dataframe,
    display_timeline,
    to_dataframe,
    to_polars,
)
from clawdstrike.hunt.playbook import Playbook, PlaybookResult
from clawdstrike.hunt.mitre import (
    MitreTechnique,
    coverage_matrix,
    map_alert_to_mitre,
    map_event_to_mitre,
)
from clawdstrike.hunt.anomaly import (
    Baseline,
    BaselineData,
    ScoredEvent,
    score_anomalies,
)
from clawdstrike.hunt.timeline import merge_timeline, parse_envelope
from clawdstrike.hunt.types import (
    Alert,
    CorrelationRule,
    EventSourceType,
    EvidenceItem,
    HuntQuery,
    HuntReport,
    IocEntry,
    IocMatch,
    IocType,
    NormalizedVerdict,
    QueryVerdict,
    RuleCondition,
    RuleOutput,
    RuleSeverity,
    TimelineEvent,
    TimelineEventKind,
    WatchConfig,
    WatchStats,
)

__all__ = [
    # errors
    "HuntError",
    "QueryError",
    "ParseError",
    "IoError",
    "CorrelationError",
    "IocError",
    "WatchError",
    "ReportError",
    # types / enums
    "EventSourceType",
    "TimelineEventKind",
    "NormalizedVerdict",
    "QueryVerdict",
    "RuleSeverity",
    "IocType",
    "TimelineEvent",
    "HuntQuery",
    "RuleCondition",
    "RuleOutput",
    "CorrelationRule",
    "Alert",
    "IocEntry",
    "IocMatch",
    "EvidenceItem",
    "HuntReport",
    "WatchConfig",
    "WatchStats",
    # query
    "parse_query_verdict",
    "matches_query",
    # timeline
    "parse_envelope",
    "merge_timeline",
    # local
    "default_local_dirs",
    "query_local_files",
    "hunt",
    # correlate
    "CorrelationEngine",
    "correlate",
    "parse_rule",
    "validate_rule",
    "load_rules_from_files",
    # ioc
    "IocDatabase",
    "detect_ioc_type",
    # report
    "build_report",
    "sign_report",
    "verify_report",
    "evidence_from_alert",
    "evidence_from_events",
    "evidence_from_ioc_matches",
    "collect_evidence",
    # testing
    "test_rule",
    "event",
    "TestResult",
    # replay
    "replay",
    "ReplayResult",
    # decorator
    "guarded",
    "HuntAlertError",
    "PlaybookError",
    # dataframe
    "to_dataframe",
    "to_polars",
    "alerts_to_dataframe",
    "display_timeline",
    # playbook
    "Playbook",
    "PlaybookResult",
    # mitre
    "MitreTechnique",
    "map_event_to_mitre",
    "map_alert_to_mitre",
    "coverage_matrix",
    # anomaly
    "ScoredEvent",
    "BaselineData",
    "Baseline",
    "score_anomalies",
    # watch (lazy import — requires nats-py)
    "run_watch",
]


def __getattr__(name: str):  # type: ignore[no-untyped-def]
    """Lazy import for run_watch to avoid import error when nats-py is absent."""
    if name == "run_watch":
        from clawdstrike.hunt.watch import run_watch

        return run_watch
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
