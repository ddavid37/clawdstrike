export {
  HuntError,
  QueryError,
  ParseError,
  IoError,
  CorrelationError,
  IocError,
  WatchError,
  ReportError,
} from './errors.js';

export {
  EventSourceType,
  TimelineEventKind,
  NormalizedVerdict,
  QueryVerdict,
  RuleSeverity,
  IocType,
} from './types.js';

export type {
  TimelineEvent,
  HuntQuery,
  RuleCondition,
  RuleOutput,
  CorrelationRule,
  Alert,
  IocEntry,
  IocMatch,
  EvidenceItem,
  HuntReport,
  WatchConfig,
  WatchStats,
} from './types.js';

export {
  matchesQuery,
  parseQueryVerdict,
} from './query.js';

export { parseEnvelope, mergeTimeline } from './timeline.js';

export { defaultLocalDirs, queryLocalFiles, hunt } from './local.js';
export type { HuntOptions } from './local.js';

// Correlate
export {
  CorrelationEngine,
  correlate,
  detectIocType,
  IocDatabase,
  loadRulesFromFiles,
  parseRule,
  validateRule,
} from './correlate/index.js';

// Report
export {
  buildReport,
  evidenceFromAlert,
  evidenceFromEvents,
  evidenceFromIocMatches,
  collectEvidence,
  signReport,
  verifyReport,
} from './report.js';

// Watch
export { runWatch } from './watch.js';

// Testing
export { testRule, event } from './testing.js';
export type { TestResult, TestRuleOptions } from './testing.js';

// Replay
export { replay } from './replay.js';
export type { ReplayResult, ReplayOptions } from './replay.js';
