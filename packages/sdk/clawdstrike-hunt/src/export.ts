/**
 * Export adapters — webhook, Splunk HEC, Elasticsearch, STIX 2.1, and CSV.
 */

import { ExportError } from './errors.js';
import type { Alert, TimelineEvent, IocMatch, IocEntry } from './types.js';

export interface ExportAdapter {
  export(items: (Alert | TimelineEvent)[]): Promise<void>;
}

export class WebhookAdapter implements ExportAdapter {
  private url: string;
  private headers: Record<string, string>;

  constructor(url: string, headers?: Record<string, string>) {
    this.url = url;
    this.headers = headers ?? {};
  }

  async export(items: (Alert | TimelineEvent)[]): Promise<void> {
    const body = JSON.stringify(items.map(itemToJSON));
    const response = await fetch(this.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...this.headers },
      body,
    });
    if (!response.ok) {
      throw new ExportError(
        `Webhook export failed: ${response.status} ${response.statusText}`,
      );
    }
  }
}

export class SplunkHECAdapter implements ExportAdapter {
  private url: string;
  private token: string;
  private index?: string;

  constructor(url: string, token: string, index?: string) {
    this.url = url;
    this.token = token;
    this.index = index;
  }

  async export(items: (Alert | TimelineEvent)[]): Promise<void> {
    const events = items.map((item) => {
      const data = itemToJSON(item);
      const event: Record<string, unknown> = { event: data };
      if (this.index) event.index = this.index;
      return JSON.stringify(event);
    });
    const body = events.join('\n');

    const response = await fetch(this.url, {
      method: 'POST',
      headers: {
        Authorization: `Splunk ${this.token}`,
        'Content-Type': 'application/json',
      },
      body,
    });
    if (!response.ok) {
      throw new ExportError(
        `Splunk HEC export failed: ${response.status} ${response.statusText}`,
      );
    }
  }
}

export class ElasticAdapter implements ExportAdapter {
  private url: string;
  private index: string;
  private apiKey?: string;

  constructor(url: string, index: string, apiKey?: string) {
    this.url = url;
    this.index = index;
    this.apiKey = apiKey;
  }

  async export(items: (Alert | TimelineEvent)[]): Promise<void> {
    const lines: string[] = [];
    for (const item of items) {
      lines.push(JSON.stringify({ index: { _index: this.index } }));
      lines.push(JSON.stringify(itemToJSON(item)));
    }
    const body = lines.join('\n') + '\n';

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-ndjson',
    };
    if (this.apiKey) {
      headers['Authorization'] = `ApiKey ${this.apiKey}`;
    }

    const response = await fetch(`${this.url}/_bulk`, {
      method: 'POST',
      headers,
      body,
    });
    if (!response.ok) {
      throw new ExportError(
        `Elasticsearch export failed: ${response.status} ${response.statusText}`,
      );
    }
  }
}

/**
 * Convert alerts and optional IOC matches to a STIX 2.1 bundle.
 */
export function toStix(
  alerts: Alert[],
  iocMatches?: IocMatch[],
): Record<string, unknown> {
  const objects: Record<string, unknown>[] = [];

  for (const alert of alerts) {
    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${generateId()}`,
      created: alert.triggeredAt.toISOString(),
      modified: alert.triggeredAt.toISOString(),
      name: alert.title,
      description: alert.description,
      pattern_type: 'clawdstrike',
      pattern: `[alert:rule_name = '${escapeStixValue(alert.ruleName)}']`,
      valid_from: alert.triggeredAt.toISOString(),
      labels: [alert.severity],
    });
  }

  if (iocMatches) {
    for (const match of iocMatches) {
      for (const ioc of match.matchedIocs) {
        objects.push({
          type: 'indicator',
          spec_version: '2.1',
          id: `indicator--${generateId()}`,
          created: match.event.timestamp.toISOString(),
          modified: match.event.timestamp.toISOString(),
          name: `IOC: ${ioc.indicator}`,
          description: ioc.description ?? `IOC match: ${ioc.indicator}`,
          pattern_type: 'stix',
          pattern: iocToStixPattern(ioc),
          valid_from: match.event.timestamp.toISOString(),
        });
      }
    }
  }

  return {
    type: 'bundle',
    id: `bundle--${generateId()}`,
    objects,
  };
}

/**
 * Convert items to CSV string. Auto-detects Alert vs TimelineEvent.
 */
export function toCSV(items: (Alert | TimelineEvent)[]): string {
  if (items.length === 0) return '';

  const first = items[0];
  if (isAlert(first)) {
    const headers = [
      'ruleName',
      'severity',
      'title',
      'triggeredAt',
      'description',
      'evidenceCount',
    ];
    const rows = (items as Alert[]).map((a) =>
      [
        a.ruleName,
        a.severity,
        a.title,
        a.triggeredAt.toISOString(),
        a.description,
        String(a.evidence.length),
      ]
        .map(csvEscape)
        .join(','),
    );
    return [headers.join(','), ...rows].join('\n');
  } else {
    const headers = [
      'timestamp',
      'source',
      'kind',
      'verdict',
      'summary',
      'process',
      'actionType',
    ];
    const rows = (items as TimelineEvent[]).map((e) =>
      [
        e.timestamp.toISOString(),
        e.source,
        e.kind,
        e.verdict,
        e.summary,
        e.process ?? '',
        e.actionType ?? '',
      ]
        .map(csvEscape)
        .join(','),
    );
    return [headers.join(','), ...rows].join('\n');
  }
}

function isAlert(item: unknown): item is Alert {
  return (
    typeof item === 'object' &&
    item !== null &&
    'ruleName' in item &&
    'triggeredAt' in item
  );
}

function itemToJSON(item: Alert | TimelineEvent): Record<string, unknown> {
  if (isAlert(item)) {
    return {
      type: 'alert',
      ruleName: item.ruleName,
      severity: item.severity,
      title: item.title,
      triggeredAt: item.triggeredAt.toISOString(),
      description: item.description,
      evidenceCount: item.evidence.length,
    };
  }
  return {
    type: 'event',
    timestamp: item.timestamp.toISOString(),
    source: item.source,
    kind: item.kind,
    verdict: item.verdict,
    summary: item.summary,
    process: item.process,
    actionType: item.actionType,
  };
}

function csvEscape(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return '"' + value.replace(/"/g, '""') + '"';
  }
  return value;
}

function escapeStixValue(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function iocToStixPattern(ioc: IocEntry): string {
  const v = escapeStixValue(ioc.indicator);
  switch (ioc.iocType) {
    case 'sha256':
      return `[file:hashes.'SHA-256' = '${v}']`;
    case 'sha1':
      return `[file:hashes.'SHA-1' = '${v}']`;
    case 'md5':
      return `[file:hashes.MD5 = '${v}']`;
    case 'domain':
      return `[domain-name:value = '${v}']`;
    case 'ipv4':
      return `[ipv4-addr:value = '${v}']`;
    case 'ipv6':
      return `[ipv6-addr:value = '${v}']`;
    case 'url':
      return `[url:value = '${v}']`;
    default:
      return `[x-clawdstrike:value = '${v}']`;
  }
}

function generateId(): string {
  // Use crypto.randomUUID() when available, fall back to random hex.
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
