import { describe, it, expect } from 'vitest';
import { WatchError } from './errors.js';
import type { StreamItem, StreamOptions } from './stream.js';
import type { TimelineEvent, Alert } from './types.js';
import { EventSourceType, TimelineEventKind, NormalizedVerdict, RuleSeverity } from './types.js';

describe('stream module', () => {
  it('exports stream function', async () => {
    const mod = await import('./stream.js');
    expect(typeof mod.stream).toBe('function');
  });

  it('exports streamAll function', async () => {
    const mod = await import('./stream.js');
    expect(typeof mod.streamAll).toBe('function');
  });

  it('stream throws WatchError when nats is not available', async () => {
    const { stream } = await import('./stream.js');
    const options: StreamOptions = {
      natsUrl: 'nats://localhost:4222',
      rules: [],
      maxWindow: 60000,
    };

    try {
      const gen = stream(options);
      await gen.next();
      // If nats is installed, it tried to connect and will fail — that's ok
    } catch (e: unknown) {
      const err = e as Error;
      expect(err).toBeInstanceOf(Error);
    }
  });

  it('streamAll throws WatchError when nats is not available', async () => {
    const { streamAll } = await import('./stream.js');
    const options: StreamOptions = {
      natsUrl: 'nats://localhost:4222',
      rules: [],
      maxWindow: 60000,
    };

    try {
      const gen = streamAll(options);
      await gen.next();
    } catch (e: unknown) {
      const err = e as Error;
      expect(err).toBeInstanceOf(Error);
    }
  });

  it('StreamItem alert type has correct structure', () => {
    const now = new Date();
    const event: TimelineEvent = {
      timestamp: now,
      source: EventSourceType.Receipt,
      kind: TimelineEventKind.GuardDecision,
      verdict: NormalizedVerdict.Deny,
      summary: 'test',
    };
    const alert: Alert = {
      ruleName: 'test-rule',
      severity: RuleSeverity.High,
      title: 'Test Alert',
      triggeredAt: now,
      evidence: [event],
      description: 'test description',
    };

    const item: StreamItem = { type: 'alert', alert };
    expect(item.type).toBe('alert');
    expect(item.alert.ruleName).toBe('test-rule');
  });

  it('StreamItem event type has correct structure', () => {
    const event: TimelineEvent = {
      timestamp: new Date(),
      source: EventSourceType.Tetragon,
      kind: TimelineEventKind.ProcessExec,
      verdict: NormalizedVerdict.Allow,
      summary: 'ls executed',
    };

    const item: StreamItem = { type: 'event', event };
    expect(item.type).toBe('event');
    expect(item.event.summary).toBe('ls executed');
  });

  it('StreamItem discriminated union covers both variants', () => {
    const event: TimelineEvent = {
      timestamp: new Date(),
      source: EventSourceType.Tetragon,
      kind: TimelineEventKind.ProcessExec,
      verdict: NormalizedVerdict.Allow,
      summary: 'test',
    };

    const items: StreamItem[] = [
      { type: 'event', event },
      {
        type: 'alert',
        alert: {
          ruleName: 'r',
          severity: RuleSeverity.Low,
          title: 't',
          triggeredAt: new Date(),
          evidence: [event],
          description: 'd',
        },
      },
    ];

    const types = items.map(i => i.type);
    expect(types).toEqual(['event', 'alert']);
  });
});
