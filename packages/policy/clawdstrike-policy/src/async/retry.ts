import type { RetryConfig, RetryOptions } from "./types.js";
import { sleep } from "./util.js";

export async function retry<T>(
  cfg: RetryConfig,
  fn: (attempt: number, signal?: AbortSignal) => Promise<T>,
  signal?: AbortSignal,
  options: RetryOptions = {},
): Promise<T> {
  const shouldRetry = options.shouldRetry ?? (() => true);
  const random = options.random ?? Math.random;

  for (let attempt = 0; ; attempt++) {
    try {
      return await fn(attempt, signal);
    } catch (err) {
      if (attempt >= cfg.maxRetries || !shouldRetry(err, attempt)) {
        throw err;
      }
      const backoffMs = backoffForAttempt(cfg, attempt, random);
      await sleep(backoffMs, signal);
    }
  }
}

export function backoffForAttempt(
  cfg: RetryConfig,
  attempt: number,
  random: () => number = Math.random,
): number {
  const base = Math.max(0, cfg.initialBackoffMs);
  const mult = Math.max(1, cfg.multiplier);
  const scaled = base * Math.pow(mult, attempt);
  const cap = Math.max(cfg.maxBackoffMs, base);
  const capped = Math.min(scaled, cap);

  // Apply bounded +/-20% jitter to avoid synchronized retries across agents.
  const jitterRange = capped * 0.2;
  const jitter = (random() * 2 - 1) * jitterRange;
  const withJitter = capped + jitter;
  return Math.max(0, Math.round(withJitter));
}
