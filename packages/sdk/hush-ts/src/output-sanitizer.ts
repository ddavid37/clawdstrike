import { getWasmModule } from "./crypto/backend.js";
import { camelToSnake, toSnakeCaseKeys } from "./case-convert.js";

export type SensitiveCategory = "secret" | "pii" | "internal" | "custom";

export type RedactionStrategy = "full" | "partial" | "type_label" | "hash" | "none";

export type DetectorType = "pattern" | "entropy" | "denylist" | "entity";

export interface Span {
  start: number;
  end: number;
}

export interface SensitiveDataFinding {
  id: string;
  category: SensitiveCategory;
  dataType: string;
  confidence: number;
  span: Span;
  preview: string;
  detector: DetectorType;
  recommendedAction: RedactionStrategy;
}

export interface Redaction {
  findingId: string;
  strategy: RedactionStrategy;
  originalSpan: Span;
  replacement: string;
}

export interface ProcessingStats {
  inputLength: number;
  outputLength: number;
  findingsCount: number;
  redactionsCount: number;
  processingTimeMs: number;
}

export interface SanitizationResult {
  sanitized: string;
  wasRedacted: boolean;
  findings: SensitiveDataFinding[];
  redactions: Redaction[];
  stats: ProcessingStats;
}

export interface AllowlistConfig {
  exact?: string[];
  patterns?: Array<string | RegExp>;
  allowTestCredentials?: boolean;
}

export interface DenylistConfig {
  patterns?: Array<string | RegExp>;
}

export interface EntropyConfig {
  enabled?: boolean;
  threshold?: number; // bits/char
  minTokenLen?: number;
}

export interface StreamingConfig {
  enabled?: boolean;
  bufferSize?: number;
  carryBytes?: number;
}

export interface OutputSanitizerConfig {
  categories?: {
    secrets?: boolean;
    pii?: boolean;
    internal?: boolean;
  };
  allowlist?: AllowlistConfig;
  denylist?: DenylistConfig;
  entropy?: EntropyConfig;
  streaming?: StreamingConfig;
  maxInputBytes?: number;
}

export interface EntityFinding {
  entityType: string;
  confidence: number;
  span: Span;
}

export interface EntityRecognizer {
  detect(text: string): EntityFinding[];
}

function prepareConfig(config: OutputSanitizerConfig): unknown {
  const prepared: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(config)) {
    const snakeKey = camelToSnake(k);
    if ((k === "allowlist" || k === "denylist") && v && typeof v === "object") {
      const section = { ...(v as Record<string, unknown>) };
      if (Array.isArray(section.patterns)) {
        section.patterns = section.patterns.map((p: unknown) =>
          p instanceof RegExp ? p.source : p,
        );
      }
      prepared[snakeKey] = toSnakeCaseKeys(section);
    } else if (v && typeof v === "object" && !Array.isArray(v)) {
      prepared[snakeKey] = toSnakeCaseKeys(v);
    } else {
      prepared[snakeKey] = v;
    }
  }
  return prepared;
}

export class OutputSanitizer {
  // biome-ignore lint/suspicious/noExplicitAny: WASM instance type is dynamic
  private readonly inner: any;

  constructor(config?: OutputSanitizerConfig) {
    const wasm = getWasmModule();
    if (!wasm?.WasmOutputSanitizer) {
      throw new Error(
        "WASM not initialized. Call initWasm() before using OutputSanitizer.",
      );
    }
    this.inner = new wasm.WasmOutputSanitizer(
      config ? JSON.stringify(prepareConfig(config)) : undefined,
    );
  }

  sanitize(text: string): SanitizationResult {
    return JSON.parse(this.inner.sanitize(text));
  }

  createStream(config?: StreamingConfig): SanitizationStream {
    return new SanitizationStream(this, config);
  }
}

export class SanitizationStream {
  private sanitizer: OutputSanitizer;
  private buffer: string = "";
  private bufferSize: number;
  private carryBytes: number;

  constructor(sanitizer: OutputSanitizer, config?: StreamingConfig) {
    this.sanitizer = sanitizer;
    this.bufferSize = config?.bufferSize ?? 50_000;
    // Carry the last N bytes from each flush into the next buffer so secrets
    // that span chunk boundaries are still detected.
    this.carryBytes = config?.carryBytes ?? 128;
  }

  write(chunk: string): SanitizationResult | null {
    this.buffer += chunk;
    if (this.buffer.length >= this.bufferSize) {
      return this.flush();
    }
    return null;
  }

  flush(): SanitizationResult {
    const result = this.sanitizer.sanitize(this.buffer);
    // Keep the tail so cross-boundary secrets get caught on the next pass.
    if (this.carryBytes > 0 && this.buffer.length > this.carryBytes) {
      this.buffer = this.buffer.slice(-this.carryBytes);
    } else {
      this.buffer = "";
    }
    return result;
  }
}
