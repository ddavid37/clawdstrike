import {
  AsyncGuardError,
  type HttpClient,
  type HttpRequestPolicy,
  type HttpResponse,
} from "./types.js";

export class FetchHttpClient implements HttpClient {
  async requestJson(
    guard: string,
    method: string,
    url: string,
    headers: Record<string, string>,
    body: unknown | null,
    policy: HttpRequestPolicy,
    signal?: AbortSignal,
  ): Promise<HttpResponse> {
    const parsed = new URL(url);
    enforceUrlPolicy(parsed, method, policy);

    const redactedUrl = redactUrl(parsed);

    const maxRequestSizeBytes = policy.maxRequestSizeBytes ?? 1_048_576;
    const maxResponseSizeBytes = policy.maxResponseSizeBytes ?? 10_485_760;
    const timeoutMs = policy.timeoutMs ?? 30_000;

    const start = Date.now();

    let requestBody: string | undefined;
    const requestHeaders: Record<string, string> = { ...headers };
    if (body !== null && body !== undefined) {
      requestBody = JSON.stringify(body);
      if (Buffer.byteLength(requestBody, "utf8") > maxRequestSizeBytes) {
        throw new Error(`request too large`);
      }
      if (!Object.keys(requestHeaders).some((k) => k.toLowerCase() === "content-type")) {
        requestHeaders["content-type"] = "application/json";
      }
    }

    const timeoutController = new AbortController();
    const controller = signal ? anySignal([signal, timeoutController.signal]) : timeoutController;
    const timeoutId = setTimeout(() => timeoutController.abort(), timeoutMs);
    timeoutId.unref?.();
    let timedOut = false;
    timeoutController.signal.addEventListener("abort", () => {
      timedOut = true;
    });

    try {
      const resp = await fetch(parsed.toString(), {
        method,
        headers: requestHeaders,
        body: requestBody,
        redirect: "manual",
        signal: controller.signal,
      });

      // Treat redirects as errors (policy: no redirects).
      if (resp.status >= 300 && resp.status <= 399) {
        throw new AsyncGuardError(
          "http",
          `redirect not allowed (status ${resp.status})`,
          resp.status,
        );
      }

      const buf = Buffer.from(await resp.arrayBuffer());
      if (buf.byteLength > maxResponseSizeBytes) {
        throw new AsyncGuardError("http", "response too large", resp.status);
      }

      let json: unknown;
      try {
        json = JSON.parse(buf.toString("utf8"));
      } catch (err) {
        throw new AsyncGuardError("parse", `parse json: ${String(err)}`, resp.status);
      }

      const durationMs = Date.now() - start;
      return {
        status: resp.status,
        json,
        audit: {
          method,
          url: redactedUrl,
          status: resp.status,
          durationMs,
        },
      };
    } catch (err) {
      // Intentionally do not include headers/query params in error strings.
      const durationMs = Date.now() - start;
      if (err instanceof AsyncGuardError) {
        throw new AsyncGuardError(
          err.kind,
          `${guard}: http error (${durationMs}ms): ${err.message}`,
          err.status,
        );
      }
      if (timedOut || isAbortError(err)) {
        throw new AsyncGuardError("timeout", `${guard}: http timeout (${durationMs}ms)`);
      }
      const message = err instanceof Error ? err.message : String(err);
      throw new AsyncGuardError("http", `${guard}: http error (${durationMs}ms): ${message}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

function enforceUrlPolicy(url: URL, method: string, policy: HttpRequestPolicy): void {
  const hostname = url.hostname;
  const allowedHosts = policy.allowedHosts ?? [];
  if (allowedHosts.length > 0 && !allowedHosts.includes(hostname)) {
    throw new AsyncGuardError("other", `host not allowed: ${hostname}`);
  }

  const allowedMethods = (policy.allowedMethods ?? []).map((m) => m.toUpperCase());
  if (allowedMethods.length > 0 && !allowedMethods.includes(method.toUpperCase())) {
    throw new AsyncGuardError("other", `http method not allowed: ${method}`);
  }

  const scheme = url.protocol.replace(":", "");
  if (scheme === "https") return;

  const allowInsecure = policy.allowInsecureHttpForLoopback !== false;
  if (scheme === "http" && allowInsecure && isLoopbackHost(hostname)) return;

  throw new AsyncGuardError("other", `unsupported url scheme: ${scheme}`);
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function redactUrl(url: URL): string {
  // Strip query string to avoid leaking API keys (e.g. Safe Browsing key=...).
  return `${url.protocol}//${url.host}${url.pathname}`;
}

function anySignal(signals: AbortSignal[]): AbortController {
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  for (const s of signals) {
    if (s.aborted) {
      controller.abort();
      return controller;
    }
    s.addEventListener("abort", onAbort, { once: true });
  }
  return controller;
}

function isAbortError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === "AbortError" || error.message.toLowerCase().includes("aborted"))
  );
}
