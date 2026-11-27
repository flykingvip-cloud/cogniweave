import type {
  CloudAuthContext,
  CloudDeleteTombstoneInput,
  CloudIntelligenceClient,
  CloudOpResult,
  CloudPullInput,
  CloudPullResult,
  CloudPushInput,
} from "./cloud-client.js";
import { assertPromotionEnvelopeHygiene } from "./promotion-envelope.js";

export interface HttpCloudClientOptions {
  baseUrl: string;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
  maxRetries?: number;
  retryDelayMs?: number;
}

/**
 * Production HTTP CloudIntelligenceClient.
 * Enforces envelope hygiene, validates HTTP status (!res.ok -> error, never masked as success),
 * and retries transient 5xx/network failures with backoff.
 */
export class HttpCloudIntelligenceClient implements CloudIntelligenceClient {
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryDelayMs: number;

  constructor(options: HttpCloudClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.fetchFn = options.fetchFn ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.maxRetries = Math.max(0, options.maxRetries ?? 1);
    this.retryDelayMs = Math.max(0, options.retryDelayMs ?? 100);
  }

  async push(input: CloudPushInput, auth: CloudAuthContext): Promise<CloudOpResult> {
    if (!auth.credential.trim()) {
      return { ok: false, code: "UNAUTHENTICATED", message: "Missing credential" };
    }
    if (input.claimedTenantId && input.claimedTenantId !== auth.tenantId) {
      return { ok: false, code: "TENANT_MISMATCH", message: "Claimed tenant mismatch" };
    }
    try {
      assertPromotionEnvelopeHygiene(input.envelope);
    } catch (err) {
      return {
        ok: false,
        code: "ENVELOPE_HYGIENE",
        message: err instanceof Error ? err.message : String(err),
      };
    }

    return this.postJson<CloudOpResult>("/v1/cloud/promotions", input, auth, {
      "Idempotency-Key": input.idempotencyKey,
      "X-CogniWeave-Nonce": input.nonce,
      "X-CogniWeave-Timestamp": String(input.timestampMs),
    });
  }

  async deleteTombstone(
    input: CloudDeleteTombstoneInput,
    auth: CloudAuthContext,
  ): Promise<CloudOpResult> {
    if (!auth.credential.trim()) {
      return { ok: false, code: "UNAUTHENTICATED", message: "Missing credential" };
    }
    if (input.claimedTenantId && input.claimedTenantId !== auth.tenantId) {
      return { ok: false, code: "TENANT_MISMATCH", message: "Claimed tenant mismatch" };
    }
    return this.postJson<CloudOpResult>("/v1/cloud/tombstones", input, auth, {
      "Idempotency-Key": input.idempotencyKey,
      "X-CogniWeave-Nonce": input.nonce,
      "X-CogniWeave-Timestamp": String(input.timestampMs),
    });
  }

  async pull(input: CloudPullInput, auth: CloudAuthContext): Promise<CloudPullResult> {
    if (!auth.credential.trim()) {
      return { ok: false, code: "UNAUTHENTICATED", message: "Missing credential" };
    }
    if (input.claimedTenantId && input.claimedTenantId !== auth.tenantId) {
      return { ok: false, code: "TENANT_MISMATCH", message: "Claimed tenant mismatch" };
    }
    return this.postJson<CloudPullResult>("/v1/cloud/pull", input, auth, {
      "X-CogniWeave-Nonce": input.nonce,
      "X-CogniWeave-Timestamp": String(input.timestampMs),
    });
  }

  private async postJson<T>(
    path: string,
    body: unknown,
    auth: CloudAuthContext,
    extraHeaders: Record<string, string>,
  ): Promise<T> {
    let lastError: Error | undefined;
    for (let attempt = 0; attempt <= this.maxRetries; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const res = await this.fetchFn(`${this.baseUrl}${path}`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${auth.credential}`,
            "x-cogniweave-tenant-id": auth.tenantId,
            "x-cogniweave-device-id": auth.deviceId,
            ...extraHeaders,
          },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          const err = new Error(`Cloud HTTP ${res.status}: ${text || res.statusText}`);
          if (res.status >= 500 && attempt < this.maxRetries) {
            lastError = err;
            await new Promise((r) => setTimeout(r, this.retryDelayMs * (attempt + 1)));
            continue;
          }
          throw err;
        }
        return (await res.json()) as T;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt < this.maxRetries && !lastError.message.startsWith("Cloud HTTP 4")) {
          await new Promise((r) => setTimeout(r, this.retryDelayMs * (attempt + 1)));
          continue;
        }
        throw lastError;
      } finally {
        clearTimeout(timer);
      }
    }
    throw lastError ?? new Error("Cloud HTTP request failed");
  }
}
