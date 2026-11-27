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
}

/**
 * Production HTTP CloudIntelligenceClient.
 * Enforces envelope hygiene client-side before transmission and sends
 * tenant, device, bearer credential, idempotency, and anti-replay headers.
 */
export class HttpCloudIntelligenceClient implements CloudIntelligenceClient {
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;

  constructor(options: HttpCloudClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.fetchFn = options.fetchFn ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
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
      return (await res.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }
}
