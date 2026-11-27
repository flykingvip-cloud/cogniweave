import { describe, expect, it } from "vitest";
import { HttpCloudIntelligenceClient } from "./http-cloud-client.js";
import type { CloudPromotionEnvelope } from "./promotion-envelope.js";

const VALID_ENVELOPE: CloudPromotionEnvelope = {
  envelopeVersion: 1,
  atomId: "atm_1",
  atomType: "strategy",
  scope: {
    workspaceId: "ws_1",
    projectId: "proj_1",
    agentId: "agent_main",
    visibility: "shared",
  },
  claim: {
    type: "procedural",
    statement: "Use idempotency keys on retries.",
  },
  trigger: { contextTags: ["reliability"], conditionCount: 1 },
  metrics: { confidence: 0.9 },
  governance: { promotionScore: 0.85, scoreVersion: 1 },
  provenance: { sourceEventIdCount: 1 },
  privacy: { privacyLevel: "shared", syncEligibility: "eligible" },
  versioning: { version: 1 },
};

describe("HttpCloudIntelligenceClient (CW-07)", () => {
  it("enforces tenant match, credential, and sends auth/anti-replay headers", async () => {
    const calls: Array<{ url: string; headers: Record<string, string> }> = [];
    const client = new HttpCloudIntelligenceClient({
      baseUrl: "https://cloud.cogniweave.test/",
      fetchFn: (async (url, init) => {
        calls.push({
          url: String(url),
          headers: (init?.headers ?? {}) as Record<string, string>,
        });
        return new Response(JSON.stringify({ ok: true, cloudObjectId: "obj_1" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }) as typeof fetch,
    });

    const denied = await client.push(
      {
        idempotencyKey: "k1",
        envelope: VALID_ENVELOPE,
        claimedTenantId: "t_other",
        nonce: "n1",
        timestampMs: 1000,
      },
      { tenantId: "t_1", deviceId: "dev_1", credential: "tok_1" },
    );
    expect(denied).toEqual({
      ok: false,
      code: "TENANT_MISMATCH",
      message: "Claimed tenant mismatch",
    });
    expect(calls).toHaveLength(0);

    const ok = await client.push(
      {
        idempotencyKey: "k1",
        envelope: VALID_ENVELOPE,
        nonce: "n1",
        timestampMs: 1000,
      },
      { tenantId: "t_1", deviceId: "dev_1", credential: "tok_1" },
    );
    expect(ok).toEqual({ ok: true, cloudObjectId: "obj_1" });
    expect(calls[0]?.url).toBe("https://cloud.cogniweave.test/v1/cloud/promotions");
    expect(calls[0]?.headers.authorization).toBe("Bearer tok_1");
    expect(calls[0]?.headers["x-cogniweave-tenant-id"]).toBe("t_1");
    expect(calls[0]?.headers["Idempotency-Key"]).toBe("k1");

    // Non-OK HTTP status must throw instead of masquerading as success.
    const errClient = new HttpCloudIntelligenceClient({
      baseUrl: "https://cloud.cogniweave.test/",
      maxRetries: 0,
      fetchFn: (async () =>
        new Response(JSON.stringify({ ok: false, error: "internal" }), {
          status: 500,
          statusText: "Internal Server Error",
        })) as typeof fetch,
    });
    await expect(
      errClient.push(
        { idempotencyKey: "k2", envelope: VALID_ENVELOPE, nonce: "n2", timestampMs: 2000 },
        { tenantId: "t_1", deviceId: "dev_1", credential: "tok_1" },
      ),
    ).rejects.toThrow("Cloud HTTP 500");
  });
});
