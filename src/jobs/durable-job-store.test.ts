import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FileDurableJobStore } from "./durable-job-store.js";

describe("FileDurableJobStore (CW-07)", () => {
  it("supports idempotency, checkpointing, restart persistence, and DLQ transition", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cw-jobs-"));
    const filePath = join(dir, "jobs.json");
    try {
      const store1 = new FileDurableJobStore(filePath);
      const j1 = await store1.enqueue({
        kind: "optimization",
        tenantId: "t_1",
        idempotencyKey: "idem_1",
        maxAttempts: 2,
        payload: { scope: "ws_1" },
      });
      const j1Dup = await store1.enqueue({
        kind: "optimization",
        tenantId: "t_1",
        idempotencyKey: "idem_1",
        maxAttempts: 2,
        payload: { scope: "ws_1" },
      });
      expect(j1Dup.jobId).toBe(j1.jobId);

      await store1.checkpoint(j1.jobId, "consolidation_done", 50);
      await store1.fail(j1.jobId, "transient_err");
      const dlq = await store1.fail(j1.jobId, "fatal_err");
      expect(dlq.status).toBe("dead_letter");

      // Reload from disk in fresh instance
      const store2 = new FileDurableJobStore(filePath);
      const reloaded = await store2.get(j1.jobId);
      expect(reloaded?.status).toBe("dead_letter");
      expect(reloaded?.checkpoint).toBe("consolidation_done");
      expect((await store2.listDeadLetters("t_1")).map((j) => j.jobId)).toEqual([j1.jobId]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
