import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FileDurableJobStore } from "./durable-job-store.js";

describe("FileDurableJobStore (CW-07B)", () => {
  it("handles concurrent init, payload fingerprint conflicts, worker leases, backoff, state guards, and rejects corrupted files", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cw-jobs-"));
    const filePath = join(dir, "jobs.json");
    try {
      const store1 = new FileDurableJobStore(filePath, { baseBackoffMs: 1000 });
      const [j1, j2] = await Promise.all([
        store1.enqueue({
          kind: "optimization",
          tenantId: "t_1",
          idempotencyKey: "idem_1",
          maxAttempts: 2,
          payload: { scope: "ws_1" },
        }),
        store1.enqueue({
          kind: "optimization",
          tenantId: "t_1",
          idempotencyKey: "idem_2",
          maxAttempts: 2,
          payload: { scope: "ws_2" },
        }),
      ]);

      // J-06: Same idempotencyKey with different payload throws IdempotencyConflictError
      await expect(
        store1.enqueue({
          kind: "optimization",
          tenantId: "t_1",
          idempotencyKey: "idem_1",
          payload: { scope: "DIFFERENT" },
        }),
      ).rejects.toThrow("different payload");

      // J-05: Worker lease claim
      const claimed = await store1.claimJob(j1.jobId, "worker_1", 5000, 1000);
      expect(claimed?.claimedByWorkerId).toBe("worker_1");
      expect(await store1.claimJob(j1.jobId, "worker_2", 5000, 2000)).toBeNull();

      // J-04: Exponential backoff on retry -> dead_letter on maxAttempts
      const retrying = await store1.fail(j1.jobId, "transient_err", 10_000);
      expect(retrying.status).toBe("retrying");
      expect(retrying.nextAttemptAt).toBe(new Date(11_000).toISOString());

      const dlq = await store1.fail(j1.jobId, "fatal_err", 12_000);
      expect(dlq.status).toBe("dead_letter");

      // J-07: State machine prevents completing or cancelling terminal DLQ job
      await expect(store1.complete(j1.jobId, {})).rejects.toThrow("terminal job");
      await expect(store1.cancel(j1.jobId)).rejects.toThrow("terminal job");

      // J-02: Corrupted JSON throws instead of silently overwriting
      const corruptPath = join(dir, "corrupt.json");
      await writeFile(corruptPath, "{broken-json", "utf8");
      const corruptStore = new FileDurableJobStore(corruptPath);
      await expect(corruptStore.get(j2.jobId)).rejects.toThrow();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
