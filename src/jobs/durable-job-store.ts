import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { IdempotencyConflictError } from "../errors.js";

export type DurableJobKind =
  | "ingestion"
  | "distillation"
  | "optimization"
  | "index_repair"
  | "promotion";

export type DurableJobStatus =
  | "pending"
  | "running"
  | "partially_completed"
  | "completed"
  | "failed"
  | "retrying"
  | "cancelled"
  | "dead_letter";

export interface DurableJobRecord<Payload = unknown, Result = unknown> {
  jobId: string;
  kind: DurableJobKind;
  tenantId: string;
  idempotencyKey: string;
  payloadFingerprint: string;
  pipelineVersion: string;
  status: DurableJobStatus;
  attempt: number;
  maxAttempts: number;
  progress: number;
  checkpoint?: string;
  claimedByWorkerId?: string;
  fencingToken: number;
  leaseExpiresAt?: string;
  nextAttemptAt?: string;
  payload: Payload;
  result?: Result;
  error?: string;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
}

export interface DurableJobStore {
  enqueue<Payload>(input: {
    kind: DurableJobKind;
    tenantId: string;
    idempotencyKey: string;
    pipelineVersion?: string;
    maxAttempts?: number;
    payload: Payload;
  }): Promise<DurableJobRecord<Payload>>;
  get(jobId: string): Promise<DurableJobRecord | undefined>;
  listPendingJobs(nowMs?: number): Promise<DurableJobRecord[]>;
  claimJob(jobId: string, workerId: string, leaseMs?: number, nowMs?: number): Promise<DurableJobRecord | null>;
  releaseExpiredLeases(nowMs?: number): Promise<number>;
  checkpoint(
    jobId: string,
    checkpoint: string,
    progress: number,
    lease?: { workerId: string; fencingToken: number },
  ): Promise<DurableJobRecord>;
  complete<Result>(
    jobId: string,
    result: Result,
    lease?: { workerId: string; fencingToken: number },
  ): Promise<DurableJobRecord<unknown, Result>>;
  fail(
    jobId: string,
    error: string,
    nowMs?: number,
    lease?: { workerId: string; fencingToken: number },
  ): Promise<DurableJobRecord>;
  cancel(jobId: string): Promise<DurableJobRecord>;
  listDeadLetters(tenantId?: string): Promise<DurableJobRecord[]>;
}

const TERMINAL_STATUSES: ReadonlySet<DurableJobStatus> = new Set([
  "completed",
  "cancelled",
  "dead_letter",
]);

function fingerprintPayload(payload: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(payload ?? null))
    .digest("hex")
    .slice(0, 32);
}

/**
 * File-backed DurableJobStore (single-host / local dev adapter; multi-instance
 * deployments should use a transactional PostgreSQL DurableJobStore).
 * Fixes: shared loadPromise (no concurrent init race), ENOENT-only fallback (corrupted JSON throws),
 * payloadFingerprint conflict detection, state-machine guards, retry backoff, and worker lease claims.
 */
export class FileDurableJobStore implements DurableJobStore {
  private readonly jobs = new Map<string, DurableJobRecord>();
  private readonly byIdempotency = new Map<string, string>();
  private loadPromise: Promise<void> | null = null;
  private readonly baseBackoffMs: number;

  constructor(
    private readonly filePath: string,
    options?: { baseBackoffMs?: number },
  ) {
    this.baseBackoffMs = options?.baseBackoffMs ?? 1000;
  }

  private ensureLoaded(): Promise<void> {
    if (!this.loadPromise) {
      this.loadPromise = this.loadFromDisk();
    }
    return this.loadPromise;
  }

  private async loadFromDisk(): Promise<void> {
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as DurableJobRecord[];
      if (!Array.isArray(parsed)) {
        throw new Error(`Corrupted durable job store file (expected array): ${this.filePath}`);
      }
      for (const job of parsed) {
        this.jobs.set(job.jobId, job);
        this.byIdempotency.set(`${job.tenantId}\0${job.kind}\0${job.idempotencyKey}`, job.jobId);
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | null)?.code;
      if (code === "ENOENT") {
        return;
      }
      this.loadPromise = null;
      throw err;
    }
  }

  private async persist(): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp.${randomUUID().slice(0, 8)}`;
    await writeFile(tmp, JSON.stringify([...this.jobs.values()], null, 2), "utf8");
    await rename(tmp, this.filePath);
  }

  async enqueue<Payload>(input: {
    kind: DurableJobKind;
    tenantId: string;
    idempotencyKey: string;
    pipelineVersion?: string;
    maxAttempts?: number;
    payload: Payload;
  }): Promise<DurableJobRecord<Payload>> {
    await this.ensureLoaded();
    const key = `${input.tenantId}\0${input.kind}\0${input.idempotencyKey}`;
    const payloadFingerprint = fingerprintPayload(input.payload);
    const existingId = this.byIdempotency.get(key);
    if (existingId) {
      const existing = this.jobs.get(existingId);
      if (existing) {
        if (existing.payloadFingerprint !== payloadFingerprint) {
          throw new IdempotencyConflictError(
            `Idempotency key "${input.idempotencyKey}" already used with different payload`,
          );
        }
        return existing as DurableJobRecord<Payload>;
      }
    }

    const now = new Date().toISOString();
    const record: DurableJobRecord<Payload> = {
      jobId: `job_${randomUUID().slice(0, 12)}`,
      kind: input.kind,
      tenantId: input.tenantId,
      idempotencyKey: input.idempotencyKey,
      payloadFingerprint,
      pipelineVersion: input.pipelineVersion ?? "1.0.0",
      status: "pending",
      attempt: 0,
      maxAttempts: Math.max(1, input.maxAttempts ?? 3),
      progress: 0,
      fencingToken: 0,
      payload: input.payload,
      createdAt: now,
      updatedAt: now,
    };
    this.jobs.set(record.jobId, record);
    this.byIdempotency.set(key, record.jobId);
    await this.persist();
    return record;
  }

  async get(jobId: string): Promise<DurableJobRecord | undefined> {
    await this.ensureLoaded();
    return this.jobs.get(jobId);
  }

  async listPendingJobs(nowMs = Date.now()): Promise<DurableJobRecord[]> {
    await this.ensureLoaded();
    return [...this.jobs.values()].filter((job) => {
      if (job.status === "pending") return true;
      if (job.status === "retrying") {
        return !job.nextAttemptAt || Date.parse(job.nextAttemptAt) <= nowMs;
      }
      return false;
    });
  }

  async claimJob(
    jobId: string,
    workerId: string,
    leaseMs = 30_000,
    nowMs = Date.now(),
  ): Promise<DurableJobRecord | null> {
    await this.ensureLoaded();
    const existing = this.jobs.get(jobId);
    if (!existing || TERMINAL_STATUSES.has(existing.status)) {
      return null;
    }
    if (
      existing.status === "running" &&
      existing.leaseExpiresAt &&
      Date.parse(existing.leaseExpiresAt) > nowMs
    ) {
      return null;
    }
    const updated: DurableJobRecord = {
      ...existing,
      status: "running",
      claimedByWorkerId: workerId,
      fencingToken: (existing.fencingToken ?? 0) + 1,
      leaseExpiresAt: new Date(nowMs + leaseMs).toISOString(),
      updatedAt: new Date(nowMs).toISOString(),
    };
    this.jobs.set(jobId, updated);
    await this.persist();
    return updated;
  }

  async releaseExpiredLeases(nowMs = Date.now()): Promise<number> {
    await this.ensureLoaded();
    let released = 0;
    for (const [jobId, job] of this.jobs.entries()) {
      if (
        job.status === "running" &&
        job.leaseExpiresAt &&
        Date.parse(job.leaseExpiresAt) <= nowMs
      ) {
        this.jobs.set(jobId, {
          ...job,
          status: "retrying",
          claimedByWorkerId: undefined,
          leaseExpiresAt: undefined,
          updatedAt: new Date(nowMs).toISOString(),
        });
        released += 1;
      }
    }
    if (released > 0) {
      await this.persist();
    }
    return released;
  }

  private assertLease(
    existing: DurableJobRecord,
    lease?: { workerId: string; fencingToken: number },
  ): void {
    if (!lease) return;
    if (
      existing.claimedByWorkerId !== lease.workerId ||
      existing.fencingToken !== lease.fencingToken
    ) {
      throw new Error(
        `Stale worker lease for job ${existing.jobId}: expected (${existing.claimedByWorkerId}, ${existing.fencingToken}), got (${lease.workerId}, ${lease.fencingToken})`,
      );
    }
  }

  async checkpoint(
    jobId: string,
    checkpoint: string,
    progress: number,
    lease?: { workerId: string; fencingToken: number },
  ): Promise<DurableJobRecord> {
    await this.ensureLoaded();
    const existing = this.jobs.get(jobId);
    if (!existing) throw new Error(`Durable job not found: ${jobId}`);
    if (TERMINAL_STATUSES.has(existing.status)) {
      throw new Error(`Cannot checkpoint terminal job ${jobId} (${existing.status})`);
    }
    this.assertLease(existing, lease);
    const updated: DurableJobRecord = {
      ...existing,
      status: "running",
      checkpoint,
      progress: Math.min(100, Math.max(0, progress)),
      updatedAt: new Date().toISOString(),
    };
    this.jobs.set(jobId, updated);
    await this.persist();
    return updated;
  }

  async complete<Result>(
    jobId: string,
    result: Result,
    lease?: { workerId: string; fencingToken: number },
  ): Promise<DurableJobRecord<unknown, Result>> {
    await this.ensureLoaded();
    const existing = this.jobs.get(jobId);
    if (!existing) throw new Error(`Durable job not found: ${jobId}`);
    if (TERMINAL_STATUSES.has(existing.status)) {
      throw new Error(`Cannot complete terminal job ${jobId} (${existing.status})`);
    }
    this.assertLease(existing, lease);
    const now = new Date().toISOString();
    const updated: DurableJobRecord<unknown, Result> = {
      ...existing,
      status: "completed",
      progress: 100,
      claimedByWorkerId: undefined,
      leaseExpiresAt: undefined,
      result,
      updatedAt: now,
      completedAt: now,
    };
    this.jobs.set(jobId, updated);
    await this.persist();
    return updated;
  }

  async fail(
    jobId: string,
    error: string,
    nowMs = Date.now(),
    lease?: { workerId: string; fencingToken: number },
  ): Promise<DurableJobRecord> {
    await this.ensureLoaded();
    const existing = this.jobs.get(jobId);
    if (!existing) throw new Error(`Durable job not found: ${jobId}`);
    if (TERMINAL_STATUSES.has(existing.status)) {
      throw new Error(`Cannot fail terminal job ${jobId} (${existing.status})`);
    }
    this.assertLease(existing, lease);
    const nextAttempt = existing.attempt + 1;
    const isDlq = nextAttempt >= existing.maxAttempts;
    const status: DurableJobStatus = isDlq ? "dead_letter" : "retrying";
    const delayMs = this.baseBackoffMs * Math.pow(2, nextAttempt - 1);
    const updated: DurableJobRecord = {
      ...existing,
      attempt: nextAttempt,
      status,
      error,
      claimedByWorkerId: undefined,
      leaseExpiresAt: undefined,
      ...(isDlq ? {} : { nextAttemptAt: new Date(nowMs + delayMs).toISOString() }),
      updatedAt: new Date(nowMs).toISOString(),
    };
    this.jobs.set(jobId, updated);
    await this.persist();
    return updated;
  }

  async cancel(jobId: string): Promise<DurableJobRecord> {
    await this.ensureLoaded();
    const existing = this.jobs.get(jobId);
    if (!existing) throw new Error(`Durable job not found: ${jobId}`);
    if (TERMINAL_STATUSES.has(existing.status)) {
      throw new Error(`Cannot cancel terminal job ${jobId} (${existing.status})`);
    }
    const updated: DurableJobRecord = {
      ...existing,
      status: "cancelled",
      claimedByWorkerId: undefined,
      leaseExpiresAt: undefined,
      updatedAt: new Date().toISOString(),
    };
    this.jobs.set(jobId, updated);
    await this.persist();
    return updated;
  }

  async listDeadLetters(tenantId?: string): Promise<DurableJobRecord[]> {
    await this.ensureLoaded();
    return [...this.jobs.values()].filter(
      (job) => job.status === "dead_letter" && (!tenantId || job.tenantId === tenantId),
    );
  }
}
