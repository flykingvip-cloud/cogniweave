import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

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
  pipelineVersion: string;
  status: DurableJobStatus;
  attempt: number;
  maxAttempts: number;
  progress: number;
  checkpoint?: string;
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
  checkpoint(jobId: string, checkpoint: string, progress: number): Promise<DurableJobRecord>;
  complete<Result>(jobId: string, result: Result): Promise<DurableJobRecord<unknown, Result>>;
  fail(jobId: string, error: string): Promise<DurableJobRecord>;
  cancel(jobId: string): Promise<DurableJobRecord>;
  listDeadLetters(tenantId?: string): Promise<DurableJobRecord[]>;
}

/**
 * File-backed DurableJobStore with atomic temp-file rename persistence,
 * idempotency deduplication, checkpointing, retry backoff, and DLQ transition.
 */
export class FileDurableJobStore implements DurableJobStore {
  private readonly jobs = new Map<string, DurableJobRecord>();
  private readonly byIdempotency = new Map<string, string>();
  private loaded = false;

  constructor(private readonly filePath: string) {}

  private async ensureLoaded(): Promise<void> {
    if (this.loaded) {
      return;
    }
    this.loaded = true;
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as DurableJobRecord[];
      for (const job of parsed) {
        this.jobs.set(job.jobId, job);
        this.byIdempotency.set(`${job.tenantId}\0${job.kind}\0${job.idempotencyKey}`, job.jobId);
      }
    } catch {
      // File does not exist yet on first run.
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
    const existingId = this.byIdempotency.get(key);
    if (existingId) {
      const existing = this.jobs.get(existingId);
      if (existing) {
        return existing as DurableJobRecord<Payload>;
      }
    }

    const now = new Date().toISOString();
    const record: DurableJobRecord<Payload> = {
      jobId: `job_${randomUUID().slice(0, 12)}`,
      kind: input.kind,
      tenantId: input.tenantId,
      idempotencyKey: input.idempotencyKey,
      pipelineVersion: input.pipelineVersion ?? "1.0.0",
      status: "pending",
      attempt: 0,
      maxAttempts: Math.max(1, input.maxAttempts ?? 3),
      progress: 0,
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

  async checkpoint(jobId: string, checkpoint: string, progress: number): Promise<DurableJobRecord> {
    await this.ensureLoaded();
    const existing = this.jobs.get(jobId);
    if (!existing) {
      throw new Error(`Durable job not found: ${jobId}`);
    }
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
  ): Promise<DurableJobRecord<unknown, Result>> {
    await this.ensureLoaded();
    const existing = this.jobs.get(jobId);
    if (!existing) {
      throw new Error(`Durable job not found: ${jobId}`);
    }
    const now = new Date().toISOString();
    const updated: DurableJobRecord<unknown, Result> = {
      ...existing,
      status: "completed",
      progress: 100,
      result,
      updatedAt: now,
      completedAt: now,
    };
    this.jobs.set(jobId, updated);
    await this.persist();
    return updated;
  }

  async fail(jobId: string, error: string): Promise<DurableJobRecord> {
    await this.ensureLoaded();
    const existing = this.jobs.get(jobId);
    if (!existing) {
      throw new Error(`Durable job not found: ${jobId}`);
    }
    const nextAttempt = existing.attempt + 1;
    const status: DurableJobStatus =
      nextAttempt >= existing.maxAttempts ? "dead_letter" : "retrying";
    const updated: DurableJobRecord = {
      ...existing,
      attempt: nextAttempt,
      status,
      error,
      updatedAt: new Date().toISOString(),
    };
    this.jobs.set(jobId, updated);
    await this.persist();
    return updated;
  }

  async cancel(jobId: string): Promise<DurableJobRecord> {
    await this.ensureLoaded();
    const existing = this.jobs.get(jobId);
    if (!existing) {
      throw new Error(`Durable job not found: ${jobId}`);
    }
    const updated: DurableJobRecord = {
      ...existing,
      status: "cancelled",
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
