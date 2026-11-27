import { createHash } from "node:crypto";
import type { DurableJobStore } from "../jobs/durable-job-store.js";
import { computeScopeFingerprint } from "../keys.js";
import type { MemoryAtom, Scope } from "../models.js";
import type { GraphStore, MetadataStore, VectorStore } from "../storage/types.js";
import { abstractFromAtoms, type AbstractedMemory } from "./abstraction.js";
import {
  applyConsolidation,
  consolidateAtoms,
  type AppliedConsolidationResult,
  type ConsolidationPlan,
} from "./consolidation.js";
import {
  applyLifecycleDecisions,
  evaluateLifecycle,
  type LifecycleEvaluation,
} from "./lifecycle.js";

export type OptimizationJobStatus =
  | "pending"
  | "running"
  | "partially_completed"
  | "completed"
  | "failed"
  | "cancelled";

export type OptimizationType = "full" | "consolidation" | "abstraction" | "lifecycle";

export interface OptimizationReport {
  reportId: string;
  inputAtomCount: number;
  consolidation?: ConsolidationPlan;
  appliedConsolidation?: AppliedConsolidationResult;
  abstraction?: AbstractedMemory | null;
  lifecycleEvaluations: LifecycleEvaluation[];
  duplicateReductionCount: number;
  estimatedTokensBefore: number;
  plannedTokensAfter: number;
  plannedTokenReduction: number;
  verifiedTokenReduction: number;
}

export interface MemoryOptimizationJob {
  jobId: string;
  idempotencyKey: string;
  tenantId: string;
  subjectId: string;
  scope: Scope;
  optimizationType: OptimizationType;
  targetMemoryIds: string[];
  policyVersion: string;
  pipelineVersion: string;
  status: OptimizationJobStatus;
  checkpoint?: string;
  result?: OptimizationReport;
  error?: string;
  createdAt: string;
  completedAt?: string;
}

function estimateTotalTokens(atoms: ReadonlyArray<MemoryAtom>): number {
  return atoms.reduce(
    (sum, atom) => sum + Math.max(1, Math.ceil(atom.claim.statement.length / 4)),
    0,
  );
}

export function computeOptimizationIdempotencyKey(params: {
  tenantId: string;
  scope: Scope;
  optimizationType: OptimizationType;
  targetMemoryIds: ReadonlyArray<string>;
  policyVersion: string;
}): string {
  const payload = JSON.stringify({
    tenantId: params.tenantId,
    scope: computeScopeFingerprint(params.scope),
    optimizationType: params.optimizationType,
    targetMemoryIds: [...params.targetMemoryIds].toSorted(),
    policyVersion: params.policyVersion,
  });
  return createHash("sha256").update(payload).digest("hex").slice(0, 32);
}

/**
 * Execute an idempotent MemoryOptimizationJob.
 * - Uses deterministic idempotencyKey (deduplicates via DurableJobStore when provided).
 * - Distinguishes plannedTokenReduction vs verifiedTokenReduction (only non-zero when
 *   canonical write-back via metadataStore actually executes).
 */
export async function runOptimizationJob(params: {
  idempotencyKey?: string;
  tenantId: string;
  subjectId: string;
  scope: Scope;
  optimizationType: OptimizationType;
  atoms: ReadonlyArray<MemoryAtom>;
  policyVersion?: string;
  pipelineVersion?: string;
  nowMs?: number;
  jobStore?: DurableJobStore;
  metadataStore?: MetadataStore;
  graphStore?: GraphStore;
  vectorStore?: VectorStore;
}): Promise<MemoryOptimizationJob> {
  const policyVersion = params.policyVersion ?? "1.0.0";
  const pipelineVersion = params.pipelineVersion ?? "1.0.0";
  const targetMemoryIds = params.atoms.map((a) => a.id);
  const idempotencyKey =
    params.idempotencyKey ??
    computeOptimizationIdempotencyKey({
      tenantId: params.tenantId,
      scope: params.scope,
      optimizationType: params.optimizationType,
      targetMemoryIds,
      policyVersion,
    });

  let jobId = `opt_${idempotencyKey.slice(0, 12)}`;
  let createdAt = new Date(params.nowMs ?? Date.now()).toISOString();

  if (params.jobStore) {
    const record = await params.jobStore.enqueue({
      kind: "optimization",
      tenantId: params.tenantId,
      idempotencyKey,
      pipelineVersion,
      payload: {
        subjectId: params.subjectId,
        scope: params.scope,
        optimizationType: params.optimizationType,
        targetMemoryIds,
      },
    });
    jobId = record.jobId;
    createdAt = record.createdAt;
    if (record.status === "completed" && record.result) {
      return {
        jobId,
        idempotencyKey,
        tenantId: params.tenantId,
        subjectId: params.subjectId,
        scope: params.scope,
        optimizationType: params.optimizationType,
        targetMemoryIds,
        policyVersion,
        pipelineVersion,
        status: "completed",
        checkpoint: record.checkpoint,
        result: record.result as OptimizationReport,
        createdAt,
        completedAt: record.completedAt,
      };
    }
  }

  try {
    const consolidation =
      params.optimizationType === "full" || params.optimizationType === "consolidation"
        ? consolidateAtoms(params.atoms)
        : undefined;
    if (params.jobStore) {
      await params.jobStore.checkpoint(jobId, "consolidation_planned", 35);
    }

    const abstraction =
      params.optimizationType === "full" || params.optimizationType === "abstraction"
        ? abstractFromAtoms({ atoms: params.atoms })
        : undefined;
    if (params.jobStore) {
      await params.jobStore.checkpoint(jobId, "abstraction_evaluated", 60);
    }

    const lifecycleEvaluations =
      params.optimizationType === "full" || params.optimizationType === "lifecycle"
        ? params.atoms.map((atom) => evaluateLifecycle(atom, { nowMs: params.nowMs }))
        : [];

    let appliedConsolidation: AppliedConsolidationResult | undefined;
    let verifiedDeprecatedOrPurged = new Set<string>();
    if (params.metadataStore) {
      if (consolidation) {
        appliedConsolidation = await applyConsolidation({
          plan: consolidation,
          metadataStore: params.metadataStore,
          graphStore: params.graphStore,
          vectorStore: params.vectorStore,
          now: createdAt,
        });
        for (const id of appliedConsolidation.deprecatedSourceIds) {
          verifiedDeprecatedOrPurged.add(id);
        }
      }
      if (lifecycleEvaluations.length > 0) {
        const appliedLife = await applyLifecycleDecisions({
          evaluations: lifecycleEvaluations,
          metadataStore: params.metadataStore,
          graphStore: params.graphStore,
          vectorStore: params.vectorStore,
          now: createdAt,
        });
        for (const id of [
          ...appliedLife.archivedIds,
          ...appliedLife.deprecatedIds,
          ...appliedLife.purgedIds,
        ]) {
          verifiedDeprecatedOrPurged.add(id);
        }
      }
    }

    const estimatedTokensBefore = estimateTotalTokens(params.atoms);
    const duplicateReductionCount = consolidation?.mergedCount ?? 0;
    const retainedPlannedIds = new Set(
      consolidation ? consolidation.clusters.map((c) => c.canonicalAtomId) : targetMemoryIds,
    );
    const plannedTokensAfter = estimateTotalTokens(
      params.atoms.filter((a) => retainedPlannedIds.has(a.id)),
    );
    const plannedTokenReduction = Math.max(0, estimatedTokensBefore - plannedTokensAfter);
    const verifiedTokenReduction = params.metadataStore
      ? estimateTotalTokens(params.atoms.filter((a) => verifiedDeprecatedOrPurged.has(a.id)))
      : 0;

    const report: OptimizationReport = {
      reportId: `rep_${jobId}`,
      inputAtomCount: params.atoms.length,
      ...(consolidation ? { consolidation } : {}),
      ...(appliedConsolidation ? { appliedConsolidation } : {}),
      ...(abstraction !== undefined ? { abstraction } : {}),
      lifecycleEvaluations,
      duplicateReductionCount,
      estimatedTokensBefore,
      plannedTokensAfter,
      plannedTokenReduction,
      verifiedTokenReduction,
    };

    const completedAt = new Date(params.nowMs ?? Date.now()).toISOString();
    if (params.jobStore) {
      await params.jobStore.complete(jobId, report);
    }

    return {
      jobId,
      idempotencyKey,
      tenantId: params.tenantId,
      subjectId: params.subjectId,
      scope: params.scope,
      optimizationType: params.optimizationType,
      targetMemoryIds,
      policyVersion,
      pipelineVersion,
      status: "completed",
      checkpoint: "done",
      result: report,
      createdAt,
      completedAt,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (params.jobStore) {
      await params.jobStore.fail(jobId, message);
    }
    return {
      jobId,
      idempotencyKey,
      tenantId: params.tenantId,
      subjectId: params.subjectId,
      scope: params.scope,
      optimizationType: params.optimizationType,
      targetMemoryIds,
      policyVersion,
      pipelineVersion,
      status: "failed",
      error: message,
      createdAt,
    };
  }
}
