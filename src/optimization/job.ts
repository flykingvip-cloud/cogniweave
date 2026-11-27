import { randomUUID } from "node:crypto";
import type { MemoryAtom, Scope } from "../models.js";
import { abstractFromAtoms, type AbstractedMemory } from "./abstraction.js";
import { consolidateAtoms, type ConsolidationResult } from "./consolidation.js";
import { evaluateLifecycle, type LifecycleEvaluation } from "./lifecycle.js";

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
  consolidation?: ConsolidationResult;
  abstraction?: AbstractedMemory | null;
  lifecycleEvaluations: LifecycleEvaluation[];
  duplicateReductionCount: number;
  estimatedTokensBefore: number;
  estimatedTokensAfter: number;
}

export interface MemoryOptimizationJob {
  jobId: string;
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

/**
 * Execute a deterministic, idempotent MemoryOptimizationJob over target atoms.
 */
export function runOptimizationJob(params: {
  jobId?: string;
  tenantId: string;
  subjectId: string;
  scope: Scope;
  optimizationType: OptimizationType;
  atoms: ReadonlyArray<MemoryAtom>;
  policyVersion?: string;
  pipelineVersion?: string;
  nowMs?: number;
}): MemoryOptimizationJob {
  const createdAt = new Date(params.nowMs ?? Date.now()).toISOString();
  const jobId = params.jobId ?? `opt_${randomUUID().slice(0, 12)}`;
  const targetMemoryIds = params.atoms.map((a) => a.id);

  try {
    const consolidation =
      params.optimizationType === "full" || params.optimizationType === "consolidation"
        ? consolidateAtoms(params.atoms)
        : undefined;

    const abstraction =
      params.optimizationType === "full" || params.optimizationType === "abstraction"
        ? abstractFromAtoms({ atoms: params.atoms })
        : undefined;

    const lifecycleEvaluations =
      params.optimizationType === "full" || params.optimizationType === "lifecycle"
        ? params.atoms.map((atom) => evaluateLifecycle(atom, { nowMs: params.nowMs }))
        : [];

    const estimatedTokensBefore = estimateTotalTokens(params.atoms);
    const duplicateReductionCount = consolidation?.mergedCount ?? 0;
    const retainedIds = new Set(
      consolidation ? consolidation.clusters.map((c) => c.canonicalAtomId) : targetMemoryIds,
    );
    const estimatedTokensAfter = estimateTotalTokens(
      params.atoms.filter((a) => retainedIds.has(a.id)),
    );

    const report: OptimizationReport = {
      reportId: `rep_${jobId}`,
      inputAtomCount: params.atoms.length,
      ...(consolidation ? { consolidation } : {}),
      ...(abstraction !== undefined ? { abstraction } : {}),
      lifecycleEvaluations,
      duplicateReductionCount,
      estimatedTokensBefore,
      estimatedTokensAfter,
    };

    return {
      jobId,
      tenantId: params.tenantId,
      subjectId: params.subjectId,
      scope: params.scope,
      optimizationType: params.optimizationType,
      targetMemoryIds,
      policyVersion: params.policyVersion ?? "1.0.0",
      pipelineVersion: params.pipelineVersion ?? "1.0.0",
      status: "completed",
      checkpoint: "done",
      result: report,
      createdAt,
      completedAt: new Date(params.nowMs ?? Date.now()).toISOString(),
    };
  } catch (err) {
    return {
      jobId,
      tenantId: params.tenantId,
      subjectId: params.subjectId,
      scope: params.scope,
      optimizationType: params.optimizationType,
      targetMemoryIds,
      policyVersion: params.policyVersion ?? "1.0.0",
      pipelineVersion: params.pipelineVersion ?? "1.0.0",
      status: "failed",
      error: err instanceof Error ? err.message : String(err),
      createdAt,
    };
  }
}
