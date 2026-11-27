import { createHash } from "node:crypto";
import {
  authorizeAtomBindings,
  authorizeTrustedExecution,
  type ExecutionAuthorizationDecision,
  type TrustedAuthorizationAssembly,
  type TrustedExecutionAuthorizationOptions,
} from "../auth/authorize.js";
import type { DurableJobStore } from "../jobs/durable-job-store.js";
import { computeScopeFingerprint } from "../keys.js";
import type { MemoryAtom, MemorySubject, MemorySubjectBinding, Scope } from "../models.js";
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
  type AppliedLifecycleResult,
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

export interface OptimizationExecutionContext {
  actorUserId: string;
  tenantId: string;
  scope: Scope;
  caller: MemorySubject;
  /**
   * @deprecated CW-09-02: caller-submitted bindings are not evidence and are ignored.
   * Production authorization queries an AuthoritativeBindingQuery / MetadataStore.
   */
  bindings?: ReadonlyArray<MemorySubjectBinding>;
  /**
   * @deprecated CW-09-02: not proof of delegation. Lawful delegation must be a
   * DelegationAuthorizationStore record.
   */
  delegatedActorFor?: ReadonlyArray<string>;
  dataPlaneId: string;
  workerId?: string;
  allowLifecycleMutations?: boolean;
}

export interface OptimizationReport {
  reportId: string;
  inputAtomCount: number;
  consolidation?: ConsolidationPlan;
  appliedConsolidation?: AppliedConsolidationResult;
  appliedLifecycle?: AppliedLifecycleResult;
  abstraction?: AbstractedMemory | null;
  lifecycleEvaluations: LifecycleEvaluation[];
  duplicateReductionCount: number;
  estimatedTokensBefore: number;
  plannedTokensAfter: number;
  plannedTokenReduction: number;
  estimatedTokensOfPersistedRemovedAtoms: number;
  estimatedCanonicalClaimTokensBefore?: number;
  estimatedCanonicalClaimTokensAfter?: number;
  estimatedCanonicalClaimTokenDelta?: number;
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
  /** CW-09-02 audit trace: Actor, Delegator, Caller, Subject, Binding, Tenant, Scope, Decision, Trace. */
  authorization?: ExecutionAuthorizationDecision;
}

function estimateClaimTokens(atoms: ReadonlyArray<MemoryAtom>): number {
  return atoms.reduce(
    (sum, atom) => sum + Math.max(1, Math.ceil(atom.claim.statement.length / 4)),
    0,
  );
}

function buildAtomDigests(atoms: ReadonlyArray<MemoryAtom>) {
  return [...atoms]
    .toSorted((a, b) => a.id.localeCompare(b.id))
    .map((a) => ({
      id: a.id,
      version: a.versioning.version,
      status: a.state.status,
      claim: a.claim.statement,
      evidence: [...a.provenance.evidenceRefs].toSorted(),
    }));
}

export function computeOptimizationIdempotencyKey(params: {
  tenantId: string;
  scope: Scope;
  optimizationType: OptimizationType;
  atoms: ReadonlyArray<MemoryAtom>;
  policyVersion: string;
  pipelineVersion: string;
}): string {
  const payload = JSON.stringify({
    tenantId: params.tenantId,
    scope: computeScopeFingerprint(params.scope),
    optimizationType: params.optimizationType,
    atomDigests: buildAtomDigests(params.atoms),
    policyVersion: params.policyVersion,
    pipelineVersion: params.pipelineVersion,
  });
  return createHash("sha256").update(payload).digest("hex").slice(0, 32);
}

/**
 * CW-04J-01 / CW-04J-05 / CW-09-02:
 * - Requires executionContext and verifies the trusted identity chain before enqueue or store I/O:
 *   Trusted Principal → Actor → Delegation Authorization → Caller Subject →
 *   Authoritative Binding → Job Subject.
 * - `delegatedActorFor` and `executionContext.bindings` are ignored and are not evidence.
 * - Includes atomDigests in DurableJobStore payload so even explicit idempotencyKeys reject changed inputs.
 * - Uses honest Estimated Canonical Claim Token naming.
 */
export async function runOptimizationJob(params: {
  idempotencyKey?: string;
  tenantId: string;
  subjectId: string;
  scope: Scope;
  optimizationType: OptimizationType;
  atoms: ReadonlyArray<MemoryAtom>;
  executionContext: OptimizationExecutionContext;
  /** Request-level authorization options (bearer token, environment). Not a credential bag. */
  authorization?: TrustedExecutionAuthorizationOptions;
  /**
   * Trusted runtime assembly of Principal Provider, Binding Query, and
   * Delegation Store. Required in service/cloud. Not a business-request field.
   */
  trustedServices?: TrustedAuthorizationAssembly;
  policyVersion?: string;
  pipelineVersion?: string;
  nowMs?: number;
  jobStore?: DurableJobStore;
  metadataStore?: MetadataStore;
  graphStore?: GraphStore;
  vectorStore?: VectorStore;
}): Promise<MemoryOptimizationJob> {
  const ctx = params.executionContext;
  if (!ctx) {
    throw new Error("OptimizationExecutionContext is required");
  }
  const expectedScopeFp = computeScopeFingerprint(params.scope);
  if (ctx.tenantId !== params.tenantId) {
    throw new Error("OptimizationExecutionContext tenant mismatch");
  }
  if (computeScopeFingerprint(ctx.scope) !== expectedScopeFp) {
    throw new Error("OptimizationExecutionContext scope mismatch");
  }

  const now = new Date(params.nowMs ?? Date.now()).toISOString();
  const productionLike = (params.authorization?.environment ?? "service") !== "local";
  const authz = await authorizeTrustedExecution({
    request: {
      tenantId: params.tenantId,
      subjectId: params.subjectId,
      scope: params.scope,
      dataPlaneId: ctx.dataPlaneId,
      declaredActorUserId: ctx.actorUserId,
      declaredCaller: ctx.caller,
      now,
    },
    authorization: params.authorization,
    trustedServices: params.trustedServices ?? params.authorization?.trustedServices,
    // Production must not treat the job's data-plane metadataStore as a
    // caller-substitutable Binding Query. Local/test may still use it.
    ...(productionLike ? {} : { metadataStore: params.metadataStore }),
  });
  const authorizedCaller = authz.caller;

  await authorizeAtomBindings({
    atoms: params.atoms,
    expectedScope: params.scope,
    dataPlaneId: ctx.dataPlaneId,
    caller: authorizedCaller,
    bindings: authz.bindings,
  });

  const policyVersion = params.policyVersion ?? "1.0.0";
  const pipelineVersion = params.pipelineVersion ?? "1.0.0";
  const targetMemoryIds = params.atoms.map((a) => a.id);
  const atomDigests = buildAtomDigests(params.atoms);
  const idempotencyKey =
    params.idempotencyKey ??
    computeOptimizationIdempotencyKey({
      tenantId: params.tenantId,
      scope: params.scope,
      optimizationType: params.optimizationType,
      atoms: params.atoms,
      policyVersion,
      pipelineVersion,
    });

  let jobId = `opt_${idempotencyKey.slice(0, 12)}`;
  let createdAt = new Date(params.nowMs ?? Date.now()).toISOString();
  let lease: { workerId: string; fencingToken: number } | undefined;

  if (params.jobStore) {
    const record = await params.jobStore.enqueue({
      kind: "optimization",
      tenantId: params.tenantId,
      idempotencyKey,
      pipelineVersion,
      payload: {
        subjectId: params.subjectId,
        scope: expectedScopeFp,
        optimizationType: params.optimizationType,
        policyVersion,
        atomDigests,
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
        authorization: authz.decision,
      };
    }
    const workerId = ctx.workerId ?? `opt_worker_${ctx.actorUserId}`;
    const claimed = await params.jobStore.claimJob(jobId, workerId, 60_000, params.nowMs);
    if (!claimed) {
      throw new Error(`Unable to claim optimization job ${jobId} for worker ${workerId}`);
    }
    lease = { workerId, fencingToken: claimed.fencingToken };
  }

  try {
    let estimatedCanonicalClaimTokensBefore: number | undefined;
    if (params.metadataStore) {
      const allBefore = await params.metadataStore.listAtoms();
      const activeBefore = allBefore.filter(
        (a) => computeScopeFingerprint(a.scope) === expectedScopeFp && a.state.status !== "deprecated",
      );
      estimatedCanonicalClaimTokensBefore = estimateClaimTokens(activeBefore);
    }

    const consolidation =
      params.optimizationType === "full" || params.optimizationType === "consolidation"
        ? consolidateAtoms(params.atoms)
        : undefined;
    if (params.jobStore && lease) {
      await params.jobStore.checkpoint(jobId, "consolidation_planned", 35, lease);
    }

    const abstraction =
      params.optimizationType === "full" || params.optimizationType === "abstraction"
        ? abstractFromAtoms({ atoms: params.atoms })
        : undefined;
    if (params.jobStore && lease) {
      await params.jobStore.checkpoint(jobId, "abstraction_evaluated", 60, lease);
    }

    const lifecycleEvaluations =
      params.optimizationType === "full" || params.optimizationType === "lifecycle"
        ? params.atoms.map((atom) => evaluateLifecycle(atom, { nowMs: params.nowMs }))
        : [];

    let appliedConsolidation: AppliedConsolidationResult | undefined;
    let appliedLifecycle: AppliedLifecycleResult | undefined;
    const verifiedDeprecatedOrPurged = new Set<string>();

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
      if (lifecycleEvaluations.length > 0 && ctx.allowLifecycleMutations !== false) {
        appliedLifecycle = await applyLifecycleDecisions({
          evaluations: lifecycleEvaluations,
          metadataStore: params.metadataStore,
          graphStore: params.graphStore,
          vectorStore: params.vectorStore,
          now: createdAt,
        });
        for (const id of [
          ...appliedLifecycle.archivedIds,
          ...appliedLifecycle.deprecatedIds,
          ...appliedLifecycle.tombstonedIds,
          ...appliedLifecycle.purgedIds,
        ]) {
          verifiedDeprecatedOrPurged.add(id);
        }
      }
    }

    let estimatedCanonicalClaimTokensAfter: number | undefined;
    let estimatedCanonicalClaimTokenDelta: number | undefined;
    if (params.metadataStore && estimatedCanonicalClaimTokensBefore !== undefined) {
      const allAfter = await params.metadataStore.listAtoms();
      const activeAfter = allAfter.filter(
        (a) => computeScopeFingerprint(a.scope) === expectedScopeFp && a.state.status !== "deprecated",
      );
      estimatedCanonicalClaimTokensAfter = estimateClaimTokens(activeAfter);
      estimatedCanonicalClaimTokenDelta = Math.max(
        0,
        estimatedCanonicalClaimTokensBefore - estimatedCanonicalClaimTokensAfter,
      );
    }

    const estimatedTokensBefore = estimateClaimTokens(params.atoms);
    const duplicateReductionCount = consolidation?.mergedCount ?? 0;
    const retainedPlannedIds = new Set(
      consolidation ? consolidation.clusters.map((c) => c.canonicalAtomId) : targetMemoryIds,
    );
    const plannedTokensAfter = estimateClaimTokens(
      params.atoms.filter((a) => retainedPlannedIds.has(a.id)),
    );
    const plannedTokenReduction = Math.max(0, estimatedTokensBefore - plannedTokensAfter);
    const estimatedTokensOfPersistedRemovedAtoms = params.metadataStore
      ? estimateClaimTokens(params.atoms.filter((a) => verifiedDeprecatedOrPurged.has(a.id)))
      : 0;

    const report: OptimizationReport = {
      reportId: `rep_${jobId}`,
      inputAtomCount: params.atoms.length,
      ...(consolidation ? { consolidation } : {}),
      ...(appliedConsolidation ? { appliedConsolidation } : {}),
      ...(appliedLifecycle ? { appliedLifecycle } : {}),
      ...(abstraction !== undefined ? { abstraction } : {}),
      lifecycleEvaluations,
      duplicateReductionCount,
      estimatedTokensBefore,
      plannedTokensAfter,
      plannedTokenReduction,
      estimatedTokensOfPersistedRemovedAtoms,
      ...(estimatedCanonicalClaimTokensBefore !== undefined
        ? { estimatedCanonicalClaimTokensBefore }
        : {}),
      ...(estimatedCanonicalClaimTokensAfter !== undefined
        ? { estimatedCanonicalClaimTokensAfter }
        : {}),
      ...(estimatedCanonicalClaimTokenDelta !== undefined
        ? { estimatedCanonicalClaimTokenDelta }
        : {}),
    };

    const completedAt = new Date(params.nowMs ?? Date.now()).toISOString();
    if (params.jobStore && lease) {
      await params.jobStore.complete(jobId, report, lease);
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
      authorization: authz.decision,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (params.jobStore && lease) {
      await params.jobStore.fail(jobId, message, lease, params.nowMs);
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
      authorization: authz.decision,
    };
  }
}
