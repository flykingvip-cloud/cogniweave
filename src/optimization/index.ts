export {
  evaluateAdmission,
  type AdmissionDisposition,
  type AdmissionEvaluationInput,
  type AdmissionEvaluationResult,
  type SourceAuthorityLevel,
} from "./admission.js";
export {
  applyConsolidation,
  consolidateAtoms,
  type AppliedConsolidationResult,
  type CanonicalCommitStatus,
  type ConsolidationCluster,
  type ConsolidationPlan,
  type ConsolidationRelation,
} from "./consolidation.js";
export { abstractFromAtoms, type AbstractedMemory } from "./abstraction.js";
export {
  applyLifecycleDecisions,
  DEFAULT_LIFECYCLE_POLICY,
  evaluateLifecycle,
  type AppliedLifecycleResult,
  type LifecycleAction,
  type LifecycleCanonicalCommitStatus,
  type LifecycleEvaluation,
  type LifecyclePolicy,
} from "./lifecycle.js";
export {
  optimizeRetrieval,
  type ExcludedRetrievalCandidate,
  type OptimizedRetrievalResult,
  type RetrievalAuthContext,
  type RetrievalCandidateDecision,
  type RetrievalDecisionTrace,
  type RetrievalExclusionReason,
} from "./retrieval.js";
export {
  buildContextPackage,
  type BudgetStatus,
  type ConflictWarning,
  type ContextBudgetResult,
  type OmissionReason,
  type OmittedMemoryItem,
} from "./context-budget.js";
export {
  computeOptimizationIdempotencyKey,
  runOptimizationJob,
  type MemoryOptimizationJob,
  type OptimizationExecutionContext,
  type OptimizationJobStatus,
  type OptimizationReport,
  type OptimizationType,
} from "./job.js";
