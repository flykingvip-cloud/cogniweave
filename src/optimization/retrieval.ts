import { scoreRetrieval } from "../domain/atom-v2.js";
import { computeScopeFingerprint } from "../keys.js";
import type {
  MemoryAtom,
  MemoryPartitionKeyV1,
  MemorySubject,
  MemorySubjectBinding,
  Scope,
  TaskFrame,
} from "../models.js";
import { isAtomRetrievable } from "../retrieval/lifecycle-gate.js";
import { authorizeMemoryAccess } from "../subject/binding.js";

export type RetrievalExclusionReason =
  | "unauthorized"
  | "deprecated"
  | "conflicted"
  | "scope_mismatch"
  | "low_relevance"
  | "budget_exceeded";

export interface RetrievalCandidateDecision {
  atom: MemoryAtom;
  baseScore: number;
  taskBonus: number;
  score: number;
  estimatedTokens: number;
  authorized: boolean;
}

export interface ExcludedRetrievalCandidate {
  atomId: string;
  reason: RetrievalExclusionReason;
}

export interface RetrievalDecisionTrace {
  authorizedBy: "subject_binding" | "pre_authorized" | "denied";
  tokenAccounting: "exact" | "estimated";
  latencyMs: number;
  totalCandidates: number;
  selectedCount: number;
  excludedCount: number;
}

export interface OptimizedRetrievalResult {
  selectedAtoms: RetrievalCandidateDecision[];
  excludedCandidates: ExcludedRetrievalCandidate[];
  evidenceRefs: string[];
  estimatedTokenCost: number;
  trace: RetrievalDecisionTrace;
}

function defaultTokenCounter(text: string): number {
  return Math.max(1, Math.ceil(text.length / 4));
}

function taskFrameMatchScore(taskFrame: TaskFrame, atom: MemoryAtom): number {
  let bonus = 0;
  if (taskFrame.requiredAtomTypes.includes(atom.atomType)) {
    bonus += 0.2;
  }
  const frameTerms = new Set(
    [
      ...taskFrame.scenarioTags,
      ...taskFrame.entities,
      ...taskFrame.goals,
      ...taskFrame.problems,
      ...taskFrame.constraints,
    ]
      .join(" ")
      .toLowerCase()
      .split(/[^a-z0-9\u4e00-\u9fff]+/i)
      .filter((t) => t.length > 2),
  );
  for (const tag of atom.trigger.contextTags) {
    if (frameTerms.has(tag.toLowerCase())) bonus += 0.08;
  }
  for (const word of atom.claim.statement.toLowerCase().split(/[^a-z0-9]+/)) {
    if (word.length > 3 && frameTerms.has(word)) {
      bonus += 0.04;
    }
  }
  if (taskFrame.riskLevel === "high" && (atom.atomType === "policy" || atom.atomType === "anti_pattern")) {
    bonus += 0.1;
  }
  if (taskFrame.timeHorizon === "short" && atom.lifecycle?.retentionClass === "ephemeral") {
    bonus += 0.05;
  }
  return Math.min(0.45, Number(bonus.toFixed(4)));
}

function scopeMatches(target: Scope, candidate: Scope): boolean {
  return computeScopeFingerprint(target) === computeScopeFingerprint(candidate) ||
    (target.workspaceId === candidate.workspaceId &&
      target.projectId === candidate.projectId &&
      candidate.visibility === "shared");
}

/**
 * MOP-05 Task-driven Retrieval Optimizer.
 * Enforces explicit SubjectBinding authorization (fail-closed if auth provided and denied),
 * uses full TaskFrame context, supports pluggable tokenCounter, and emits RetrievalDecisionTrace.
 */
export function optimizeRetrieval(params: {
  taskFrame: TaskFrame;
  candidates: ReadonlyArray<MemoryAtom>;
  contextBudgetTokens?: number;
  includeConflicted?: boolean;
  preAuthorized?: boolean;
  auth?: {
    caller: MemorySubject;
    bindings: ReadonlyArray<MemorySubjectBinding>;
    partition: MemoryPartitionKeyV1;
  };
  tokenCounter?: (text: string) => number;
}): OptimizedRetrievalResult {
  const started = performance.now();
  const budget = Math.max(1, params.contextBudgetTokens ?? 2000);
  const countTokens = params.tokenCounter ?? defaultTokenCounter;
  const tokenAccounting: "exact" | "estimated" = params.tokenCounter ? "exact" : "estimated";

  let authorized = false;
  let authorizedBy: RetrievalDecisionTrace["authorizedBy"] = "denied";
  if (params.auth) {
    const acl = authorizeMemoryAccess(params.auth.bindings, {
      partition: params.auth.partition,
      caller: params.auth.caller,
    });
    authorized = acl.allowed;
    authorizedBy = acl.allowed ? "subject_binding" : "denied";
  } else if (params.preAuthorized) {
    authorized = true;
    authorizedBy = "pre_authorized";
  }

  if (!authorized) {
    return {
      selectedAtoms: [],
      excludedCandidates: params.candidates.map((c) => ({ atomId: c.id, reason: "unauthorized" })),
      evidenceRefs: [],
      estimatedTokenCost: 0,
      trace: {
        authorizedBy: "denied",
        tokenAccounting,
        latencyMs: Number((performance.now() - started).toFixed(3)),
        totalCandidates: params.candidates.length,
        selectedCount: 0,
        excludedCount: params.candidates.length,
      },
    };
  }

  const excludedCandidates: ExcludedRetrievalCandidate[] = [];
  const scored: RetrievalCandidateDecision[] = [];

  for (const atom of params.candidates) {
    if (!scopeMatches(params.taskFrame.scope, atom.scope)) {
      excludedCandidates.push({ atomId: atom.id, reason: "scope_mismatch" });
      continue;
    }
    const retrievability = isAtomRetrievable(atom, {
      includeConflicted: params.includeConflicted,
    });
    if (!retrievability.retrievable) {
      excludedCandidates.push({
        atomId: atom.id,
        reason: retrievability.reason === "conflicted" ? "conflicted" : "deprecated",
      });
      continue;
    }

    const baseScore = scoreRetrieval(atom);
    const taskBonus = taskFrameMatchScore(params.taskFrame, atom);
    const totalScore = Number(Math.min(1, baseScore * 0.7 + taskBonus).toFixed(4));
    if (totalScore < 0.15) {
      excludedCandidates.push({ atomId: atom.id, reason: "low_relevance" });
      continue;
    }

    const text = `${atom.atomType} ${atom.claim.statement} ${atom.trigger.conditions.join(" ")}`;
    scored.push({
      atom,
      baseScore,
      taskBonus,
      score: totalScore,
      estimatedTokens: countTokens(text),
      authorized: true,
    });
  }

  scored.sort((a, b) => b.score - a.score);

  const selectedAtoms: RetrievalCandidateDecision[] = [];
  const evidenceSet = new Set<string>();
  let usedTokens = 0;

  for (const item of scored) {
    if (usedTokens + item.estimatedTokens > budget) {
      excludedCandidates.push({ atomId: item.atom.id, reason: "budget_exceeded" });
      continue;
    }
    usedTokens += item.estimatedTokens;
    selectedAtoms.push(item);
    for (const ev of item.atom.provenance.evidenceRefs) {
      evidenceSet.add(ev);
    }
  }

  return {
    selectedAtoms,
    excludedCandidates,
    evidenceRefs: [...evidenceSet],
    estimatedTokenCost: usedTokens,
    trace: {
      authorizedBy,
      tokenAccounting,
      latencyMs: Number((performance.now() - started).toFixed(3)),
      totalCandidates: params.candidates.length,
      selectedCount: selectedAtoms.length,
      excludedCount: excludedCandidates.length,
    },
  };
}
