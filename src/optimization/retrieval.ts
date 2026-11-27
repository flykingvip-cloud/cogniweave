import { scoreRetrieval } from "../domain/atom-v2.js";
import type { MemoryAtom, Scope, TaskFrame } from "../models.js";
import { isAtomRetrievable } from "../retrieval/lifecycle-gate.js";

export type RetrievalExclusionReason =
  | "deprecated"
  | "conflicted"
  | "scope_mismatch"
  | "low_relevance"
  | "budget_exceeded";

export interface RetrievalCandidateDecision {
  atom: MemoryAtom;
  score: number;
  estimatedTokens: number;
}

export interface ExcludedRetrievalCandidate {
  atomId: string;
  reason: RetrievalExclusionReason;
}

export interface OptimizedRetrievalResult {
  selectedAtoms: RetrievalCandidateDecision[];
  excludedCandidates: ExcludedRetrievalCandidate[];
  evidenceRefs: string[];
  estimatedTokenCost: number;
}

function estimateAtomTokens(atom: MemoryAtom): number {
  const text = `${atom.atomType} ${atom.claim.statement} ${atom.trigger.conditions.join(" ")}`;
  return Math.max(1, Math.ceil(text.length / 4));
}

function taskFrameMatchScore(taskFrame: TaskFrame, atom: MemoryAtom): number {
  let bonus = 0;
  if (taskFrame.requiredAtomTypes.includes(atom.atomType)) {
    bonus += 0.25;
  }
  const tags = new Set([
    ...taskFrame.scenarioTags.map((t) => t.toLowerCase()),
    ...taskFrame.entities.map((e) => e.toLowerCase()),
  ]);
  for (const tag of atom.trigger.contextTags) {
    if (tags.has(tag.toLowerCase())) {
      bonus += 0.1;
    }
  }
  return Math.min(0.45, bonus);
}

function scopeMatches(target: Scope, candidate: Scope): boolean {
  if (target.workspaceId !== candidate.workspaceId || target.projectId !== candidate.projectId) {
    return false;
  }
  return candidate.visibility === "shared" || candidate.agentId === target.agentId;
}

/**
 * MOP-05 Task-driven Retrieval Optimizer.
 * Combines lifecycle gating, scope matching, scoreRetrieval(), task-frame alignment, and token budget.
 */
export function optimizeRetrieval(params: {
  taskFrame: TaskFrame;
  candidates: ReadonlyArray<MemoryAtom>;
  contextBudgetTokens?: number;
  includeConflicted?: boolean;
}): OptimizedRetrievalResult {
  const budget = Math.max(1, params.contextBudgetTokens ?? 2000);
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

    const base = scoreRetrieval(atom);
    const taskBonus = taskFrameMatchScore(params.taskFrame, atom);
    const totalScore = Number(Math.min(1, base * 0.7 + taskBonus).toFixed(4));
    if (totalScore < 0.15) {
      excludedCandidates.push({ atomId: atom.id, reason: "low_relevance" });
      continue;
    }
    scored.push({
      atom,
      score: totalScore,
      estimatedTokens: estimateAtomTokens(atom),
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
  };
}
