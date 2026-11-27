import type { CognitivePackage, MemoryAtom } from "../models.js";

export type OmissionReason = "budget_exceeded" | "low_priority";

export interface OmittedMemoryItem {
  atomId: string;
  reason: OmissionReason;
}

export interface ContextBudgetResult {
  selectedMemoryIds: string[];
  omittedMemories: OmittedMemoryItem[];
  tokenEstimate: number;
  budgetTokens: number;
  budgetUtilization: number;
  evidenceRefs: string[];
  evidenceCompleteness: number;
  constraintsPreserved: string[];
}

function estimateAtomTokens(atom: MemoryAtom): number {
  return Math.max(1, Math.ceil(`${atom.atomType}:${atom.claim.statement}`.length / 4));
}

function priorityRank(atom: MemoryAtom): number {
  if (atom.atomType === "policy" || atom.claim.type === "policy") return 4;
  if (atom.state.status === "conflicted") return 3;
  if (atom.atomType === "anti_pattern" || atom.atomType === "failure_pattern") return 2;
  return 1;
}

/**
 * MOP-06 Context Budgeting Engine.
 * Prioritizes constraints/policies, conflict warnings, and high-confidence evidence
 * instead of blind Top-K or raw text truncation.
 */
export function buildContextPackage(params: {
  pkg: CognitivePackage;
  atoms: ReadonlyArray<MemoryAtom>;
  budgetTokens: number;
}): ContextBudgetResult {
  const budgetTokens = Math.max(1, params.budgetTokens);
  const byId = new Map(params.atoms.map((a) => [a.id, a]));
  const ordered = params.pkg.supportingAtoms
    .map((id) => byId.get(id))
    .filter((a): a is MemoryAtom => Boolean(a))
    .toSorted((a, b) => {
      const rankDelta = priorityRank(b) - priorityRank(a);
      if (rankDelta !== 0) return rankDelta;
      return b.metrics.confidence - a.metrics.confidence;
    });

  const selectedMemoryIds: string[] = [];
  const omittedMemories: OmittedMemoryItem[] = [];
  const evidenceSet = new Set<string>();
  let tokenEstimate = 0;

  for (const atom of ordered) {
    const cost = estimateAtomTokens(atom);
    if (tokenEstimate + cost > budgetTokens) {
      omittedMemories.push({ atomId: atom.id, reason: "budget_exceeded" });
      continue;
    }
    tokenEstimate += cost;
    selectedMemoryIds.push(atom.id);
    for (const ev of atom.provenance.evidenceRefs) {
      evidenceSet.add(ev);
    }
  }

  const totalPkgEvidence = new Set(params.pkg.evidenceRefs);
  const evidenceCompleteness =
    totalPkgEvidence.size === 0
      ? 1
      : Number((evidenceSet.size / totalPkgEvidence.size).toFixed(4));

  return {
    selectedMemoryIds,
    omittedMemories,
    tokenEstimate,
    budgetTokens,
    budgetUtilization: Number(Math.min(1, tokenEstimate / budgetTokens).toFixed(4)),
    evidenceRefs: [...evidenceSet],
    evidenceCompleteness,
    constraintsPreserved: [...params.pkg.constraints],
  };
}
