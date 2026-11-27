import type { CognitivePackage, MemoryAtom, PackageRiskMarker } from "../models.js";

export type OmissionReason = "budget_exceeded" | "low_priority";

export interface OmittedMemoryItem {
  atomId: string;
  reason: OmissionReason;
}

export interface ConflictWarning {
  atomId: string;
  conflictsWith: string[];
  statement: string;
  resolutionHint: string;
}

export interface ContextBudgetResult {
  budgetedPackage: CognitivePackage;
  selectedMemoryIds: string[];
  omittedMemories: OmittedMemoryItem[];
  tokenEstimate: number;
  budgetTokens: number;
  budgetUtilization: number;
  tokenAccounting: "exact" | "estimated";
  evidenceRefs: string[];
  evidenceCompleteness: number;
  constraintsPreserved: string[];
  conflictWarnings: ConflictWarning[];
}

function defaultTokenCounter(text: string): number {
  return Math.max(1, Math.ceil(text.length / 4));
}

function priorityRank(atom: MemoryAtom): number {
  if (atom.atomType === "policy" || atom.claim.type === "policy") return 4;
  if (atom.state.status === "conflicted" || (atom.state.conflictsWith?.length ?? 0) > 0) return 3;
  if (atom.atomType === "anti_pattern" || atom.atomType === "failure_pattern") return 2;
  return 1;
}

/**
 * MOP-06 Context Budgeting Engine.
 * Produces a genuinely trimmed, semantically coherent CognitivePackage within budgetTokens,
 * accounting for constraints in the token budget, clamping evidenceCompleteness to [0, 1],
 * and preserving conflict pairs + resolution hints.
 */
export function buildContextPackage(params: {
  pkg: CognitivePackage;
  atoms: ReadonlyArray<MemoryAtom>;
  budgetTokens: number;
  minConfidence?: number;
  tokenCounter?: (text: string) => number;
}): ContextBudgetResult {
  const budgetTokens = Math.max(1, params.budgetTokens);
  const countTokens = params.tokenCounter ?? defaultTokenCounter;
  const tokenAccounting: "exact" | "estimated" = params.tokenCounter ? "exact" : "estimated";
  const minConfidence = params.minConfidence ?? 0.3;

  let tokenEstimate = 0;
  const constraintsPreserved: string[] = [];
  for (const constraint of params.pkg.constraints) {
    const cost = countTokens(constraint);
    if (tokenEstimate + cost <= budgetTokens || constraintsPreserved.length === 0) {
      constraintsPreserved.push(constraint);
      tokenEstimate += cost;
    }
  }

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
  const selectedStatements: string[] = [];
  const omittedMemories: OmittedMemoryItem[] = [];
  const evidenceSet = new Set<string>();
  const conflictWarnings: ConflictWarning[] = [];
  const conflicts: PackageRiskMarker[] = [];

  for (const atom of ordered) {
    const rank = priorityRank(atom);
    if (rank === 1 && atom.metrics.confidence < minConfidence) {
      omittedMemories.push({ atomId: atom.id, reason: "low_priority" });
      continue;
    }

    const cost = countTokens(`${atom.atomType}:${atom.claim.statement}`);
    if (tokenEstimate + cost > budgetTokens) {
      omittedMemories.push({ atomId: atom.id, reason: "budget_exceeded" });
      continue;
    }

    tokenEstimate += cost;
    selectedMemoryIds.push(atom.id);
    selectedStatements.push(atom.claim.statement);

    for (const ev of atom.provenance.evidenceRefs) {
      evidenceSet.add(ev);
    }

    if (atom.state.status === "conflicted" || (atom.state.conflictsWith?.length ?? 0) > 0) {
      const targetList = atom.state.conflictsWith ?? [];
      conflictWarnings.push({
        atomId: atom.id,
        conflictsWith: [...targetList],
        statement: atom.claim.statement,
        resolutionHint: `Verify atom ${atom.id} against conflicting [${targetList.join(", ")}] before acting.`,
      });
      conflicts.push({
        atomId: atom.id,
        status: "conflicted",
        explanation: `Conflicts with [${targetList.join(", ")}]: ${atom.claim.statement}`,
      });
    }
  }

  // Clamp evidenceCompleteness to [0, 1] strictly against pkg.evidenceRefs.
  const totalPkgEvidence = new Set(params.pkg.evidenceRefs);
  let matchedPkgEvidence = 0;
  for (const ev of totalPkgEvidence) {
    if (evidenceSet.has(ev)) matchedPkgEvidence += 1;
  }
  const evidenceCompleteness =
    totalPkgEvidence.size === 0
      ? 1
      : Number(Math.min(1, matchedPkgEvidence / totalPkgEvidence.size).toFixed(4));

  const budgetedPackage: CognitivePackage = {
    ...params.pkg,
    answer: {
      summary:
        selectedStatements.length > 0
          ? selectedStatements.join(" | ")
          : params.pkg.answer.summary,
      recommendations:
        selectedStatements.length > 0
          ? selectedStatements
          : params.pkg.answer.recommendations,
      nextSteps: params.pkg.answer.nextSteps,
    },
    supportingAtoms: selectedMemoryIds,
    constraints: constraintsPreserved,
    conflicts: conflicts.length > 0 ? conflicts : params.pkg.conflicts,
    evidenceRefs: [...evidenceSet],
  };

  return {
    budgetedPackage,
    selectedMemoryIds,
    omittedMemories,
    tokenEstimate,
    budgetTokens,
    budgetUtilization: Number(Math.min(1, tokenEstimate / budgetTokens).toFixed(4)),
    tokenAccounting,
    evidenceRefs: [...evidenceSet],
    evidenceCompleteness,
    constraintsPreserved,
    conflictWarnings,
  };
}
