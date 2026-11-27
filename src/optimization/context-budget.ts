import type { CognitivePackage, MemoryAtom, PackageRiskMarker } from "../models.js";

export type OmissionReason = "budget_exceeded" | "low_priority";
export type BudgetStatus = "within_budget" | "unsatisfied_budget";

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
  budgetStatus: BudgetStatus;
  budgetedPackage: CognitivePackage;
  selectedMemoryIds: string[];
  omittedMemories: OmittedMemoryItem[];
  omittedFields: string[];
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

function measurePackageTokens(
  pkg: CognitivePackage,
  countTokens: (text: string) => number,
): number {
  return countTokens(JSON.stringify(pkg));
}

/**
 * MOP-06 Context Budgeting Engine (CW-04D-R1).
 * - Accounts for the FULL serialized CognitivePackage (not just claims).
 * - Never masks over-budget results (exposes budgetStatus: "unsatisfied_budget" and unclamped budgetUtilization).
 * - Trims optional fields (reasoningPath, risks, nextSteps) before dropping high-priority atoms.
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

  const omittedFields: string[] = [];

  // Build baseline skeleton without optional bulk fields if needed.
  let basePkg: CognitivePackage = {
    ...params.pkg,
    answer: {
      summary: params.pkg.answer.summary,
      recommendations: [],
      nextSteps: [...params.pkg.answer.nextSteps],
    },
    supportingAtoms: [],
    reasoningPath: [...params.pkg.reasoningPath],
    risks: [...params.pkg.risks],
    constraints: [...params.pkg.constraints],
    conflicts: [],
    evidenceRefs: [],
  };

  if (measurePackageTokens(basePkg, countTokens) > budgetTokens && basePkg.reasoningPath.length > 0) {
    basePkg = { ...basePkg, reasoningPath: [] };
    omittedFields.push("reasoningPath");
  }
  if (measurePackageTokens(basePkg, countTokens) > budgetTokens && basePkg.risks.length > 0) {
    basePkg = { ...basePkg, risks: [] };
    omittedFields.push("risks");
  }
  if (
    measurePackageTokens(basePkg, countTokens) > budgetTokens &&
    basePkg.answer.nextSteps.length > 0
  ) {
    basePkg = { ...basePkg, answer: { ...basePkg.answer, nextSteps: [] } };
    omittedFields.push("answer.nextSteps");
  }

  // If hard constraints + minimal package shell still exceed budgetTokens, fail explicitly with unsatisfied_budget.
  const shellTokens = measurePackageTokens(basePkg, countTokens);
  if (shellTokens > budgetTokens) {
    return {
      budgetStatus: "unsatisfied_budget",
      budgetedPackage: basePkg,
      selectedMemoryIds: [],
      omittedMemories: params.pkg.supportingAtoms.map((atomId) => ({
        atomId,
        reason: "budget_exceeded",
      })),
      omittedFields,
      tokenEstimate: shellTokens,
      budgetTokens,
      budgetUtilization: Number((shellTokens / budgetTokens).toFixed(4)),
      tokenAccounting,
      evidenceRefs: [],
      evidenceCompleteness: params.pkg.evidenceRefs.length === 0 ? 1 : 0,
      constraintsPreserved: [...basePkg.constraints],
      conflictWarnings: [],
    };
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

  let currentPkg = basePkg;

  for (const atom of ordered) {
    const rank = priorityRank(atom);
    if (rank === 1 && atom.metrics.confidence < minConfidence) {
      omittedMemories.push({ atomId: atom.id, reason: "low_priority" });
      continue;
    }

    const nextStatements = [...selectedStatements, atom.claim.statement];
    const nextIds = [...selectedMemoryIds, atom.id];
    const nextEv = new Set([...evidenceSet, ...atom.provenance.evidenceRefs]);
    const nextConflicts = [...conflicts];
    let nextWarning: ConflictWarning | undefined;

    if (atom.state.status === "conflicted" || (atom.state.conflictsWith?.length ?? 0) > 0) {
      const targetList = atom.state.conflictsWith ?? [];
      nextWarning = {
        atomId: atom.id,
        conflictsWith: [...targetList],
        statement: atom.claim.statement,
        resolutionHint: `Verify atom ${atom.id} against conflicting [${targetList.join(", ")}] before acting.`,
      };
      nextConflicts.push({
        atomId: atom.id,
        status: "conflicted",
        explanation: `Conflicts with [${targetList.join(", ")}]: ${atom.claim.statement}`,
      });
    }

    const candidatePkg: CognitivePackage = {
      ...currentPkg,
      answer: {
        ...currentPkg.answer,
        summary: nextStatements.join(" | "),
        recommendations: nextStatements,
      },
      supportingAtoms: nextIds,
      conflicts: nextConflicts,
      evidenceRefs: [...nextEv],
    };

    if (measurePackageTokens(candidatePkg, countTokens) > budgetTokens) {
      omittedMemories.push({ atomId: atom.id, reason: "budget_exceeded" });
      continue;
    }

    currentPkg = candidatePkg;
    selectedMemoryIds.push(atom.id);
    selectedStatements.push(atom.claim.statement);
    for (const ev of atom.provenance.evidenceRefs) evidenceSet.add(ev);
    if (nextWarning) {
      conflictWarnings.push(nextWarning);
      conflicts.push(nextConflicts[nextConflicts.length - 1]);
    }
  }

  const finalTokens = measurePackageTokens(currentPkg, countTokens);
  const totalPkgEvidence = new Set(params.pkg.evidenceRefs);
  let matchedPkgEvidence = 0;
  for (const ev of totalPkgEvidence) {
    if (evidenceSet.has(ev)) matchedPkgEvidence += 1;
  }
  const evidenceCompleteness =
    totalPkgEvidence.size === 0
      ? 1
      : Number(Math.min(1, matchedPkgEvidence / totalPkgEvidence.size).toFixed(4));

  return {
    budgetStatus: finalTokens <= budgetTokens ? "within_budget" : "unsatisfied_budget",
    budgetedPackage: currentPkg,
    selectedMemoryIds,
    omittedMemories,
    omittedFields,
    tokenEstimate: finalTokens,
    budgetTokens,
    budgetUtilization: Number((finalTokens / budgetTokens).toFixed(4)),
    tokenAccounting,
    evidenceRefs: [...evidenceSet],
    evidenceCompleteness,
    constraintsPreserved: [...currentPkg.constraints],
    conflictWarnings,
  };
}
