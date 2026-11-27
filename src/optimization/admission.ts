import { scoreAdmission } from "../domain/atom-v2.js";
import { computeScopeFingerprint } from "../keys.js";
import type { MemoryAtom } from "../models.js";

export type AdmissionDisposition = "accepted" | "tentative" | "rejected" | "pending_review";
export type SourceAuthorityLevel = "low" | "medium" | "high" | "authoritative";

export interface AdmissionEvaluationInput {
  atom: MemoryAtom;
  sourceAuthority?: SourceAuthorityLevel;
  existingAtoms?: ReadonlyArray<MemoryAtom>;
  highRisk?: boolean;
}

export interface AdmissionEvaluationResult {
  disposition: AdmissionDisposition;
  admissionScore: number;
  sourceAuthority: SourceAuthorityLevel;
  conflictMode: "heuristic_polarity";
  requiresReview: boolean;
  duplicateOfAtomId?: string;
  conflictAtomIds: string[];
  reasons: string[];
}

const AUTHORITY_MIN_SCORE: Record<SourceAuthorityLevel, number> = {
  low: 0.7,
  medium: 0.55,
  high: 0.45,
  authoritative: 0.35,
};

function normalizeText(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, " ");
}

function hasOpposingPolarityHeuristic(a: string, b: string): boolean {
  const negA = /\b(never|not|avoid|disable|forbid|dont|don't)\b/i.test(a);
  const negB = /\b(never|not|avoid|disable|forbid|dont|don't)\b/i.test(b);
  if (negA === negB) return false;

  const stripNeg = (s: string) =>
    new Set(
      s
        .toLowerCase()
        .replace(/\b(never|not|avoid|disable|forbid|dont|don't)\b/gi, "")
        .split(/[^a-z0-9\u4e00-\u9fff]+/i)
        .filter((w) => w.length > 2),
    );
  const wordsA = stripNeg(a);
  const wordsB = stripNeg(b);
  if (wordsA.size === 0 || wordsB.size === 0) return false;

  let overlap = 0;
  for (const w of wordsA) {
    if (wordsB.has(w)) overlap += 1;
  }
  return overlap / Math.min(wordsA.size, wordsB.size) >= 0.5;
}

/**
 * MOP-01 Memory Admission Engine (CW-04B-R2).
 * Isolates existingAtoms to the exact same ScopeFingerprint + visibility before
 * running duplicate detection and heuristic polarity conflict checks.
 */
export function evaluateAdmission(input: AdmissionEvaluationInput): AdmissionEvaluationResult {
  const { atom } = input;
  const sourceAuthority: SourceAuthorityLevel = input.sourceAuthority ?? "medium";
  const admissionScore = scoreAdmission(atom);
  const reasons: string[] = [];
  const targetScopeFp = computeScopeFingerprint(atom.scope);

  // CW-04B-R2: Scope-isolate existingAtoms so cross-agent/cross-workspace claims never pollute admission.
  const sameScopeExisting = (input.existingAtoms ?? []).filter(
    (candidate) =>
      candidate.id !== atom.id &&
      candidate.state.status !== "deprecated" &&
      computeScopeFingerprint(candidate.scope) === targetScopeFp,
  );

  const normalizedStatement = normalizeText(atom.claim.statement);
  const exactDup = sameScopeExisting.find(
    (candidate) =>
      (candidate.dedupKey && atom.dedupKey && candidate.dedupKey === atom.dedupKey) ||
      normalizeText(candidate.claim.statement) === normalizedStatement,
  );
  if (exactDup) {
    return {
      disposition: "rejected",
      admissionScore,
      sourceAuthority,
      conflictMode: "heuristic_polarity",
      requiresReview: false,
      duplicateOfAtomId: exactDup.id,
      conflictAtomIds: [],
      reasons: ["exact_duplicate"],
    };
  }

  const detectedConflicts = sameScopeExisting
    .filter((candidate) => hasOpposingPolarityHeuristic(atom.claim.statement, candidate.claim.statement))
    .map((c) => c.id);
  const conflictAtomIds = [...new Set([...(atom.state.conflictsWith ?? []), ...detectedConflicts])];

  const hasEvidence = (atom.provenance?.evidenceRefs?.length ?? 0) > 0;
  if (!hasEvidence) {
    reasons.push("missing_evidence");
  }

  if (input.highRisk) {
    reasons.push("high_risk_requires_review");
    return {
      disposition: "pending_review",
      admissionScore,
      sourceAuthority,
      conflictMode: "heuristic_polarity",
      requiresReview: true,
      conflictAtomIds,
      reasons,
    };
  }

  if (conflictAtomIds.length > 0) {
    reasons.push("has_conflicts");
    return {
      disposition: "pending_review",
      admissionScore,
      sourceAuthority,
      conflictMode: "heuristic_polarity",
      requiresReview: true,
      conflictAtomIds,
      reasons,
    };
  }

  if (!hasEvidence) {
    reasons.push("unverified_fact");
    return {
      disposition: "tentative",
      admissionScore,
      sourceAuthority,
      conflictMode: "heuristic_polarity",
      requiresReview: false,
      conflictAtomIds,
      reasons,
    };
  }

  const minScore = AUTHORITY_MIN_SCORE[sourceAuthority];
  if (admissionScore < minScore) {
    reasons.push(`below_authority_threshold:${sourceAuthority}`);
    return {
      disposition: "tentative",
      admissionScore,
      sourceAuthority,
      conflictMode: "heuristic_polarity",
      requiresReview: false,
      conflictAtomIds,
      reasons,
    };
  }

  reasons.push(`admitted_with_authority:${sourceAuthority}`);
  return {
    disposition: "accepted",
    admissionScore,
    sourceAuthority,
    conflictMode: "heuristic_polarity",
    requiresReview: false,
    conflictAtomIds,
    reasons,
  };
}
