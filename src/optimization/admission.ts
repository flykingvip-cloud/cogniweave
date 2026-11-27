import { scoreAdmission } from "../domain/atom-v2.js";
import type { MemoryAtom } from "../models.js";

export type AdmissionDisposition = "accepted" | "tentative" | "rejected" | "pending_review";

export interface AdmissionEvaluationInput {
  atom: MemoryAtom;
  sourceAuthority?: "low" | "medium" | "high" | "authoritative";
  existingAtoms?: ReadonlyArray<MemoryAtom>;
  highRisk?: boolean;
}

export interface AdmissionEvaluationResult {
  disposition: AdmissionDisposition;
  admissionScore: number;
  requiresReview: boolean;
  duplicateOfAtomId?: string;
  conflictAtomIds: string[];
  reasons: string[];
}

function normalizeText(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, " ");
}

/**
 * MOP-01 Memory Admission Engine.
 * Reuses scoreAdmission() from domain/atom-v2.ts as the base numeric signal.
 */
export function evaluateAdmission(input: AdmissionEvaluationInput): AdmissionEvaluationResult {
  const { atom } = input;
  const admissionScore = scoreAdmission(atom);
  const reasons: string[] = [];
  const existing = input.existingAtoms ?? [];

  const normalizedStatement = normalizeText(atom.claim.statement);
  const exactDup = existing.find(
    (candidate) =>
      candidate.id !== atom.id &&
      (candidate.dedupKey && atom.dedupKey
        ? candidate.dedupKey === atom.dedupKey
        : normalizeText(candidate.claim.statement) === normalizedStatement),
  );
  if (exactDup) {
    return {
      disposition: "rejected",
      admissionScore,
      requiresReview: false,
      duplicateOfAtomId: exactDup.id,
      conflictAtomIds: [],
      reasons: ["exact_duplicate"],
    };
  }

  const conflictAtomIds = [...(atom.state.conflictsWith ?? [])];
  const hasEvidence = (atom.provenance?.evidenceRefs?.length ?? 0) > 0;
  if (!hasEvidence) {
    reasons.push("missing_evidence");
  }

  if (input.highRisk) {
    reasons.push("high_risk_requires_review");
    return {
      disposition: "pending_review",
      admissionScore,
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
      requiresReview: true,
      conflictAtomIds,
      reasons,
    };
  }

  if (!hasEvidence || admissionScore < 0.45) {
    reasons.push(admissionScore < 0.45 ? "low_admission_score" : "unverified_fact");
    return {
      disposition: "tentative",
      admissionScore,
      requiresReview: false,
      conflictAtomIds,
      reasons,
    };
  }

  if (input.sourceAuthority === "low" && admissionScore < 0.7) {
    reasons.push("low_source_authority");
    return {
      disposition: "tentative",
      admissionScore,
      requiresReview: false,
      conflictAtomIds,
      reasons,
    };
  }

  reasons.push("admitted_with_evidence");
  return {
    disposition: "accepted",
    admissionScore,
    requiresReview: false,
    conflictAtomIds,
    reasons,
  };
}
