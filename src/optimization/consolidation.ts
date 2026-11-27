import type { MemoryAtom } from "../models.js";

export type ConsolidationRelation =
  | "exact_duplicate"
  | "semantic_duplicate"
  | "compatible"
  | "related"
  | "conflicting"
  | "superseding";

export interface ConsolidationCluster {
  canonicalAtomId: string;
  sourceAtomIds: string[];
  evidenceRefs: string[];
  decision: ConsolidationRelation;
  versionHistory: number[];
  conflictAtomIds: string[];
}

export interface ConsolidationResult {
  clusters: ConsolidationCluster[];
  mergedCount: number;
  preservedConflictCount: number;
}

function normalizeWords(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .split(/[^a-z0-9\u4e00-\u9fff]+/i)
      .map((w) => w.trim())
      .filter((w) => w.length > 1),
  );
}

function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) {
    return 1;
  }
  if (a.size === 0 || b.size === 0) {
    return 0;
  }
  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) {
      intersection += 1;
    }
  }
  return intersection / (a.size + b.size - intersection);
}

function applicabilityCompatible(a: MemoryAtom, b: MemoryAtom): boolean {
  const incA = new Set(a.applicability?.include ?? []);
  const incB = new Set(b.applicability?.include ?? []);
  const excA = new Set(a.applicability?.exclude ?? []);
  const excB = new Set(b.applicability?.exclude ?? []);

  for (const item of incA) {
    if (excB.has(item)) {
      return false;
    }
  }
  for (const item of incB) {
    if (excA.has(item)) {
      return false;
    }
  }
  if (incA.size > 0 && incB.size > 0) {
    let overlap = false;
    for (const item of incA) {
      if (incB.has(item)) {
        overlap = true;
        break;
      }
    }
    if (!overlap) {
      return false;
    }
  }
  return true;
}

/**
 * MOP-02 Memory Consolidation Engine.
 * Merges exact/semantic duplicates only when non-conflicting and applicability-compatible,
 * preserving all source atom IDs and evidence references.
 */
export function consolidateAtoms(atoms: ReadonlyArray<MemoryAtom>): ConsolidationResult {
  const consumed = new Set<string>();
  const clusters: ConsolidationCluster[] = [];
  let mergedCount = 0;
  let preservedConflictCount = 0;

  for (let i = 0; i < atoms.length; i += 1) {
    const primary = atoms[i];
    if (consumed.has(primary.id)) {
      continue;
    }
    consumed.add(primary.id);

    const primaryConflicts = new Set(primary.state.conflictsWith ?? []);
    const primaryWords = normalizeWords(primary.claim.statement);
    const sourceAtomIds = [primary.id];
    const evidenceSet = new Set<string>(primary.provenance.evidenceRefs ?? []);
    const versions = [primary.versioning.version];
    const clusterConflicts = new Set<string>(primaryConflicts);
    let decision: ConsolidationRelation = "compatible";

    if (primary.state.status === "conflicted" || primaryConflicts.size > 0) {
      preservedConflictCount += 1;
      clusters.push({
        canonicalAtomId: primary.id,
        sourceAtomIds,
        evidenceRefs: [...evidenceSet],
        decision: "conflicting",
        versionHistory: versions,
        conflictAtomIds: [...clusterConflicts],
      });
      continue;
    }

    for (let j = i + 1; j < atoms.length; j += 1) {
      const candidate = atoms[j];
      if (consumed.has(candidate.id)) {
        continue;
      }
      const candidateConflicts = new Set(candidate.state.conflictsWith ?? []);
      if (
        candidate.state.status === "conflicted" ||
        primaryConflicts.has(candidate.id) ||
        candidateConflicts.has(primary.id)
      ) {
        continue;
      }
      if (primary.atomType !== candidate.atomType || !applicabilityCompatible(primary, candidate)) {
        continue;
      }

      const exact =
        (primary.dedupKey && candidate.dedupKey && primary.dedupKey === candidate.dedupKey) ||
        primary.claim.statement.trim().toLowerCase() ===
          candidate.claim.statement.trim().toLowerCase();
      const sim = exact
        ? 1
        : jaccardSimilarity(primaryWords, normalizeWords(candidate.claim.statement));

      if (exact || sim >= 0.75) {
        consumed.add(candidate.id);
        sourceAtomIds.push(candidate.id);
        for (const ev of candidate.provenance.evidenceRefs ?? []) {
          evidenceSet.add(ev);
        }
        versions.push(candidate.versioning.version);
        decision = exact ? "exact_duplicate" : "semantic_duplicate";
        mergedCount += 1;
      }
    }

    clusters.push({
      canonicalAtomId: primary.id,
      sourceAtomIds,
      evidenceRefs: [...evidenceSet],
      decision,
      versionHistory: versions,
      conflictAtomIds: [...clusterConflicts],
    });
  }

  return { clusters, mergedCount, preservedConflictCount };
}
