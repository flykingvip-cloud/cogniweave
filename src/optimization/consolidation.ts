import { randomUUID } from "node:crypto";
import { computeScopeFingerprint } from "../keys.js";
import type { MemoryAtom, Scope, WriteJournal } from "../models.js";
import type { GraphStore, MetadataStore, VectorStore } from "../storage/types.js";

export type ConsolidationRelation =
  | "exact_duplicate"
  | "lexical_similarity"
  | "compatible"
  | "related"
  | "conflicting"
  | "superseding";

export interface ConsolidationCluster {
  canonicalAtomId: string;
  scope: Scope;
  sourceAtomIds: string[];
  evidenceRefs: string[];
  decision: ConsolidationRelation;
  versionHistory: number[];
  conflictAtomIds: string[];
}

export interface ConsolidationPlan {
  clusters: ConsolidationCluster[];
  excludedInactiveIds: string[];
  mergedCount: number;
  preservedConflictCount: number;
}

export type CanonicalCommitStatus = "COMMITTED" | "PARTIAL_COMMIT" | "RECOVERY_REQUIRED";

export interface AppliedConsolidationResult {
  plan: ConsolidationPlan;
  journalId: string;
  canonicalCommitted: boolean;
  canonicalCommitStatus: CanonicalCommitStatus;
  derivedIndexesSynced: boolean;
  derivedSyncError?: string;
  updatedCanonicalIds: string[];
  deprecatedSourceIds: string[];
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
  if (a.size === 0 && b.size === 0) return 1;
  if (a.size === 0 || b.size === 0) return 0;
  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) intersection += 1;
  }
  return intersection / (a.size + b.size - intersection);
}

function applicabilityCompatible(a: MemoryAtom, b: MemoryAtom): boolean {
  const incA = new Set(a.applicability?.include ?? []);
  const incB = new Set(b.applicability?.include ?? []);
  const excA = new Set(a.applicability?.exclude ?? []);
  const excB = new Set(b.applicability?.exclude ?? []);

  for (const item of incA) if (excB.has(item)) return false;
  for (const item of incB) if (excA.has(item)) return false;
  if (incA.size > 0 && incB.size > 0) {
    let overlap = false;
    for (const item of incA) {
      if (incB.has(item)) {
        overlap = true;
        break;
      }
    }
    if (!overlap) return false;
  }
  return true;
}

function isInactiveAtom(atom: MemoryAtom): boolean {
  return (
    atom.state.status === "deprecated" ||
    Boolean(atom.lifecycle?.deprecatedAt) ||
    Boolean(atom.lifecycle?.tombstonedAt)
  );
}

export function consolidateAtoms(atoms: ReadonlyArray<MemoryAtom>): ConsolidationPlan {
  const excludedInactiveIds: string[] = [];
  const activeAtoms: MemoryAtom[] = [];
  for (const atom of atoms) {
    if (isInactiveAtom(atom)) {
      excludedInactiveIds.push(atom.id);
    } else {
      activeAtoms.push(atom);
    }
  }

  const consumed = new Set<string>();
  const clusters: ConsolidationCluster[] = [];
  let mergedCount = 0;
  let preservedConflictCount = 0;

  for (let i = 0; i < activeAtoms.length; i += 1) {
    const primary = activeAtoms[i];
    if (consumed.has(primary.id)) continue;
    consumed.add(primary.id);

    const primaryScopeFp = computeScopeFingerprint(primary.scope);
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
        scope: primary.scope,
        sourceAtomIds,
        evidenceRefs: [...evidenceSet],
        decision: "conflicting",
        versionHistory: versions,
        conflictAtomIds: [...clusterConflicts],
      });
      continue;
    }

    for (let j = i + 1; j < activeAtoms.length; j += 1) {
      const candidate = activeAtoms[j];
      if (consumed.has(candidate.id)) continue;
      if (computeScopeFingerprint(candidate.scope) !== primaryScopeFp) continue;

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
        decision = exact ? "exact_duplicate" : "lexical_similarity";
        mergedCount += 1;
      }
    }

    clusters.push({
      canonicalAtomId: primary.id,
      scope: primary.scope,
      sourceAtomIds,
      evidenceRefs: [...evidenceSet],
      decision,
      versionHistory: versions,
      conflictAtomIds: [...clusterConflicts],
    });
  }

  return { clusters, excludedInactiveIds, mergedCount, preservedConflictCount };
}

/**
 * MOP-02 Phase 2: Transactional Canonical Consolidation Write-back (CW-04E-R1).
 * - Wraps canonical updates in metadataStore.withTransaction() when available.
 * - Writes a WriteJournal entry tracking canonical commit vs derived index sync.
 * - Explicitly reports derivedIndexesSynced=false if GraphStore/VectorStore are absent or fail.
 */
export async function applyConsolidation(params: {
  plan: ConsolidationPlan;
  metadataStore: MetadataStore;
  graphStore?: GraphStore;
  vectorStore?: VectorStore;
  now?: string;
}): Promise<AppliedConsolidationResult> {
  const updatedCanonicalIds: string[] = [];
  const deprecatedSourceIds: string[] = [];
  const now = params.now ?? new Date().toISOString();
  const journalId = `jrnl_cons_${randomUUID().slice(0, 12)}`;
  const journal: WriteJournal = {
    id: journalId,
    eventKey: journalId,
    status: "RECEIVED",
    phase: "RECEIVED",
    retryCount: 0,
    objectIds: {
      eventIds: [],
      atomIds: [],
      entityIds: [],
      scenarioIds: [],
      problemIds: [],
      evidenceIds: [],
      relationIds: [],
    },
    derivedPlan: {
      graphNodeIds: [],
      graphEdgeIds: [],
      vectorDocIds: [],
    },
    updatedAt: now,
  };
  await params.metadataStore.putJournal(journal);

  const runCanonicalWrites = async () => {
    for (const cluster of params.plan.clusters) {
      if (cluster.sourceAtomIds.length <= 1 || cluster.decision === "conflicting") continue;
      const canonical = await params.metadataStore.getAtom(cluster.canonicalAtomId);
      if (!canonical) continue;

      await params.metadataStore.saveAtom({
        ...canonical,
        provenance: {
          ...canonical.provenance,
          evidenceRefs: [...new Set([...canonical.provenance.evidenceRefs, ...cluster.evidenceRefs])],
        },
        versioning: { ...canonical.versioning, version: canonical.versioning.version + 1 },
      });
      updatedCanonicalIds.push(canonical.id);

      for (const sourceId of cluster.sourceAtomIds) {
        if (sourceId === canonical.id) continue;
        const src = await params.metadataStore.getAtom(sourceId);
        if (!src) continue;
        await params.metadataStore.saveAtom({
          ...src,
          state: { ...src.state, status: "deprecated" },
          lifecycle: { ...src.lifecycle, deprecatedAt: now },
          versioning: {
            ...src.versioning,
            version: src.versioning.version + 1,
            parentVersion: canonical.id,
          },
        });
        deprecatedSourceIds.push(src.id);
      }
    }
  };

  let canonicalCommitStatus: CanonicalCommitStatus = "PARTIAL_COMMIT";
  if (params.metadataStore.withTransaction) {
    await params.metadataStore.withTransaction(runCanonicalWrites);
    canonicalCommitStatus = "COMMITTED";
  } else {
    await runCanonicalWrites();
    canonicalCommitStatus = updatedCanonicalIds.length === 0 ? "COMMITTED" : "PARTIAL_COMMIT";
  }

  let derivedIndexesSynced = false;
  let derivedSyncError: string | undefined;

  if (deprecatedSourceIds.length === 0) {
    derivedIndexesSynced = true;
  } else if (
    typeof params.graphStore?.delete !== "function" ||
    typeof params.vectorStore?.delete !== "function"
  ) {
    derivedIndexesSynced = false;
    derivedSyncError = "derived_store_delete_unsupported";
  } else {
    try {
      await params.graphStore.delete(deprecatedSourceIds);
      await params.vectorStore.delete(deprecatedSourceIds);
      derivedIndexesSynced = true;
    } catch (err) {
      derivedIndexesSynced = false;
      derivedSyncError = err instanceof Error ? err.message : String(err);
    }
  }

  await params.metadataStore.updateJournal(journalId, {
    status:
      canonicalCommitStatus === "COMMITTED" && derivedIndexesSynced
        ? "COMPLETED"
        : "DERIVED_OUT_OF_SYNC",
    phase:
      canonicalCommitStatus === "COMMITTED" && derivedIndexesSynced
        ? "COMPLETED"
        : "METADATA_COMMITTED",
    objectIds: {
      ...journal.objectIds,
      atomIds: [...updatedCanonicalIds, ...deprecatedSourceIds],
    },
    lastError: derivedSyncError,
    updatedAt: new Date().toISOString(),
  });

  return {
    plan: params.plan,
    journalId,
    canonicalCommitted: canonicalCommitStatus === "COMMITTED",
    canonicalCommitStatus,
    derivedIndexesSynced,
    ...(derivedSyncError ? { derivedSyncError } : {}),
    updatedCanonicalIds,
    deprecatedSourceIds,
  };
}
