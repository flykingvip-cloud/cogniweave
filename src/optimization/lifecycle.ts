import { randomUUID } from "node:crypto";
import type { MemoryAtom, WriteJournal } from "../models.js";
import type { GraphStore, MetadataStore, VectorStore } from "../storage/types.js";

export type LifecycleAction =
  | "keep_active"
  | "revalidate"
  | "deprioritize"
  | "archive"
  | "deprecate"
  | "tombstone"
  | "purge";

export interface LifecyclePolicy {
  ephemeralHalfLifeDays: number;
  standardHalfLifeDays: number;
  durableHalfLifeDays: number;
  ephemeralArchiveDays: number;
  purgeAfterArchiveDays: number;
  revalidateThreshold: number;
  deprioritizeThreshold: number;
}

export const DEFAULT_LIFECYCLE_POLICY: LifecyclePolicy = {
  ephemeralHalfLifeDays: 7,
  standardHalfLifeDays: 60,
  durableHalfLifeDays: 180,
  ephemeralArchiveDays: 30,
  purgeAfterArchiveDays: 90,
  revalidateThreshold: 0.25,
  deprioritizeThreshold: 0.45,
};

export interface LifecycleEvaluation {
  atomId: string;
  action: LifecycleAction;
  decayedValue: number;
  retrievable: boolean;
  legalHold: boolean;
  reason: string;
}

export interface AppliedLifecycleResult {
  journalId: string;
  canonicalCommitted: boolean;
  archivedIds: string[];
  deprecatedIds: string[];
  tombstonedIds: string[];
  revalidatedIds: string[];
  deprioritizedIds: string[];
  purgedIds: string[];
  derivedIndexesSynced: boolean;
  derivedSyncError?: string;
}

export function evaluateLifecycle(
  atom: MemoryAtom,
  options?: {
    nowMs?: number;
    supersededByAtomId?: string;
    evidenceInvalidated?: boolean;
    policy?: Partial<LifecyclePolicy>;
  },
): LifecycleEvaluation {
  const policy: LifecyclePolicy = { ...DEFAULT_LIFECYCLE_POLICY, ...options?.policy };
  const retention = atom.lifecycle?.retentionClass ?? "standard";
  const nowMs = options?.nowMs ?? Date.now();

  if (retention === "legal_hold") {
    const retrievable = atom.state.status === "active" && !options?.evidenceInvalidated;
    return {
      atomId: atom.id,
      action: "keep_active",
      decayedValue: atom.metrics.confidence,
      retrievable,
      legalHold: true,
      reason: options?.evidenceInvalidated
        ? "legal_hold_retained_but_evidence_invalidated"
        : "protected_by_legal_hold",
    };
  }

  if (options?.evidenceInvalidated) {
    return {
      atomId: atom.id,
      action: "revalidate",
      decayedValue: 0,
      retrievable: false,
      legalHold: false,
      reason: "evidence_invalidated",
    };
  }

  if (options?.supersededByAtomId) {
    return {
      atomId: atom.id,
      action: "deprecate",
      decayedValue: 0,
      retrievable: false,
      legalHold: false,
      reason: `superseded_by:${options.supersededByAtomId}`,
    };
  }

  if (atom.lifecycle?.tombstonedAt) {
    const tombMs = Date.parse(atom.lifecycle.tombstonedAt);
    if (Number.isFinite(tombMs) && (nowMs - tombMs) / (1000 * 60 * 60 * 24) >= policy.purgeAfterArchiveDays) {
      return {
        atomId: atom.id,
        action: "purge",
        decayedValue: 0,
        retrievable: false,
        legalHold: false,
        reason: "tombstone_grace_expired",
      };
    }
    return {
      atomId: atom.id,
      action: "tombstone",
      decayedValue: 0,
      retrievable: false,
      legalHold: false,
      reason: "already_tombstoned",
    };
  }

  if (atom.state.status === "deprecated") {
    const depMs = atom.lifecycle?.deprecatedAt ? Date.parse(atom.lifecycle.deprecatedAt) : Number.NaN;
    if (Number.isFinite(depMs) && (nowMs - depMs) / (1000 * 60 * 60 * 24) >= policy.purgeAfterArchiveDays) {
      return {
        atomId: atom.id,
        action: "purge",
        decayedValue: 0,
        retrievable: false,
        legalHold: false,
        reason: "deprecated_grace_expired",
      };
    }
    return {
      atomId: atom.id,
      action: "archive",
      decayedValue: 0,
      retrievable: false,
      legalHold: false,
      reason: "deprecated_ready_for_archive",
    };
  }

  if (atom.state.status === "conflicted" || (atom.state.conflictsWith?.length ?? 0) > 0) {
    return {
      atomId: atom.id,
      action: "revalidate",
      decayedValue: Number((atom.metrics.confidence * 0.5).toFixed(4)),
      retrievable: false,
      legalHold: false,
      reason: "conflicted_requires_revalidation",
    };
  }

  const lastTouch = atom.lifecycle?.lastRetrievedAt ?? atom.lifecycle?.admittedAt;
  if (!lastTouch) {
    return {
      atomId: atom.id,
      action: "revalidate",
      decayedValue: atom.metrics.confidence,
      retrievable: atom.state.status === "active",
      legalHold: false,
      reason: "missing_timestamp_requires_revalidation",
    };
  }
  const parsedMs = Date.parse(lastTouch);
  if (!Number.isFinite(parsedMs)) {
    return {
      atomId: atom.id,
      action: "revalidate",
      decayedValue: atom.metrics.confidence,
      retrievable: false,
      legalHold: false,
      reason: "invalid_timestamp_requires_revalidation",
    };
  }

  const ageDays = Math.max(0, (nowMs - parsedMs) / (1000 * 60 * 60 * 24));
  const halfLifeDays =
    retention === "ephemeral"
      ? policy.ephemeralHalfLifeDays
      : retention === "durable"
        ? policy.durableHalfLifeDays
        : policy.standardHalfLifeDays;
  const decayFactor = Math.pow(0.5, ageDays / halfLifeDays);
  const reuseBoost = Math.min(0.25, atom.metrics.reuseCount * 0.03);
  const decayedValue = Number(
    Math.min(1, Math.max(0, atom.metrics.confidence * decayFactor + reuseBoost)).toFixed(4),
  );

  if (retention === "ephemeral" && ageDays > policy.ephemeralArchiveDays && atom.metrics.reuseCount === 0) {
    return {
      atomId: atom.id,
      action: "archive",
      decayedValue,
      retrievable: false,
      legalHold: false,
      reason: "ephemeral_stale_unused",
    };
  }

  if (decayedValue < policy.revalidateThreshold) {
    return {
      atomId: atom.id,
      action: "revalidate",
      decayedValue,
      retrievable: true,
      legalHold: false,
      reason: "value_decayed_below_threshold",
    };
  }

  if (decayedValue < policy.deprioritizeThreshold) {
    return {
      atomId: atom.id,
      action: "deprioritize",
      decayedValue,
      retrievable: true,
      legalHold: false,
      reason: "low_recent_utility",
    };
  }

  return {
    atomId: atom.id,
    action: "keep_active",
    decayedValue,
    retrievable: true,
    legalHold: false,
    reason: "healthy_active_memory",
  };
}

/**
 * CW-04F-R1: Complete Lifecycle State Execution across Canonical Store and Derived Indexes.
 * Persists purge, tombstone, archive, deprecate, revalidate, and deprioritize transitions.
 */
export async function applyLifecycleDecisions(params: {
  evaluations: ReadonlyArray<LifecycleEvaluation>;
  metadataStore: MetadataStore;
  graphStore?: GraphStore;
  vectorStore?: VectorStore;
  now?: string;
}): Promise<AppliedLifecycleResult> {
  const archivedIds: string[] = [];
  const deprecatedIds: string[] = [];
  const tombstonedIds: string[] = [];
  const revalidatedIds: string[] = [];
  const deprioritizedIds: string[] = [];
  const purgedIds: string[] = [];
  const removeFromDerivedIds: string[] = [];
  const now = params.now ?? new Date().toISOString();
  const journalId = `jrnl_life_${randomUUID().slice(0, 12)}`;

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

  const runBatch = async () => {
    for (const ev of params.evaluations) {
      const atom = await params.metadataStore.getAtom(ev.atomId);
      if (!atom) continue;
      if (atom.lifecycle?.retentionClass === "legal_hold") continue;

      if (ev.action === "purge") {
        await params.metadataStore.deleteAtom(atom.id);
        purgedIds.push(atom.id);
        removeFromDerivedIds.push(atom.id);
      } else if (ev.action === "tombstone") {
        await params.metadataStore.saveAtom({
          ...atom,
          state: { ...atom.state, status: "deprecated" },
          lifecycle: {
            ...atom.lifecycle,
            tombstonedAt: atom.lifecycle?.tombstonedAt ?? now,
            deprecatedAt: atom.lifecycle?.deprecatedAt ?? now,
          },
          versioning: { ...atom.versioning, version: atom.versioning.version + 1 },
        });
        tombstonedIds.push(atom.id);
        removeFromDerivedIds.push(atom.id);
      } else if (ev.action === "deprecate" || ev.action === "archive") {
        await params.metadataStore.saveAtom({
          ...atom,
          state: { ...atom.state, status: "deprecated" },
          lifecycle: { ...atom.lifecycle, deprecatedAt: atom.lifecycle?.deprecatedAt ?? now },
          versioning: { ...atom.versioning, version: atom.versioning.version + 1 },
        });
        if (ev.action === "archive") archivedIds.push(atom.id);
        else deprecatedIds.push(atom.id);
        removeFromDerivedIds.push(atom.id);
      } else if (ev.action === "revalidate") {
        await params.metadataStore.saveAtom({
          ...atom,
          state: { ...atom.state, status: "tentative" },
          versioning: { ...atom.versioning, version: atom.versioning.version + 1 },
        });
        revalidatedIds.push(atom.id);
      } else if (ev.action === "deprioritize") {
        await params.metadataStore.saveAtom({
          ...atom,
          governance: {
            ...atom.governance,
            retrievalScore: ev.decayedValue,
            lastScoredAt: now,
            scoreVersion: 1,
          },
        });
        deprioritizedIds.push(atom.id);
      }
    }
  };

  if (params.metadataStore.withTransaction) {
    await params.metadataStore.withTransaction(runBatch);
  } else {
    await runBatch();
  }

  let derivedIndexesSynced = false;
  let derivedSyncError: string | undefined;
  if (removeFromDerivedIds.length === 0) {
    derivedIndexesSynced = true;
  } else if (
    typeof params.graphStore?.delete !== "function" ||
    typeof params.vectorStore?.delete !== "function"
  ) {
    derivedIndexesSynced = false;
    derivedSyncError = "derived_store_delete_unsupported";
  } else {
    try {
      await params.graphStore.delete(removeFromDerivedIds);
      await params.vectorStore.delete(removeFromDerivedIds);
      derivedIndexesSynced = true;
    } catch (err) {
      derivedIndexesSynced = false;
      derivedSyncError = err instanceof Error ? err.message : String(err);
    }
  }

  await params.metadataStore.updateJournal(journalId, {
    status: derivedIndexesSynced ? "COMPLETED" : "DERIVED_OUT_OF_SYNC",
    phase: derivedIndexesSynced ? "COMPLETED" : "METADATA_COMMITTED",
    objectIds: {
      ...journal.objectIds,
      atomIds: [
        ...archivedIds,
        ...deprecatedIds,
        ...tombstonedIds,
        ...revalidatedIds,
        ...deprioritizedIds,
        ...purgedIds,
      ],
    },
    lastError: derivedSyncError,
    updatedAt: new Date().toISOString(),
  });

  return {
    journalId,
    canonicalCommitted: true,
    archivedIds,
    deprecatedIds,
    tombstonedIds,
    revalidatedIds,
    deprioritizedIds,
    purgedIds,
    derivedIndexesSynced,
    ...(derivedSyncError ? { derivedSyncError } : {}),
  };
}
