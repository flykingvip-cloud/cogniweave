import type { MemoryAtom } from "../models.js";
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
  reason: string;
}

/**
 * MOP-04 Memory Lifecycle Optimizer.
 * Handles missing/invalid timestamps safely, separates legal_hold retention from retrieval,
 * supports configurable Retention Policy, and emits purge when archived/tombstoned beyond grace period.
 */
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
      reason: "protected_by_legal_hold",
    };
  }

  if (options?.evidenceInvalidated) {
    return {
      atomId: atom.id,
      action: "revalidate",
      decayedValue: 0,
      retrievable: false,
      reason: "evidence_invalidated",
    };
  }

  if (options?.supersededByAtomId) {
    return {
      atomId: atom.id,
      action: "deprecate",
      decayedValue: 0,
      retrievable: false,
      reason: `superseded_by:${options.supersededByAtomId}`,
    };
  }

  if (atom.lifecycle?.tombstonedAt) {
    const tombMs = Date.parse(atom.lifecycle.tombstonedAt);
    if (Number.isFinite(tombMs)) {
      const daysSinceTomb = (nowMs - tombMs) / (1000 * 60 * 60 * 24);
      if (daysSinceTomb >= policy.purgeAfterArchiveDays) {
        return {
          atomId: atom.id,
          action: "purge",
          decayedValue: 0,
          retrievable: false,
          reason: "tombstone_grace_expired",
        };
      }
    }
    return {
      atomId: atom.id,
      action: "tombstone",
      decayedValue: 0,
      retrievable: false,
      reason: "already_tombstoned",
    };
  }

  if (atom.state.status === "deprecated") {
    const depMs = atom.lifecycle?.deprecatedAt ? Date.parse(atom.lifecycle.deprecatedAt) : Number.NaN;
    if (Number.isFinite(depMs)) {
      const daysSinceDep = (nowMs - depMs) / (1000 * 60 * 60 * 24);
      if (daysSinceDep >= policy.purgeAfterArchiveDays) {
        return {
          atomId: atom.id,
          action: "purge",
          decayedValue: 0,
          retrievable: false,
          reason: "deprecated_grace_expired",
        };
      }
    }
    return {
      atomId: atom.id,
      action: "archive",
      decayedValue: 0,
      retrievable: false,
      reason: "deprecated_ready_for_archive",
    };
  }

  if (atom.state.status === "conflicted" || (atom.state.conflictsWith?.length ?? 0) > 0) {
    return {
      atomId: atom.id,
      action: "revalidate",
      decayedValue: Number((atom.metrics.confidence * 0.5).toFixed(4)),
      retrievable: false,
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
      reason: "ephemeral_stale_unused",
    };
  }

  if (decayedValue < policy.revalidateThreshold) {
    return {
      atomId: atom.id,
      action: "revalidate",
      decayedValue,
      retrievable: true,
      reason: "value_decayed_below_threshold",
    };
  }

  if (decayedValue < policy.deprioritizeThreshold) {
    return {
      atomId: atom.id,
      action: "deprioritize",
      decayedValue,
      retrievable: true,
      reason: "low_recent_utility",
    };
  }

  return {
    atomId: atom.id,
    action: "keep_active",
    decayedValue,
    retrievable: true,
    reason: "healthy_active_memory",
  };
}

/**
 * Execute lifecycle evaluations against Canonical Store and derived indexes.
 */
export async function applyLifecycleDecisions(params: {
  evaluations: ReadonlyArray<LifecycleEvaluation>;
  metadataStore: MetadataStore;
  graphStore?: GraphStore;
  vectorStore?: VectorStore;
  now?: string;
}): Promise<{ archivedIds: string[]; deprecatedIds: string[]; purgedIds: string[] }> {
  const archivedIds: string[] = [];
  const deprecatedIds: string[] = [];
  const purgedIds: string[] = [];
  const now = params.now ?? new Date().toISOString();

  for (const ev of params.evaluations) {
    const atom = await params.metadataStore.getAtom(ev.atomId);
    if (!atom) continue;
    if (atom.lifecycle?.retentionClass === "legal_hold") continue;

    if (ev.action === "purge") {
      await params.metadataStore.deleteAtom(atom.id);
      purgedIds.push(atom.id);
    } else if (ev.action === "deprecate" || ev.action === "archive") {
      await params.metadataStore.saveAtom({
        ...atom,
        state: { ...atom.state, status: "deprecated" },
        lifecycle: { ...atom.lifecycle, deprecatedAt: atom.lifecycle?.deprecatedAt ?? now },
        versioning: { ...atom.versioning, version: atom.versioning.version + 1 },
      });
      if (ev.action === "archive") archivedIds.push(atom.id);
      else deprecatedIds.push(atom.id);
    }
  }

  if (purgedIds.length > 0) {
    await params.graphStore?.delete?.(purgedIds);
    await params.vectorStore?.delete?.(purgedIds);
  }

  return { archivedIds, deprecatedIds, purgedIds };
}
