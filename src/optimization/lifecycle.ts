import type { MemoryAtom } from "../models.js";

export type LifecycleAction =
  | "keep_active"
  | "revalidate"
  | "deprioritize"
  | "archive"
  | "deprecate"
  | "tombstone"
  | "purge";

export interface LifecycleEvaluation {
  atomId: string;
  action: LifecycleAction;
  decayedValue: number;
  reason: string;
}

/**
 * MOP-04 Memory Lifecycle Optimizer.
 * Evaluates freshness, reuse, conflicts, and retentionClass.
 * Respects legal_hold and never applies uniform decay to protected records.
 */
export function evaluateLifecycle(
  atom: MemoryAtom,
  options?: { nowMs?: number; supersededByAtomId?: string },
): LifecycleEvaluation {
  const retention = atom.lifecycle?.retentionClass ?? "standard";
  if (retention === "legal_hold") {
    return {
      atomId: atom.id,
      action: "keep_active",
      decayedValue: atom.metrics.confidence,
      reason: "protected_by_legal_hold",
    };
  }

  if (options?.supersededByAtomId) {
    return {
      atomId: atom.id,
      action: "deprecate",
      decayedValue: 0,
      reason: `superseded_by:${options.supersededByAtomId}`,
    };
  }

  if (atom.lifecycle?.tombstonedAt) {
    return {
      atomId: atom.id,
      action: "tombstone",
      decayedValue: 0,
      reason: "already_tombstoned",
    };
  }

  if (atom.state.status === "deprecated") {
    return {
      atomId: atom.id,
      action: "archive",
      decayedValue: 0,
      reason: "deprecated_ready_for_archive",
    };
  }

  if (atom.state.status === "conflicted" || (atom.state.conflictsWith?.length ?? 0) > 0) {
    return {
      atomId: atom.id,
      action: "revalidate",
      decayedValue: Number((atom.metrics.confidence * 0.5).toFixed(4)),
      reason: "conflicted_requires_revalidation",
    };
  }

  const nowMs = options?.nowMs ?? Date.now();
  const lastTouch = atom.lifecycle?.lastRetrievedAt ?? atom.lifecycle?.admittedAt;
  const ageDays = lastTouch
    ? Math.max(0, (nowMs - Date.parse(lastTouch)) / (1000 * 60 * 60 * 24))
    : 0;
  const halfLifeDays = retention === "ephemeral" ? 7 : retention === "durable" ? 180 : 60;
  const decayFactor = Math.pow(0.5, ageDays / halfLifeDays);
  const reuseBoost = Math.min(0.25, atom.metrics.reuseCount * 0.03);
  const decayedValue = Number(
    Math.min(1, Math.max(0, atom.metrics.confidence * decayFactor + reuseBoost)).toFixed(4),
  );

  if (retention === "ephemeral" && ageDays > 30 && atom.metrics.reuseCount === 0) {
    return {
      atomId: atom.id,
      action: "archive",
      decayedValue,
      reason: "ephemeral_stale_unused",
    };
  }

  if (decayedValue < 0.25) {
    return {
      atomId: atom.id,
      action: "revalidate",
      decayedValue,
      reason: "value_decayed_below_threshold",
    };
  }

  if (decayedValue < 0.45) {
    return {
      atomId: atom.id,
      action: "deprioritize",
      decayedValue,
      reason: "low_recent_utility",
    };
  }

  return {
    atomId: atom.id,
    action: "keep_active",
    decayedValue,
    reason: "healthy_active_memory",
  };
}
