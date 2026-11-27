import { computeScopeFingerprint } from "../keys.js";
import type { MemoryAtom } from "../models.js";

export interface AbstractedMemory {
  abstractionVersion: number;
  atomType: string;
  claimStatement: string;
  commonTokens: string[];
  applicability: { include: string[]; exclude: string[] };
  trigger: { conditions: string[]; contextTags: string[] };
  constraints: string[];
  supportingAtomIds: string[];
  independentSourceEventIds: string[];
  evidenceRefs: string[];
  confidence: number;
  knownExceptions: string[];
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9\u4e00-\u9fff]+/i)
    .map((t) => t.trim())
    .filter((t) => t.length > 2);
}

/**
 * MOP-03 Memory Abstraction Engine (Evidence-constrained).
 * - Requires >= 2 independent source events (same event's atoms don't count as independent).
 * - Intersects applicability.include (never expands scope by union).
 * - Unions applicability.exclude as knownExceptions.
 * - Extracts shared invariant terms rather than copying statements[0].
 */
export function abstractFromAtoms(params: {
  atoms: ReadonlyArray<MemoryAtom>;
  abstractionVersion?: number;
  knownExceptions?: string[];
}): AbstractedMemory | null {
  const active = params.atoms.filter(
    (atom) =>
      (atom.state.status === "active" || atom.state.status === "tentative") &&
      (atom.state.conflictsWith?.length ?? 0) === 0 &&
      !atom.lifecycle?.tombstonedAt,
  );
  if (active.length < 2) {
    return null;
  }

  const primaryType = active[0].atomType;
  const primaryScopeFp = computeScopeFingerprint(active[0].scope);
  const compatible = active.filter(
    (atom) =>
      atom.atomType === primaryType &&
      computeScopeFingerprint(atom.scope) === primaryScopeFp &&
      (atom.provenance.evidenceRefs?.length ?? 0) > 0,
  );
  if (compatible.length < 2) {
    return null;
  }

  // Verify source-event independence.
  const independentEvents = new Set<string>();
  for (const atom of compatible) {
    for (const evtId of atom.provenance.sourceEventIds) {
      independentEvents.add(evtId);
    }
  }
  if (independentEvents.size < 2) {
    return null;
  }

  // Intersection of applicability.include (safe non-expanding applicability).
  let commonInclude = new Set<string>(compatible[0].applicability.include);
  for (let i = 1; i < compatible.length; i += 1) {
    const next = new Set(compatible[i].applicability.include);
    commonInclude = new Set([...commonInclude].filter((x) => next.has(x)));
  }

  // Intersection of trigger conditions & shared claim tokens.
  let commonConditions = new Set<string>(compatible[0].trigger.conditions);
  let commonTokens = new Set<string>(tokenize(compatible[0].claim.statement));
  const excludeSet = new Set<string>();
  const tagSet = new Set<string>();
  const evidenceSet = new Set<string>();
  const supportingAtomIds: string[] = [];
  let minConfidence = 1;

  for (const atom of compatible) {
    supportingAtomIds.push(atom.id);
    minConfidence = Math.min(minConfidence, atom.metrics.confidence);
    const conds = new Set(atom.trigger.conditions);
    commonConditions = new Set([...commonConditions].filter((c) => conds.has(c)));
    const tokens = new Set(tokenize(atom.claim.statement));
    commonTokens = new Set([...commonTokens].filter((t) => tokens.has(t)));
    for (const exc of atom.applicability.exclude) excludeSet.add(exc);
    for (const tag of atom.trigger.contextTags) tagSet.add(tag);
    for (const ev of atom.provenance.evidenceRefs) evidenceSet.add(ev);
  }

  // Check if commonInclude conflicts with any known exception.
  for (const exc of excludeSet) {
    commonInclude.delete(exc);
  }

  const sharedTerms = [...commonTokens];
  if (sharedTerms.length === 0 && commonConditions.size === 0) {
    return null;
  }

  const claimStatement =
    sharedTerms.length > 0
      ? `Invariant ${primaryType} across ${independentEvents.size} independent events: [${sharedTerms.join(", ")}]`
      : `Invariant ${primaryType} for conditions [${[...commonConditions].join(", ")}] across ${independentEvents.size} events`;

  // Conservative confidence: bounded by min(confidence), scaled by independent event corroboration.
  const corroborationFactor = Math.min(1, 0.7 + independentEvents.size * 0.1);
  const confidence = Number((minConfidence * corroborationFactor).toFixed(4));

  return {
    abstractionVersion: params.abstractionVersion ?? 1,
    atomType: primaryType,
    claimStatement,
    commonTokens: sharedTerms,
    applicability: {
      include: [...commonInclude],
      exclude: [...excludeSet],
    },
    trigger: {
      conditions: [...commonConditions],
      contextTags: [...tagSet],
    },
    constraints: [...excludeSet],
    supportingAtomIds,
    independentSourceEventIds: [...independentEvents],
    evidenceRefs: [...evidenceSet],
    confidence,
    knownExceptions: params.knownExceptions ?? [...excludeSet],
  };
}
