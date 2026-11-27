import type { MemoryAtom } from "../models.js";

export interface AbstractedMemory {
  abstractionVersion: number;
  atomType: string;
  claimStatement: string;
  applicability: { include: string[]; exclude: string[] };
  trigger: { conditions: string[]; contextTags: string[] };
  constraints: string[];
  supportingAtomIds: string[];
  evidenceRefs: string[];
  confidence: number;
  knownExceptions: string[];
}

/**
 * MOP-03 Memory Abstraction Engine.
 * Distills a higher-level reusable pattern from multiple supporting atoms
 * without mutating or deleting the original source atoms/events.
 */
export function abstractFromAtoms(params: {
  atoms: ReadonlyArray<MemoryAtom>;
  abstractionVersion?: number;
  knownExceptions?: string[];
}): AbstractedMemory | null {
  const active = params.atoms.filter(
    (atom) => atom.state.status === "active" || atom.state.status === "tentative",
  );
  if (active.length < 2) {
    return null;
  }

  const primaryType = active[0].atomType;
  const sameType = active.filter((atom) => atom.atomType === primaryType);
  if (sameType.length < 2) {
    return null;
  }

  const includeSet = new Set<string>();
  const excludeSet = new Set<string>();
  const conditionSet = new Set<string>();
  const tagSet = new Set<string>();
  const evidenceSet = new Set<string>();
  const supportingAtomIds: string[] = [];
  let confidenceSum = 0;

  for (const atom of sameType) {
    supportingAtomIds.push(atom.id);
    confidenceSum += atom.metrics.confidence;
    for (const item of atom.applicability.include) includeSet.add(item);
    for (const item of atom.applicability.exclude) excludeSet.add(item);
    for (const item of atom.trigger.conditions) conditionSet.add(item);
    for (const item of atom.trigger.contextTags) tagSet.add(item);
    for (const ev of atom.provenance.evidenceRefs) evidenceSet.add(ev);
  }

  const statements = sameType.map((a) => a.claim.statement.trim()).filter(Boolean);
  const claimStatement =
    statements.length > 0
      ? `Abstracted ${primaryType} pattern (${sameType.length} observations): ${statements[0]}`
      : `Abstracted ${primaryType} pattern (${sameType.length} observations)`;

  return {
    abstractionVersion: params.abstractionVersion ?? 1,
    atomType: primaryType,
    claimStatement,
    applicability: {
      include: [...includeSet],
      exclude: [...excludeSet],
    },
    trigger: {
      conditions: [...conditionSet],
      contextTags: [...tagSet],
    },
    constraints: [...excludeSet],
    supportingAtomIds,
    evidenceRefs: [...evidenceSet],
    confidence: Number((confidenceSum / sameType.length).toFixed(4)),
    knownExceptions: params.knownExceptions ?? [...excludeSet],
  };
}
