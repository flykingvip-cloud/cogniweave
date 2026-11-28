import { computeScopeFingerprint } from "../keys.js";
import type { MemorySubject, Scope } from "../models.js";

/**
 * CW-09-02: durable, revocable delegation record.
 * `delegatedActorFor` on a request is not evidence of this record.
 */
export type DelegationAuthorization = {
  id: string;
  tenantId: string;
  delegator: MemorySubject;
  delegateActorId: string;
  subject: MemorySubject;
  scope: Scope;
  grantedAt: string;
  expiresAt: string;
  revokedAt?: string;
};

export type ActiveDelegationQuery = {
  tenantId: string;
  actorUserId: string;
  subject: MemorySubject;
  scope: Scope;
  now: string;
};

export interface DelegationAuthorizationStore {
  getActiveDelegation(query: ActiveDelegationQuery): Promise<DelegationAuthorization | null>;
}

export function sameMemorySubject(a: MemorySubject, b: MemorySubject): boolean {
  return a.tenantId === b.tenantId && a.ownerType === b.ownerType && a.ownerId === b.ownerId;
}

export type DelegationRevalidationFailure =
  | "missing_or_incomplete"
  | "revoked"
  | "expired_or_unparsable"
  | "tenant_mismatch"
  | "delegate_mismatch"
  | "subject_mismatch"
  | "scope_mismatch"
  | "delegator_subject_mismatch";

function isCompleteSubject(subject: MemorySubject | undefined): subject is MemorySubject {
  return Boolean(subject?.tenantId?.trim() && subject.ownerId?.trim() && subject.ownerType);
}

/**
 * Independent authorization-layer check of a Delegation Store return value.
 * A non-empty row is not proof: every identifying field is re-validated here.
 *
 * Business relationship: the delegator must be the Memory Subject granting the
 * actor permission to act for that same subject in the given tenant and scope.
 * Illegal or unparsable expiry is denied (Date.parse NaN is not treated as live).
 */
export function revalidateDelegationRecord(
  record: DelegationAuthorization | null | undefined,
  query: ActiveDelegationQuery,
): DelegationRevalidationFailure | null {
  if (!record) return "missing_or_incomplete";
  if (!record.id?.trim()) return "missing_or_incomplete";
  if (!record.tenantId?.trim()) return "missing_or_incomplete";
  if (!record.delegateActorId?.trim()) return "missing_or_incomplete";
  if (!record.grantedAt?.trim() || !record.expiresAt?.trim()) return "missing_or_incomplete";
  if (!isCompleteSubject(record.subject) || !isCompleteSubject(record.delegator)) {
    return "missing_or_incomplete";
  }
  if (!record.scope) return "missing_or_incomplete";
  if (record.revokedAt) return "revoked";
  const expiresAtMs = Date.parse(record.expiresAt);
  const nowMs = Date.parse(query.now);
  if (!Number.isFinite(expiresAtMs) || !Number.isFinite(nowMs) || expiresAtMs <= nowMs) {
    return "expired_or_unparsable";
  }
  if (record.tenantId !== query.tenantId) return "tenant_mismatch";
  if (record.delegator.tenantId !== query.tenantId) return "tenant_mismatch";
  if (record.delegateActorId !== query.actorUserId) return "delegate_mismatch";
  if (!sameMemorySubject(record.subject, query.subject)) return "subject_mismatch";
  // Delegator is the subject who grants the actor access; a mismatched
  // delegator cannot authorize a different subject.
  if (!sameMemorySubject(record.delegator, record.subject)) return "delegator_subject_mismatch";
  if (computeScopeFingerprint(record.scope) !== computeScopeFingerprint(query.scope)) {
    return "scope_mismatch";
  }
  return null;
}

export function isActiveDelegation(
  record: DelegationAuthorization,
  query: ActiveDelegationQuery,
): boolean {
  return revalidateDelegationRecord(record, query) === null;
}

/**
 * Deny-by-default in-memory store. Only records explicitly saved can ever allow.
 * Missing, expired, revoked, or mismatched records resolve to null.
 */
export function createMemoryDelegationAuthorizationStore(
  seed: readonly DelegationAuthorization[] = [],
): DelegationAuthorizationStore & {
  save(record: DelegationAuthorization): void;
  revoke(id: string, revokedAt: string): void;
} {
  const records = new Map<string, DelegationAuthorization>(seed.map((row) => [row.id, row]));
  return {
    save(record) {
      records.set(record.id, record);
    },
    revoke(id, revokedAt) {
      const existing = records.get(id);
      if (existing) {
        records.set(id, { ...existing, revokedAt });
      }
    },
    async getActiveDelegation(query) {
      for (const record of records.values()) {
        if (isActiveDelegation(record, query)) {
          return record;
        }
      }
      return null;
    },
  };
}
