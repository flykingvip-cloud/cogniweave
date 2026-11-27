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

export function isActiveDelegation(
  record: DelegationAuthorization,
  query: ActiveDelegationQuery,
): boolean {
  if (record.revokedAt) return false;
  if (Date.parse(record.expiresAt) <= Date.parse(query.now)) return false;
  if (record.tenantId !== query.tenantId) return false;
  if (record.delegateActorId !== query.actorUserId) return false;
  if (!sameMemorySubject(record.subject, query.subject)) return false;
  if (record.delegator.tenantId !== query.tenantId) return false;
  if (computeScopeFingerprint(record.scope) !== computeScopeFingerprint(query.scope)) {
    return false;
  }
  return true;
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
