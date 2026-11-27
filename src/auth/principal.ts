import type { EngineEnvironment, MemorySubject } from "../models.js";
import type { MemoryResourceType } from "../resource/index.js";

/**
 * CW-09-02: identity issued by the OpenBot integration layer.
 * CogniWeave does not implement an IdP and does not mint principals.
 */
export type TrustedPrincipal = {
  tenantId: string;
  userId: string;
  /** Authoritative caller subject asserted by the integration layer, not by the request. */
  subject: MemorySubject;
  roles?: string[];
  allowedWorkspaceIds?: string[];
  agentId?: string;
  allowedResourceTypes?: MemoryResourceType[];
  /** Audit / revocation correlation only; not a source of authorization. */
  tokenId?: string;
};

export type ResolveTrustedPrincipalInput = {
  bearerToken?: string;
  environment: EngineEnvironment;
};

export interface TrustedPrincipalProvider {
  /** Implemented by the OpenBot integration. CogniWeave does not issue identities. */
  resolvePrincipal(input: ResolveTrustedPrincipalInput): Promise<TrustedPrincipal | null>;
}

export function isUsableTrustedPrincipal(
  principal: TrustedPrincipal | null | undefined,
): principal is TrustedPrincipal {
  if (!principal) return false;
  return Boolean(
    principal.tenantId.trim() &&
      principal.userId.trim() &&
      principal.subject.tenantId.trim() &&
      principal.subject.ownerId.trim() &&
      principal.subject.ownerType,
  );
}

/**
 * Deny-by-default test double. Unknown tokens resolve to null.
 * Only explicitly registered tokens can produce a principal.
 */
export function createDenyByDefaultPrincipalProvider(
  allowed: ReadonlyArray<{ token: string; principal: TrustedPrincipal }> = [],
): TrustedPrincipalProvider {
  const byToken = new Map(allowed.map((entry) => [entry.token, entry.principal]));
  return {
    async resolvePrincipal(input) {
      const token = input.bearerToken?.trim() ?? "";
      if (!token) return null;
      return byToken.get(token) ?? null;
    },
  };
}
