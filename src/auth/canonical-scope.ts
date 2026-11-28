import { createMemoryPartitionKeyV1 } from "../keys.js";
import type {
  MemoryAtom,
  MemoryPrivacyMetadata,
  MemorySubject,
  MemorySubjectBinding,
  Scope,
  WriteJournal,
} from "../models.js";
import { isAtomRetrievable } from "../retrieval/lifecycle-gate.js";
import { authorizeMemoryAccess } from "../subject/binding.js";
import { StoreUnavailableError } from "../errors.js";
import type { MetadataStore } from "../storage/types.js";

export type CanonicalResourceKind =
  | "atom"
  | "package"
  | "session"
  | "journal"
  | "memory_resource"
  | "event"
  | "entity"
  | "scenario"
  | "problem"
  | "evidence"
  | "relation";

export const REBUILD_OBJECT_TYPES = [
  "atom",
  "event",
  "entity",
  "scenario",
  "problem",
  "evidence",
  "relation",
  "journal",
] as const;

export type RebuildObjectType = (typeof REBUILD_OBJECT_TYPES)[number];

export type CanonicalUnresolvedReason = "not_found" | "ownership_incomplete" | "store_unavailable";

export type CanonicalResourceScope = {
  found: boolean;
  kind: CanonicalResourceKind;
  id: string;
  scope?: Scope;
  tenantId?: string;
  owner?: Pick<MemorySubject, "ownerType" | "ownerId">;
  privacyLevel?: MemoryPrivacyMetadata["privacyLevel"];
  lifecycleStatus?: "active" | "revoked" | "archived" | "deprecated" | "tombstoned" | "tentative" | "conflicted";
  retrievable?: boolean;
  subjectBindingId?: string;
  unresolvedReason?: CanonicalUnresolvedReason;
};

export interface CanonicalResourceLookup {
  getAtom(id: string): Promise<MemoryAtom | undefined>;
  getEvent(id: string): Promise<{ id: string; scope: Scope } | undefined>;
  getJournal(id: string): Promise<WriteJournal | undefined>;
  getEntity(id: string): Promise<{ id: string; scope: Scope } | undefined>;
  getScenario(id: string): Promise<{ id: string; scope: Scope } | undefined>;
  getProblem(id: string): Promise<{ id: string; scope: Scope } | undefined>;
  getEvidence(id: string): Promise<{ id: string; scope: Scope } | undefined>;
  getRelation(id: string): Promise<{ id: string; scope: Scope } | undefined>;
  getPackageTrace(id: string): Promise<{ taskFrame?: { scope?: Scope } } | undefined>;
  getReasoningSession(id: string): Promise<{ taskFrame?: { scope?: Scope } } | undefined>;
}

export interface CanonicalResourceScopeResolver {
  resolve(kind: CanonicalResourceKind, id: string): Promise<CanonicalResourceScope>;
}

export interface AuthoritativeBindingQuery {
  /** Production: required. Missing or throwing => fail closed (no ctx.bindings). */
  listLiveBindings(filter: {
    tenantId: string;
    dataPlaneId: string;
    scope?: Scope;
    scopeFingerprint?: string;
  }): Promise<MemorySubjectBinding[]>;
}

export type ResourceCallerPrincipal = {
  tenantId: string;
  userId: string;
  roles?: string[];
  allowedWorkspaceIds?: string[];
  subject?: MemorySubject;
};

export type CanonicalAuthorizationMode = "read" | "manage" | "revoke";

export type CanonicalAuthorizationSuccess = {
  allowed: true;
  resolved: CanonicalResourceScope;
  scope: Scope;
};

export type CanonicalAuthorizationFailure = {
  allowed: false;
  httpStatus: 401 | 403 | 404 | 503;
  error:
    | "unauthorized"
    | "tenant_mismatch"
    | "not_found"
    | "store_unavailable"
    | "binding_store_unavailable"
    | "principal_unavailable";
};

export type CanonicalAuthorizationDecision =
  | CanonicalAuthorizationSuccess
  | CanonicalAuthorizationFailure;

function isStoreError(error: unknown): boolean {
  return error instanceof StoreUnavailableError;
}

export function isCompleteScope(scope?: Scope | null): scope is Scope {
  return Boolean(
    scope &&
      scope.workspaceId.trim() &&
      scope.projectId.trim() &&
      scope.agentId.trim() &&
      (scope.visibility === "private" || scope.visibility === "shared"),
  );
}

export function isRebuildObjectType(value: string): value is RebuildObjectType {
  return (REBUILD_OBJECT_TYPES as readonly string[]).includes(value);
}

export function journalObjectIdsForType(journal: WriteJournal, objectType: RebuildObjectType): string[] {
  switch (objectType) {
    case "atom":
      return journal.objectIds.atomIds;
    case "event":
      return journal.objectIds.eventIds;
    case "entity":
      return journal.objectIds.entityIds;
    case "scenario":
      return journal.objectIds.scenarioIds;
    case "problem":
      return journal.objectIds.problemIds;
    case "evidence":
      return journal.objectIds.evidenceIds;
    case "relation":
      return journal.objectIds.relationIds;
    case "journal":
      return [journal.id];
  }
}

export async function deriveJournalScope(
  journal: WriteJournal,
  lookup: Pick<CanonicalResourceLookup, "getEvent" | "getAtom">,
): Promise<Scope | undefined> {
  if (isCompleteScope(journal.scope)) {
    return journal.scope;
  }
  for (const eventId of journal.objectIds.eventIds) {
    const event = await lookup.getEvent(eventId);
    if (event && isCompleteScope(event.scope)) {
      return event.scope;
    }
  }
  for (const atomId of journal.objectIds.atomIds) {
    const atom = await lookup.getAtom(atomId);
    if (atom && isCompleteScope(atom.scope)) {
      return atom.scope;
    }
  }
  return undefined;
}

function found(kind: CanonicalResourceKind, id: string, scope: Scope | undefined, extra: Partial<CanonicalResourceScope> = {}): CanonicalResourceScope {
  if (!isCompleteScope(scope)) {
    return {
      found: true,
      kind,
      id,
      unresolvedReason: "ownership_incomplete",
      ...extra,
    };
  }
  return { found: true, kind, id, scope, ...extra };
}

function missing(kind: CanonicalResourceKind, id: string, reason: CanonicalUnresolvedReason = "not_found"): CanonicalResourceScope {
  return { found: false, kind, id, unresolvedReason: reason };
}

export async function resolveCanonicalResourceScope(
  kind: CanonicalResourceKind,
  id: string,
  lookup: CanonicalResourceLookup,
): Promise<CanonicalResourceScope> {
  try {
    if (kind === "atom") {
      const atom = await lookup.getAtom(id);
      if (!atom) return missing(kind, id);
      const retrievable = isAtomRetrievable(atom).retrievable;
      return found(kind, id, atom.scope, {
        privacyLevel: atom.privacy?.privacyLevel,
        retrievable,
        lifecycleStatus: atom.lifecycle?.tombstonedAt
          ? "tombstoned"
          : atom.state.status === "deprecated" || atom.lifecycle?.deprecatedAt
            ? "deprecated"
            : atom.state.status,
      });
    }
    if (kind === "package") {
      const pkg = await lookup.getPackageTrace(id);
      if (!pkg) return missing(kind, id);
      return found(kind, id, pkg.taskFrame?.scope);
    }
    if (kind === "session") {
      const session = await lookup.getReasoningSession(id);
      if (!session) return missing(kind, id);
      return found(kind, id, session.taskFrame?.scope);
    }
    if (kind === "journal") {
      const journal = await lookup.getJournal(id);
      if (!journal) return missing(kind, id);
      const scope = await deriveJournalScope(journal, lookup);
      return found(kind, id, scope);
    }
    if (kind === "event") {
      const event = await lookup.getEvent(id);
      if (!event) return missing(kind, id);
      return found(kind, id, event.scope);
    }
    if (kind === "entity") {
      const entity = await lookup.getEntity(id);
      if (!entity) return missing(kind, id);
      return found(kind, id, entity.scope);
    }
    if (kind === "scenario") {
      const scenario = await lookup.getScenario(id);
      if (!scenario) return missing(kind, id);
      return found(kind, id, scenario.scope);
    }
    if (kind === "problem") {
      const problem = await lookup.getProblem(id);
      if (!problem) return missing(kind, id);
      return found(kind, id, problem.scope);
    }
    if (kind === "evidence") {
      const evidence = await lookup.getEvidence(id);
      if (!evidence) return missing(kind, id);
      return found(kind, id, evidence.scope);
    }
    if (kind === "relation") {
      const relation = await lookup.getRelation(id);
      if (!relation) return missing(kind, id);
      return found(kind, id, relation.scope);
    }
    return missing(kind, id);
  } catch (error) {
    if (isStoreError(error) || error instanceof Error) {
      return missing(kind, id, "store_unavailable");
    }
    return missing(kind, id, "store_unavailable");
  }
}

function deny(
  httpStatus: CanonicalAuthorizationFailure["httpStatus"],
  error: CanonicalAuthorizationFailure["error"],
): CanonicalAuthorizationFailure {
  return { allowed: false, httpStatus, error };
}

export function isPrincipalTenantConsistent(
  principal: Pick<ResourceCallerPrincipal, "tenantId" | "subject">,
): boolean {
  return Boolean(principal.subject && principal.tenantId === principal.subject.tenantId);
}

export type DeclaredScopeAuthorizationSuccess = {
  allowed: true;
  scope: Scope;
  bindingId: string;
};

export type DeclaredScopeAuthorizationFailure = {
  allowed: false;
  httpStatus: 401 | 403 | 503;
  error:
    | "unauthorized"
    | "tenant_mismatch"
    | "missing_workspace_scope"
    | "missing_declared_scope"
    | "scope_tenant_forbidden"
    | "subject_binding_denied"
    | "binding_store_unavailable"
    | "principal_unavailable";
};

export type DeclaredScopeAuthorizationDecision =
  | DeclaredScopeAuthorizationSuccess
  | DeclaredScopeAuthorizationFailure;

function declaredDeny(
  httpStatus: DeclaredScopeAuthorizationFailure["httpStatus"],
  error: DeclaredScopeAuthorizationFailure["error"],
): DeclaredScopeAuthorizationFailure {
  return { allowed: false, httpStatus, error };
}

/**
 * CW-09-01-R1: authorize a caller-declared Scope (create/write/list filters)
 * with the same Subject Binding strictness as Canonical Resource ID authorization.
 * Workspace access alone is not sufficient.
 */
export async function authorizeDeclaredScope(input: {
  principal?: ResourceCallerPrincipal;
  scope?: Scope | null;
  authorizeWorkspace: (workspaceId: string) => Promise<boolean>;
  bindingQuery?: AuthoritativeBindingQuery;
  ensureDataPlaneId?: () => Promise<string>;
}): Promise<DeclaredScopeAuthorizationDecision> {
  if (!input.principal) {
    return declaredDeny(401, "unauthorized");
  }
  const principal = input.principal;
  const workspaceId = input.scope?.workspaceId?.trim() ?? "";
  if (!workspaceId) {
    return declaredDeny(403, "missing_workspace_scope");
  }
  if (!isCompleteScope(input.scope)) {
    return declaredDeny(403, "missing_declared_scope");
  }
  const scope = input.scope;

  const workspaceOk = await input.authorizeWorkspace(scope.workspaceId);
  if (!workspaceOk) {
    return declaredDeny(403, "scope_tenant_forbidden");
  }

  if (!principal.subject) {
    return declaredDeny(503, "principal_unavailable");
  }
  if (principal.tenantId !== principal.subject.tenantId) {
    return declaredDeny(403, "tenant_mismatch");
  }
  const verifiedTenantId = principal.tenantId;
  const callerSubject = principal.subject;

  if (!input.bindingQuery) {
    return declaredDeny(503, "binding_store_unavailable");
  }
  let dataPlaneId: string;
  try {
    dataPlaneId = (await input.ensureDataPlaneId?.())?.trim() ?? "";
  } catch {
    return declaredDeny(503, "binding_store_unavailable");
  }
  if (!dataPlaneId) {
    return declaredDeny(503, "binding_store_unavailable");
  }

  let bindings: MemorySubjectBinding[];
  try {
    bindings = await input.bindingQuery.listLiveBindings({
      tenantId: verifiedTenantId,
      dataPlaneId,
      scope,
    });
  } catch {
    return declaredDeny(503, "binding_store_unavailable");
  }

  const partition = createMemoryPartitionKeyV1(dataPlaneId, scope);
  const acl = authorizeMemoryAccess(bindings, {
    partition,
    caller: callerSubject,
  });
  if (!acl.allowed) {
    return declaredDeny(403, "subject_binding_denied");
  }

  return { allowed: true, scope, bindingId: acl.bindingId };
}

/**
 * List-filter for Memory Resource descriptors after declared-scope authorization.
 * A live binding for the Scope is not enough to reveal another Subject's descriptor.
 */
export function isAuthorizedMemoryResourceDescriptor(input: {
  principal: ResourceCallerPrincipal;
  descriptor: {
    tenantId?: string;
    ownerType?: MemorySubject["ownerType"];
    ownerId?: string;
    subjectBindingId?: string;
    lifecycleStatus?: string;
  };
  bindingId: string;
}): boolean {
  const principal = input.principal;
  if (!principal.subject || principal.tenantId !== principal.subject.tenantId) {
    return false;
  }
  if (!input.bindingId.trim()) return false;
  const desc = input.descriptor;
  if (desc.tenantId && desc.tenantId !== principal.tenantId) return false;
  if (desc.lifecycleStatus && desc.lifecycleStatus !== "active") return false;
  if (desc.subjectBindingId && desc.subjectBindingId !== input.bindingId) return false;
  if (desc.ownerType && desc.ownerId) {
    const ownerMatches =
      (desc.ownerType === principal.subject.ownerType && desc.ownerId === principal.subject.ownerId) ||
      (desc.ownerType === "user" && desc.ownerId === principal.userId);
    if (!ownerMatches) return false;
  }
  return Boolean(desc.subjectBindingId || (desc.ownerType && desc.ownerId));
}

export async function authorizeCanonicalResource(input: {
  kind: CanonicalResourceKind;
  id: string;
  principal?: ResourceCallerPrincipal;
  mode?: CanonicalAuthorizationMode;
  resolver: CanonicalResourceScopeResolver;
  authorizeWorkspace: (workspaceId: string) => Promise<boolean>;
  bindingQuery?: AuthoritativeBindingQuery;
  ensureDataPlaneId?: () => Promise<string>;
  knowledgePolicyAllows?: (params: {
    principal: ResourceCallerPrincipal;
    resolved: CanonicalResourceScope;
  }) => Promise<boolean> | boolean;
}): Promise<CanonicalAuthorizationDecision> {
  if (!input.principal) {
    return deny(401, "unauthorized");
  }
  const principal = input.principal;
  if (!principal.subject) {
    return deny(503, "principal_unavailable");
  }
  if (principal.tenantId !== principal.subject.tenantId) {
    return deny(403, "tenant_mismatch");
  }
  const verifiedTenantId = principal.tenantId;
  const callerSubject = principal.subject;
  const mode = input.mode ?? "read";

  let resolved: CanonicalResourceScope;
  try {
    resolved = await input.resolver.resolve(input.kind, input.id);
  } catch (error) {
    if (isStoreError(error) || error instanceof Error) {
      return deny(503, "store_unavailable");
    }
    return deny(503, "store_unavailable");
  }

  if (resolved.unresolvedReason === "store_unavailable") {
    return deny(503, "store_unavailable");
  }
  if (!resolved.found || !isCompleteScope(resolved.scope)) {
    return deny(404, "not_found");
  }

  if (resolved.tenantId && resolved.tenantId !== verifiedTenantId) {
    return deny(404, "not_found");
  }

  const workspaceOk = await input.authorizeWorkspace(resolved.scope.workspaceId);
  if (!workspaceOk) {
    return deny(404, "not_found");
  }

  // read, manage, and revoke all query Subject Binding. Tenant/Workspace
  // admin roles are never sufficient to skip Canonical Ownership.
  if (!input.bindingQuery) {
    return deny(503, "binding_store_unavailable");
  }
  let dataPlaneId: string;
  try {
    dataPlaneId = (await input.ensureDataPlaneId?.())?.trim() ?? "";
  } catch {
    return deny(503, "binding_store_unavailable");
  }
  if (!dataPlaneId) {
    return deny(503, "binding_store_unavailable");
  }
  let bindings: MemorySubjectBinding[];
  try {
    bindings = await input.bindingQuery.listLiveBindings({
      tenantId: verifiedTenantId,
      dataPlaneId,
      scope: resolved.scope,
    });
  } catch {
    return deny(503, "binding_store_unavailable");
  }
  const partition = createMemoryPartitionKeyV1(dataPlaneId, resolved.scope);
  const acl = authorizeMemoryAccess(bindings, {
    partition,
    caller: callerSubject,
  });

  const ownerMatches = resolved.owner
    ? (resolved.owner.ownerType === "user" && resolved.owner.ownerId === principal.userId) ||
      (resolved.owner.ownerType === callerSubject.ownerType &&
        resolved.owner.ownerId === callerSubject.ownerId)
    : false;

  if (mode === "read") {
    if (!acl.allowed) {
      return deny(404, "not_found");
    }
    if (resolved.retrievable === false) {
      return deny(404, "not_found");
    }
    if (
      input.kind === "memory_resource" &&
      resolved.lifecycleStatus &&
      resolved.lifecycleStatus !== "active"
    ) {
      return deny(404, "not_found");
    }
    if (resolved.privacyLevel === "private" && resolved.owner && !ownerMatches) {
      return deny(404, "not_found");
    }
    if (input.knowledgePolicyAllows) {
      const policyOk = await input.knowledgePolicyAllows({ principal, resolved });
      if (!policyOk) {
        return deny(404, "not_found");
      }
    }
    return { allowed: true, resolved, scope: resolved.scope };
  }

  // manage / revoke: Canonical Ownership first, then subject binding.
  // An admin role cannot substitute for owner + binding proof.
  const alreadyRevokedOrArchived =
    resolved.lifecycleStatus === "revoked" || resolved.lifecycleStatus === "archived";

  if (mode === "revoke" && alreadyRevokedOrArchived) {
    // Idempotent revoke: the owner may succeed without a still-live binding.
    // Anyone else gets a uniform 404 so existence is not leaked.
    if (resolved.owner) {
      if (!ownerMatches) {
        return deny(404, "not_found");
      }
    } else if (!acl.allowed) {
      return deny(404, "not_found");
    }
    return { allowed: true, resolved, scope: resolved.scope };
  }

  if (resolved.owner && !ownerMatches) {
    return deny(404, "not_found");
  }
  if (!acl.allowed) {
    return deny(404, "not_found");
  }
  if (
    input.kind === "memory_resource" &&
    resolved.lifecycleStatus &&
    resolved.lifecycleStatus !== "active" &&
    mode === "manage"
  ) {
    return deny(404, "not_found");
  }
  if (input.knowledgePolicyAllows) {
    const policyOk = await input.knowledgePolicyAllows({ principal, resolved });
    if (!policyOk) {
      return deny(404, "not_found");
    }
  }

  return { allowed: true, resolved, scope: resolved.scope };
}


export function createAuthoritativeBindingQueryFromMetadataStore(
  store: Pick<MetadataStore, "listMemorySubjectBindings">,
): AuthoritativeBindingQuery | undefined {
  if (!store.listMemorySubjectBindings) {
    return undefined;
  }
  return {
    async listLiveBindings(filter) {
      return store.listMemorySubjectBindings!({
        tenantId: filter.tenantId,
        dataPlaneId: filter.dataPlaneId,
        scope: filter.scope,
        scopeFingerprint: filter.scopeFingerprint,
        liveOnly: true,
      });
    },
  };
}

/** Deny-by-default test double. Only bindings explicitly provided can allow. */
export function createDenyByDefaultBindingQuery(
  allowed: readonly MemorySubjectBinding[] = [],
): AuthoritativeBindingQuery {
  return {
    async listLiveBindings(filter) {
      return allowed.filter((binding) => {
        if (binding.unboundAt) return false;
        if (filter.tenantId && binding.subject.tenantId !== filter.tenantId) return false;
        if (filter.dataPlaneId && binding.partition.dataPlaneId !== filter.dataPlaneId) return false;
        if (
          filter.scopeFingerprint &&
          binding.partition.scopeFingerprint !== filter.scopeFingerprint
        ) {
          return false;
        }
        if (filter.scope) {
          return (
            binding.scope.workspaceId === filter.scope.workspaceId &&
            binding.scope.projectId === filter.scope.projectId &&
            binding.scope.agentId === filter.scope.agentId &&
            binding.scope.visibility === filter.scope.visibility
          );
        }
        return true;
      });
    },
  };
}
