import { randomUUID } from "node:crypto";
import {
  BindingStoreUnavailableError,
  DelegationDeniedError,
  DelegationStoreUnavailableError,
  PrincipalUnavailableError,
} from "../errors.js";
import { computeScopeFingerprint, createMemoryPartitionKeyV1 } from "../keys.js";
import type { EngineEnvironment, MemorySubject, MemorySubjectBinding, Scope } from "../models.js";
import type { MetadataStore } from "../storage/types.js";
import { authorizeMemoryAccess } from "../subject/binding.js";
import type { AuthoritativeBindingQuery } from "./canonical-scope.js";
import { sameMemorySubject, type DelegationAuthorization, type DelegationAuthorizationStore } from "./delegation.js";
import {
  isUsableTrustedPrincipal,
  type TrustedPrincipal,
  type TrustedPrincipalProvider,
} from "./principal.js";

export type ExecutionAuthorizationDecision = {
  actor: { userId: string };
  delegator?: MemorySubject;
  caller: MemorySubject;
  subject: MemorySubject;
  bindingId?: string;
  tenantId: string;
  scope: Scope;
  decision: "allow" | "deny";
  reason?: string;
  traceId: string;
  delegationId?: string;
  principalTokenId?: string;
  at: string;
};

export type TrustedExecutionRequest = {
  tenantId: string;
  subjectId: string;
  scope: Scope;
  dataPlaneId: string;
  /** Declared actor; never proof of identity when requireAuth is on. */
  declaredActorUserId?: string;
  /** Declared caller; cannot override principal.subject without a delegation record. */
  declaredCaller?: MemorySubject;
  now?: string;
  traceId?: string;
};

export type TrustedExecutionAuthorizationOptions = {
  /**
   * Production default is fail-closed. `false` is honored only for environment
   * `"local"` and is not production evidence. service/cloud always require auth.
   */
  requireAuth?: boolean;
  environment?: EngineEnvironment;
  principal?: TrustedPrincipal;
  principalProvider?: TrustedPrincipalProvider;
  bearerToken?: string;
  delegationStore?: DelegationAuthorizationStore;
  bindingQuery?: AuthoritativeBindingQuery;
};

export type TrustedExecutionAuthorizationSuccess = {
  allowed: true;
  actorUserId: string;
  principal?: TrustedPrincipal;
  caller: MemorySubject;
  subject: MemorySubject;
  bindingId: string;
  bindings: MemorySubjectBinding[];
  delegation?: DelegationAuthorization;
  decision: ExecutionAuthorizationDecision;
};

function emptySubject(): MemorySubject {
  return { tenantId: "", ownerType: "user", ownerId: "" };
}

function buildDecision(input: {
  actorUserId: string;
  caller?: MemorySubject;
  subject?: MemorySubject;
  tenantId: string;
  scope: Scope;
  decision: "allow" | "deny";
  reason?: string;
  traceId: string;
  at: string;
  bindingId?: string;
  delegator?: MemorySubject;
  delegationId?: string;
  principalTokenId?: string;
}): ExecutionAuthorizationDecision {
  return {
    actor: { userId: input.actorUserId },
    caller: input.caller ?? emptySubject(),
    subject: input.subject ?? emptySubject(),
    tenantId: input.tenantId,
    scope: input.scope,
    decision: input.decision,
    reason: input.reason,
    traceId: input.traceId,
    at: input.at,
    ...(input.bindingId ? { bindingId: input.bindingId } : {}),
    ...(input.delegator ? { delegator: input.delegator } : {}),
    ...(input.delegationId ? { delegationId: input.delegationId } : {}),
    ...(input.principalTokenId ? { principalTokenId: input.principalTokenId } : {}),
  };
}

export function isProductionLikeEnvironment(environment: EngineEnvironment | undefined): boolean {
  return environment !== "local";
}

/**
 * service/cloud (and unspecified) always require auth.
 * local honors an explicit requireAuth flag and defaults to false.
 */
export function resolveRequireAuth(options?: {
  requireAuth?: boolean;
  environment?: EngineEnvironment;
}): boolean {
  const environment = options?.environment;
  if (isProductionLikeEnvironment(environment)) {
    return true;
  }
  return options?.requireAuth === true;
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

/**
 * Authorize the chain:
 * Trusted Principal → Actor → Delegation Authorization → Caller Subject →
 * Authoritative Binding → Job Subject.
 *
 * Caller-declared `actorUserId`, `delegatedActorFor`, and `ctx.bindings` are never evidence.
 */
export async function authorizeTrustedExecution(input: {
  request: TrustedExecutionRequest;
  authorization?: TrustedExecutionAuthorizationOptions;
  bindingQuery?: AuthoritativeBindingQuery;
  metadataStore?: Pick<MetadataStore, "listMemorySubjectBindings">;
}): Promise<TrustedExecutionAuthorizationSuccess> {
  const request = input.request;
  const now = request.now ?? new Date().toISOString();
  const traceId = request.traceId ?? `auth_${randomUUID()}`;
  const requireAuth = resolveRequireAuth(input.authorization);
  const environment = input.authorization?.environment ?? (requireAuth ? "service" : "local");

  const denyBase = {
    tenantId: request.tenantId,
    scope: request.scope,
    traceId,
    at: now,
    actorUserId: request.declaredActorUserId ?? "",
    caller: request.declaredCaller,
    subject: request.declaredCaller,
  };

  let principal: TrustedPrincipal | undefined;
  if (requireAuth) {
    if (input.authorization?.principal && isUsableTrustedPrincipal(input.authorization.principal)) {
      principal = input.authorization.principal;
    } else if (input.authorization?.principalProvider) {
      try {
        const resolved = await input.authorization.principalProvider.resolvePrincipal({
          bearerToken: input.authorization.bearerToken,
          environment,
        });
        if (isUsableTrustedPrincipal(resolved)) {
          principal = resolved;
        }
      } catch (error) {
        const decision = buildDecision({
          ...denyBase,
          decision: "deny",
          reason: "principal_unavailable",
        });
        throw new PrincipalUnavailableError(
          error instanceof Error ? error.message : "Trusted principal provider failed",
          decision,
        );
      }
    }
    if (!principal) {
      const decision = buildDecision({
        ...denyBase,
        decision: "deny",
        reason: "principal_unavailable",
      });
      throw new PrincipalUnavailableError(
        "Trusted Principal is required in service/cloud; CogniWeave does not accept self-declared actors",
        decision,
      );
    }
  }

  const actorUserId = principal?.userId ?? request.declaredActorUserId?.trim() ?? "";
  if (!actorUserId) {
    const decision = buildDecision({
      ...denyBase,
      actorUserId: "",
      decision: "deny",
      reason: "unauthorized",
    });
    throw new PrincipalUnavailableError("Actor identity is required", decision);
  }

  if (
    principal &&
    request.declaredActorUserId?.trim() &&
    request.declaredActorUserId.trim() !== principal.userId
  ) {
    const decision = buildDecision({
      ...denyBase,
      actorUserId: request.declaredActorUserId,
      principalTokenId: principal.tokenId,
      decision: "deny",
      reason: "forged_actor",
    });
    throw new DelegationDeniedError(
      `Declared actor ${request.declaredActorUserId} does not match trusted principal ${principal.userId}`,
      decision,
    );
  }

  const caller: MemorySubject | undefined = requireAuth
    ? request.declaredCaller ?? principal?.subject
    : request.declaredCaller;

  if (!caller || !caller.ownerId.trim() || !caller.tenantId.trim()) {
    const decision = buildDecision({
      ...denyBase,
      actorUserId,
      principalTokenId: principal?.tokenId,
      decision: "deny",
      reason: "caller_missing",
    });
    throw new DelegationDeniedError("Caller subject is required", decision);
  }

  if (principal && principal.tenantId !== request.tenantId) {
    const decision = buildDecision({
      ...denyBase,
      actorUserId,
      caller,
      subject: { tenantId: request.tenantId, ownerType: caller.ownerType, ownerId: request.subjectId },
      principalTokenId: principal.tokenId,
      decision: "deny",
      reason: "tenant_mismatch",
    });
    throw new DelegationDeniedError("Trusted principal tenant does not match job tenant", decision);
  }

  if (caller.tenantId !== request.tenantId) {
    const decision = buildDecision({
      ...denyBase,
      actorUserId,
      caller,
      subject: { tenantId: request.tenantId, ownerType: caller.ownerType, ownerId: request.subjectId },
      principalTokenId: principal?.tokenId,
      decision: "deny",
      reason: "tenant_mismatch",
    });
    throw new DelegationDeniedError("Caller tenant does not match job tenant", decision);
  }

  if (principal?.allowedWorkspaceIds && !principal.allowedWorkspaceIds.includes(request.scope.workspaceId)) {
    const decision = buildDecision({
      ...denyBase,
      actorUserId,
      caller,
      subject: { tenantId: request.tenantId, ownerType: caller.ownerType, ownerId: request.subjectId },
      principalTokenId: principal.tokenId,
      decision: "deny",
      reason: "workspace_forbidden",
    });
    throw new DelegationDeniedError("Principal is not authorized for the job workspace", decision);
  }

  const jobSubject: MemorySubject = {
    tenantId: request.tenantId,
    ownerType: caller.ownerType,
    ownerId: request.subjectId,
  };

  if (request.subjectId !== caller.ownerId) {
    const decision = buildDecision({
      ...denyBase,
      actorUserId,
      caller,
      subject: jobSubject,
      principalTokenId: principal?.tokenId,
      decision: "deny",
      reason: "job_subject_mismatch",
    });
    throw new DelegationDeniedError(
      `Job subject (${request.subjectId}) does not match caller subject (${caller.ownerId})`,
      decision,
    );
  }

  // When auth is on, a declared caller that differs from principal.subject requires delegation,
  // as does any case where the actor is not the caller owner. Actor == some user id is not enough.
  const callerMatchesPrincipalSubject = principal ? sameMemorySubject(caller, principal.subject) : true;
  const actorIsCallerOwner = actorUserId === caller.ownerId;
  const needsDelegation = !actorIsCallerOwner || (Boolean(principal) && !callerMatchesPrincipalSubject);

  let delegation: DelegationAuthorization | undefined;
  if (needsDelegation) {
    if (!input.authorization?.delegationStore) {
      const decision = buildDecision({
        ...denyBase,
        actorUserId,
        caller,
        subject: jobSubject,
        principalTokenId: principal?.tokenId,
        decision: "deny",
        reason: "delegation_store_unavailable",
      });
      throw new DelegationStoreUnavailableError(
        "DelegationAuthorizationStore is required when the actor is not the caller subject owner",
        decision,
      );
    }
    let active: DelegationAuthorization | null;
    try {
      active = await input.authorization.delegationStore.getActiveDelegation({
        tenantId: request.tenantId,
        actorUserId,
        subject: caller,
        scope: request.scope,
        now,
      });
    } catch (error) {
      const decision = buildDecision({
        ...denyBase,
        actorUserId,
        caller,
        subject: jobSubject,
        principalTokenId: principal?.tokenId,
        decision: "deny",
        reason: "delegation_store_unavailable",
      });
      throw new DelegationStoreUnavailableError(
        error instanceof Error ? error.message : "Delegation store unavailable",
        decision,
      );
    }
    if (!active) {
      const decision = buildDecision({
        ...denyBase,
        actorUserId,
        caller,
        subject: jobSubject,
        principalTokenId: principal?.tokenId,
        decision: "deny",
        reason: "delegation_denied",
      });
      throw new DelegationDeniedError(
        `Actor ${actorUserId} is not authorized to act for subject ${caller.ownerId}`,
        decision,
      );
    }
    delegation = active;
  }

  const bindingQuery =
    input.bindingQuery ??
    input.authorization?.bindingQuery ??
    (input.metadataStore
      ? createAuthoritativeBindingQueryFromMetadataStore(input.metadataStore)
      : undefined);

  if (!bindingQuery) {
    const decision = buildDecision({
      ...denyBase,
      actorUserId,
      caller,
      subject: jobSubject,
      principalTokenId: principal?.tokenId,
      delegator: delegation?.delegator,
      delegationId: delegation?.id,
      decision: "deny",
      reason: "binding_store_unavailable",
    });
    throw new BindingStoreUnavailableError(
      "Authoritative Binding query is required; caller-submitted bindings are not evidence",
      decision,
    );
  }

  let bindings: MemorySubjectBinding[];
  try {
    bindings = await bindingQuery.listLiveBindings({
      tenantId: request.tenantId,
      dataPlaneId: request.dataPlaneId,
      scope: request.scope,
      scopeFingerprint: computeScopeFingerprint(request.scope),
    });
  } catch (error) {
    const decision = buildDecision({
      ...denyBase,
      actorUserId,
      caller,
      subject: jobSubject,
      principalTokenId: principal?.tokenId,
      delegator: delegation?.delegator,
      delegationId: delegation?.id,
      decision: "deny",
      reason: "binding_store_unavailable",
    });
    throw new BindingStoreUnavailableError(
      error instanceof Error ? error.message : "Authoritative Binding query failed",
      decision,
    );
  }

  const partition = createMemoryPartitionKeyV1(request.dataPlaneId, request.scope);
  const acl = authorizeMemoryAccess(bindings, { partition, caller });
  if (!acl.allowed) {
    const decision = buildDecision({
      ...denyBase,
      actorUserId,
      caller,
      subject: jobSubject,
      principalTokenId: principal?.tokenId,
      delegator: delegation?.delegator,
      delegationId: delegation?.id,
      decision: "deny",
      reason: `binding_${acl.reason.toLowerCase()}`,
    });
    throw new DelegationDeniedError(
      `Optimization job unauthorized for target scope: ${acl.reason}`,
      decision,
    );
  }

  const decision = buildDecision({
    actorUserId,
    caller,
    subject: jobSubject,
    tenantId: request.tenantId,
    scope: request.scope,
    decision: "allow",
    reason: needsDelegation ? "delegated" : "actor_is_caller",
    traceId,
    at: now,
    bindingId: acl.bindingId,
    delegator: delegation?.delegator,
    delegationId: delegation?.id,
    principalTokenId: principal?.tokenId,
  });

  return {
    allowed: true,
    actorUserId,
    principal,
    caller,
    subject: jobSubject,
    bindingId: acl.bindingId,
    bindings,
    delegation,
    decision,
  };
}

export async function authorizeAtomBindings(input: {
  atoms: ReadonlyArray<{ id: string; scope: Scope }>;
  expectedScope: Scope;
  dataPlaneId: string;
  caller: MemorySubject;
  bindings: readonly MemorySubjectBinding[];
}): Promise<void> {
  const expectedScopeFp = computeScopeFingerprint(input.expectedScope);
  for (const atom of input.atoms) {
    if (computeScopeFingerprint(atom.scope) !== expectedScopeFp) {
      throw new DelegationDeniedError(
        `Atom ${atom.id} belongs to a different scope than target optimization job scope`,
        buildDecision({
          actorUserId: "",
          caller: input.caller,
          subject: input.caller,
          tenantId: input.caller.tenantId,
          scope: input.expectedScope,
          decision: "deny",
          reason: "atom_scope_mismatch",
          traceId: `auth_${randomUUID()}`,
          at: new Date().toISOString(),
        }),
      );
    }
    const atomPartition = createMemoryPartitionKeyV1(input.dataPlaneId, atom.scope);
    const atomAcl = authorizeMemoryAccess(input.bindings, {
      partition: atomPartition,
      caller: input.caller,
    });
    if (!atomAcl.allowed) {
      throw new DelegationDeniedError(
        `Optimization job unauthorized for atom ${atom.id}: ${atomAcl.reason}`,
        buildDecision({
          actorUserId: "",
          caller: input.caller,
          subject: input.caller,
          tenantId: input.caller.tenantId,
          scope: atom.scope,
          decision: "deny",
          reason: `binding_${atomAcl.reason.toLowerCase()}`,
          traceId: `auth_${randomUUID()}`,
          at: new Date().toISOString(),
        }),
      );
    }
  }
}
