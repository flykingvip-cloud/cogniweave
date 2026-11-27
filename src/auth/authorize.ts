import { randomUUID } from "node:crypto";
import {
  BindingStoreUnavailableError,
  DelegationDeniedError,
  DelegationStoreUnavailableError,
  PrincipalUnavailableError,
  SecurityOverrideRejectedError,
  UntrustedRuntimeError,
} from "../errors.js";
import { computeScopeFingerprint, createMemoryPartitionKeyV1 } from "../keys.js";
import type { MemorySubject, MemorySubjectBinding, Scope } from "../models.js";
import { authorizeMemoryAccess } from "../subject/binding.js";
import {
  type AuthoritativeBindingQuery,
  createAuthoritativeBindingQueryFromMetadataStore,
} from "./canonical-scope.js";
import {
  revalidateDelegationRecord,
  sameMemorySubject,
  type DelegationAuthorization,
  type DelegationAuthorizationStore,
} from "./delegation.js";
import {
  isUsableTrustedPrincipal,
  type TrustedPrincipal,
  type TrustedPrincipalProvider,
} from "./principal.js";
import {
  assertNoProductionSecurityOverrides,
  findCallerSecurityOverrides,
  isProductionLikeEnvironment,
  resolveTrustedRuntimeAssembly,
  type TrustedExecutionRequestAuthorization,
  type TrustedRuntime,
} from "./trusted-runtime.js";

export type { TrustedExecutionRequestAuthorization, TrustedRuntime } from "./trusted-runtime.js";
export {
  createAuthoritativeBindingQueryFromMetadataStore,
  isProductionLikeEnvironment,
};

/**
 * @deprecated CW-09-02-R5: request objects no longer carry authorization
 * infrastructure. Use `TrustedExecutionRequestAuthorization` (bearer token only)
 * plus a `TrustedRuntime` created by `createTrustedRuntime()`.
 */
export type TrustedExecutionAuthorizationOptions = TrustedExecutionRequestAuthorization;

/**
 * @deprecated CW-09-02-R5: production services are assembled only by
 * `createTrustedRuntime()`. This type is retained for documentation of the
 * sealed assembly shape and must not be accepted as a job/request field.
 */
export type TrustedAuthorizationAssembly = {
  principalProvider: TrustedPrincipalProvider;
  bindingQuery?: AuthoritativeBindingQuery;
  delegationStore?: DelegationAuthorizationStore;
};

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

/**
 * @deprecated CW-09-02-R5: requireAuth is decided only by a TrustedRuntime.
 * This helper always returns true so a caller cannot use it to downgrade.
 */
export function resolveRequireAuth(_options?: {
  requireAuth?: boolean;
  environment?: import("../models.js").EngineEnvironment;
}): boolean {
  return true;
}

export function resolveRequireAuthFromRuntime(runtime: TrustedRuntime): boolean {
  return resolveTrustedRuntimeAssembly(runtime).requireAuth;
}

/**
 * Authorize the chain:
 * Trusted Principal → Actor → Delegation Authorization → Caller Subject →
 * Authoritative Binding → Job Subject.
 *
 * Environment, requireAuth, Principal Provider, Binding Query, Delegation Store,
 * Trusted Principal, and local injection permission come only from `runtime`.
 * Caller-declared `actorUserId`, `delegatedActorFor`, and `ctx.bindings` are never evidence.
 */
export async function authorizeTrustedExecution(input: {
  request: TrustedExecutionRequest;
  /** Sealed runtime created by `createTrustedRuntime()`. Required. */
  runtime: TrustedRuntime;
  /** Request data only. Bearer token is allowed; security configuration is not. */
  authorization?: TrustedExecutionRequestAuthorization;
}): Promise<TrustedExecutionAuthorizationSuccess> {
  const request = input.request;
  const now = request.now ?? new Date().toISOString();
  const traceId = request.traceId ?? `auth_${randomUUID()}`;

  const denyBase = {
    tenantId: request.tenantId,
    scope: request.scope,
    traceId,
    at: now,
    actorUserId: request.declaredActorUserId ?? "",
    caller: request.declaredCaller,
    subject: request.declaredCaller,
  };

  let assembly;
  try {
    assembly = resolveTrustedRuntimeAssembly(input.runtime);
  } catch (error) {
    const decision = buildDecision({
      ...denyBase,
      decision: "deny",
      reason: "untrusted_runtime",
    });
    if (error instanceof UntrustedRuntimeError) {
      throw new UntrustedRuntimeError(error.message, decision);
    }
    throw new UntrustedRuntimeError(
      "Trusted runtime assembly is required for execution authorization",
      decision,
    );
  }

  // Snapshot runtime facts once. Later mutation of the request object cannot
  // change environment, requireAuth, or assembled services.
  const environment = assembly.environment;
  const requireAuth = assembly.requireAuth;
  const bearerToken =
    typeof input.authorization?.bearerToken === "string" ? input.authorization.bearerToken : undefined;

  const overrideBags: unknown[] = [input, input.authorization];
  try {
    assertNoProductionSecurityOverrides({ environment, bags: overrideBags });
  } catch (error) {
    const keys = overrideBags.flatMap((bag) => findCallerSecurityOverrides(bag));
    const decision = buildDecision({
      ...denyBase,
      decision: "deny",
      reason: "security_override_rejected",
    });
    throw new SecurityOverrideRejectedError(
      error instanceof Error
        ? error.message
        : `Production execution rejects caller security overrides: ${[...new Set(keys)].join(", ")}`,
      decision,
    );
  }

  let principal: TrustedPrincipal | undefined;
  if (requireAuth) {
    if (assembly.allowLocalInjection && isUsableTrustedPrincipal(assembly.injectedPrincipal)) {
      principal = assembly.injectedPrincipal;
    } else if (assembly.principalProvider) {
      try {
        const resolved = await assembly.principalProvider.resolvePrincipal({
          bearerToken,
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
    if (principal && principal.tenantId !== principal.subject.tenantId) {
      const decision = buildDecision({
        ...denyBase,
        actorUserId: principal.userId,
        principalTokenId: principal.tokenId,
        decision: "deny",
        reason: "tenant_mismatch",
      });
      throw new PrincipalUnavailableError(
        "Trusted principal tenant must equal subject tenant",
        decision,
      );
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

  const callerMatchesPrincipalSubject = principal ? sameMemorySubject(caller, principal.subject) : true;
  const actorIsCallerOwner = actorUserId === caller.ownerId;
  const needsDelegation = !actorIsCallerOwner || (Boolean(principal) && !callerMatchesPrincipalSubject);

  let delegation: DelegationAuthorization | undefined;
  if (needsDelegation) {
    const delegationStore = assembly.delegationStore;
    if (!delegationStore) {
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
    const delegationQuery = {
      tenantId: request.tenantId,
      actorUserId,
      subject: caller,
      scope: request.scope,
      now,
    };
    try {
      active = await delegationStore.getActiveDelegation(delegationQuery);
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
    const revalidation = revalidateDelegationRecord(active, delegationQuery);
    if (revalidation) {
      const decision = buildDecision({
        ...denyBase,
        actorUserId,
        caller,
        subject: jobSubject,
        principalTokenId: principal?.tokenId,
        decision: "deny",
        reason: `delegation_${revalidation}`,
      });
      throw new DelegationDeniedError(
        `Delegation store record failed independent re-validation (${revalidation})`,
        decision,
      );
    }
    delegation = active;
  }

  const bindingQuery = assembly.bindingQuery;
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
      "Authoritative Binding query is required; caller-submitted bindings and data-plane metadataStore are not evidence",
      decision,
    );
  }

  let bindings: MemorySubjectBinding[];
  try {
    bindings = await bindingQuery.listLiveBindings({
      tenantId: principal?.tenantId ?? request.tenantId,
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
