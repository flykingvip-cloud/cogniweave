import {
  BindingStoreUnavailableError,
  DelegationDeniedError,
  PrincipalUnavailableError,
  ScopeViolationError,
  UntrustedRuntimeError,
} from "../errors.js";
import type { EngineEnvironment, Scope } from "../models.js";
import {
  authorizeCanonicalResource,
  authorizeDeclaredScope,
  type CanonicalAuthorizationMode,
  type CanonicalResourceKind,
  type CanonicalResourceScopeResolver,
} from "./canonical-scope.js";
import { isUsableTrustedPrincipal, type TrustedPrincipal } from "./principal.js";
import {
  assertNoProductionSecurityOverrides,
  isProductionLikeEnvironment,
  resolveTrustedRuntimeAssembly,
  type TrustedExecutionRequestAuthorization,
  type TrustedRuntime,
} from "./trusted-runtime.js";

/**
 * Public Engine / SDK methods that read, write, rebuild, or modify
 * Canonical or Derived data. REST authorization does not automatically
 * prove these entry points are safe when invoked directly.
 *
 * This list must match the remaining public I/O surface on
 * `CogniWeaveEngine` / `InMemoryCogniWeaveEngine`. Private or unexported
 * helpers (ungated Canonical lookup, source-binding status predicates,
 * `src/journal/repair.ts`) are intentionally omitted. Presence on this
 * list is not proof that a method's implementation is authorized.
 */
export const ENGINE_DIRECT_AUTH_ENTRYPOINTS = [
  { method: "frameTask", classification: "declared_scope", mode: "manage" },
  { method: "reason", classification: "declared_scope", mode: "read" },
  { method: "reasonWithDebug", classification: "declared_scope", mode: "read" },
  { method: "ingest", classification: "declared_scope", mode: "manage" },
  { method: "distill", classification: "declared_scope", mode: "manage" },
  { method: "writeBack", classification: "declared_scope", mode: "manage" },
  { method: "upsertEvent", classification: "declared_scope", mode: "manage" },
  { method: "upsertAtoms", classification: "declared_scope", mode: "manage" },
  { method: "trace", classification: "resource_id", mode: "read", kind: "atom" },
  { method: "tracePackage", classification: "resource_id", mode: "read", kind: "package" },
  { method: "traceReasoningSession", classification: "resource_id", mode: "read", kind: "session" },
  { method: "getProvenance", classification: "resource_id", mode: "read", kind: "atom" },
  { method: "getConflicts", classification: "resource_id", mode: "read", kind: "atom" },
  { method: "getVersionHistory", classification: "resource_id", mode: "read", kind: "atom" },
  { method: "resolveEvidence", classification: "declared_or_resource", mode: "read" },
  { method: "getEvidenceRefs", classification: "resource_id", mode: "read", kind: "atom" },
  { method: "searchEvidence", classification: "declared_scope", mode: "read" },
  { method: "queryAtoms", classification: "declared_scope", mode: "read" },
  { method: "queryAtomsHybrid", classification: "declared_scope", mode: "read" },
  { method: "ensureMemorySubjectBinding", classification: "binding_provision", mode: "manage" },
  { method: "detectConflicts", classification: "declared_scope", mode: "read" },
  { method: "recomputeConfidence", classification: "resource_id", mode: "manage", kind: "atom" },
  { method: "deprecateAtom", classification: "resource_id", mode: "manage", kind: "atom" },
  { method: "supersedeAtom", classification: "resource_id", mode: "manage", kind: "atom" },
  { method: "mergeAtoms", classification: "resource_id", mode: "manage", kind: "atom" },
  { method: "repairIndexes", classification: "declared_or_resource", mode: "manage" },
  { method: "rebuildFromTruth", classification: "resource_id", mode: "manage" },
  { method: "recoverFromCanonical", classification: "declared_scope", mode: "manage" },
  { method: "compactJournals", classification: "declared_scope", mode: "manage" },
  { method: "getWriteJournal", classification: "resource_id", mode: "read", kind: "journal" },
  { method: "archiveSource", classification: "declared_scope", mode: "manage" },
  { method: "restoreSource", classification: "declared_scope", mode: "manage" },
  { method: "forgetSource", classification: "declared_scope", mode: "manage" },
  { method: "purgeSource", classification: "declared_scope", mode: "manage" },
  { method: "listLiveSourcesForAtom", classification: "resource_id", mode: "read", kind: "atom" },
  { method: "resolveCanonicalResourceScope", classification: "resource_id", mode: "read" },
] as const;

export type EngineDirectAuthMethod = (typeof ENGINE_DIRECT_AUTH_ENTRYPOINTS)[number]["method"];

export type EngineDirectAuthorizationSuccess = {
  unauthenticatedLocal: false;
  principal: TrustedPrincipal;
  scope?: Scope;
  bindingId?: string;
};

export type EngineDirectAuthorizationLocal = {
  unauthenticatedLocal: true;
};

export type EngineDirectAuthorizationResult =
  | EngineDirectAuthorizationSuccess
  | EngineDirectAuthorizationLocal;

export async function authorizeEngineDirectInvocation(input: {
  runtime: TrustedRuntime;
  method: string;
  mode: CanonicalAuthorizationMode;
  authorization?: TrustedExecutionRequestAuthorization;
  declaredScope?: Scope | null;
  resource?: { kind: CanonicalResourceKind; id: string };
  resolver?: CanonicalResourceScopeResolver;
  authorizeWorkspace?: (workspaceId: string) => Promise<boolean>;
}): Promise<EngineDirectAuthorizationResult> {
  const assembly = resolveTrustedRuntimeAssembly(input.runtime);
  assertNoProductionSecurityOverrides({
    environment: assembly.environment,
    bags: [input.authorization, input],
  });

  if (!assembly.requireAuth && assembly.environment === "local") {
    return { unauthenticatedLocal: true };
  }

  if (input.method === "ensureMemorySubjectBinding" && isProductionLikeEnvironment(assembly.environment)) {
    throw new DelegationDeniedError(
      "Public ensureMemorySubjectBinding cannot create or grant production subject bindings",
      {
        decision: "deny",
        reason: "binding_provision_forbidden",
        method: input.method,
      },
    );
  }

  let principal: TrustedPrincipal | undefined;
  if (assembly.allowLocalInjection && isUsableTrustedPrincipal(assembly.injectedPrincipal)) {
    principal = assembly.injectedPrincipal;
  } else if (assembly.principalProvider) {
    try {
      const resolved = await assembly.principalProvider.resolvePrincipal({
        bearerToken: input.authorization?.bearerToken,
        environment: assembly.environment,
      });
      if (isUsableTrustedPrincipal(resolved)) {
        principal = resolved;
      }
    } catch (error) {
      throw new PrincipalUnavailableError(
        error instanceof Error ? error.message : "Trusted principal provider failed",
        { decision: "deny", reason: "principal_unavailable", method: input.method },
      );
    }
  }
  if (!principal) {
    throw new PrincipalUnavailableError(
      `Engine method ${input.method} requires a trusted principal; missing security context is fail-closed`,
      { decision: "deny", reason: "principal_unavailable", method: input.method },
    );
  }

  const authorizeWorkspace =
    input.authorizeWorkspace ??
    (async (workspaceId: string) => Boolean(principal!.allowedWorkspaceIds?.includes(workspaceId)));

  if (input.resource) {
    if (!input.resolver) {
      throw new UntrustedRuntimeError(
        `Engine method ${input.method} cannot authorize a resource id without a canonical resolver`,
        { decision: "deny", reason: "untrusted_runtime", method: input.method },
      );
    }
    const decision = await authorizeCanonicalResource({
      kind: input.resource.kind,
      id: input.resource.id,
      principal,
      mode: input.mode,
      resolver: input.resolver,
      authorizeWorkspace,
      bindingQuery: assembly.bindingQuery,
      ensureDataPlaneId: assembly.ensureDataPlaneId,
    });
    if (!decision.allowed) {
      if (decision.error === "store_unavailable" || decision.error === "binding_store_unavailable") {
        throw new BindingStoreUnavailableError(decision.error, {
          decision: "deny",
          reason: decision.error,
          method: input.method,
        });
      }
      if (decision.error === "unauthorized" || decision.error === "principal_unavailable") {
        throw new PrincipalUnavailableError(decision.error, {
          decision: "deny",
          reason: decision.error,
          method: input.method,
        });
      }
      throw new ScopeViolationError(
        `Engine method ${input.method} is not authorized for ${input.resource.kind} ${input.resource.id}`,
      );
    }
    return {
      unauthenticatedLocal: false,
      principal,
      scope: decision.scope,
    };
  }

  if (input.declaredScope !== undefined) {
    const decision = await authorizeDeclaredScope({
      principal,
      scope: input.declaredScope,
      authorizeWorkspace,
      bindingQuery: assembly.bindingQuery,
      ensureDataPlaneId: assembly.ensureDataPlaneId,
    });
    if (!decision.allowed) {
      if (decision.error === "binding_store_unavailable") {
        throw new BindingStoreUnavailableError(decision.error, {
          decision: "deny",
          reason: decision.error,
          method: input.method,
        });
      }
      if (decision.error === "unauthorized" || decision.error === "principal_unavailable") {
        throw new PrincipalUnavailableError(decision.error, {
          decision: "deny",
          reason: decision.error,
          method: input.method,
        });
      }
      throw new ScopeViolationError(
        `Engine method ${input.method} is not authorized for the declared scope`,
      );
    }
    return {
      unauthenticatedLocal: false,
      principal,
      scope: decision.scope,
      bindingId: decision.bindingId,
    };
  }

  if (isProductionLikeEnvironment(assembly.environment) || assembly.requireAuth) {
    throw new ScopeViolationError(
      `Engine method ${input.method} requires an explicit authorized scope or resource id`,
    );
  }
  return { unauthenticatedLocal: true };
}

export function extractBearerToken(authorization?: TrustedExecutionRequestAuthorization): string | undefined {
  return typeof authorization?.bearerToken === "string" ? authorization.bearerToken : undefined;
}

export function isLocalUnauthenticatedRuntime(
  environment: EngineEnvironment,
  runtime: TrustedRuntime,
): boolean {
  try {
    const assembly = resolveTrustedRuntimeAssembly(runtime);
    return assembly.environment === "local" && !assembly.requireAuth && environment === "local";
  } catch {
    return false;
  }
}
