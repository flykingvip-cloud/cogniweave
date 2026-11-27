import { describe, expect, it } from "vitest";
import {
  BindingStoreUnavailableError,
  DelegationDeniedError,
  PrincipalUnavailableError,
  ScopeViolationError,
  SecurityOverrideRejectedError,
  UntrustedRuntimeError,
} from "../errors.js";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type { MemoryAtom, MemorySubject, Scope } from "../models.js";
import { runOptimizationJob } from "../optimization/job.js";
import { routeCogniWeaveHttpRequest } from "../rest/node-server.js";
import { CogniWeaveRestService } from "../rest/service.js";
import { InMemoryCogniWeaveEngine } from "../runtime/in-memory-engine.js";
import { InMemoryMetadataStore } from "../storage/in-memory.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import { authorizeTrustedExecution } from "./authorize.js";
import {
  authorizeCanonicalResource,
  createAuthoritativeBindingQueryFromMetadataStore,
  createDenyByDefaultBindingQuery,
} from "./canonical-scope.js";
import { createMemoryDelegationAuthorizationStore } from "./delegation.js";
import { ENGINE_DIRECT_AUTH_ENTRYPOINTS } from "./engine-invocation.js";
import { createDenyByDefaultPrincipalProvider, type TrustedPrincipal } from "./principal.js";
import {
  createTrustedRuntime,
  isVerifiableTrustedRuntime,
  resolveTrustedRuntimeAssembly,
} from "./trusted-runtime.js";

const SCOPE: Scope = {
  workspaceId: "ws_1",
  projectId: "proj_1",
  agentId: "agent_main",
  visibility: "private",
};

const SUBJECT: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "u_1" };
const OTHER: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "u_other" };
const NOW = "2026-11-28T00:00:00.000Z";
const TOKEN = "tok_r5";
const DATA_PLANE = "dp_r5";

const PRINCIPAL: TrustedPrincipal = {
  tenantId: "t_1",
  userId: "u_1",
  subject: SUBJECT,
  tokenId: "tok_r5",
  allowedWorkspaceIds: ["ws_1"],
};

function liveBinding(subject: MemorySubject = SUBJECT) {
  return createMemorySubjectBinding({
    partition: createMemoryPartitionKeyV1(DATA_PLANE, SCOPE),
    scope: SCOPE,
    subject,
    now: NOW,
  });
}

function serviceRuntime(extras: Parameters<typeof createTrustedRuntime>[0] extends infer T
  ? Partial<Omit<T, "environment">>
  : never = {}) {
  return createTrustedRuntime({
    environment: "service",
    principalProvider: createDenyByDefaultPrincipalProvider([{ token: TOKEN, principal: PRINCIPAL }]),
    bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]),
    ...extras,
  });
}

function request() {
  return {
    tenantId: "t_1",
    subjectId: "u_1",
    scope: SCOPE,
    dataPlaneId: DATA_PLANE,
    declaredActorUserId: "u_1",
    declaredCaller: SUBJECT,
    now: NOW,
  };
}

function makeAtom(id = "atm_r5"): MemoryAtom {
  return {
    id,
    atomType: "strategy",
    scope: SCOPE,
    claim: { type: "procedural", statement: "Keep the runtime sealed." },
    trigger: { conditions: ["auth"], contextTags: ["r5"] },
    applicability: { include: [], exclude: [] },
    provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_1"] },
    versioning: { version: 1 },
    state: { status: "active", conflictsWith: [] },
    metrics: { confidence: 0.8, reuseCount: 0 },
    dedupKey: id,
  };
}

const JOB_CTX = {
  actorUserId: "u_1",
  tenantId: "t_1",
  scope: SCOPE,
  caller: SUBJECT,
  dataPlaneId: DATA_PLANE,
};

describe("CW-09-02-R5 trusted runtime capability (unit)", () => {
  it("does not treat a same-shaped ordinary object as a trusted assembly", () => {
    const runtime = createTrustedRuntime({ environment: "service" });
    const forged = { environment: "service" as const, requireAuth: true };
    expect(isVerifiableTrustedRuntime(runtime)).toBe(true);
    expect(isVerifiableTrustedRuntime(forged)).toBe(false);
    expect(resolveTrustedRuntimeAssembly(runtime).environment).toBe("service");
    expect(() => resolveTrustedRuntimeAssembly(forged)).toThrow(UntrustedRuntimeError);
  });

  it("forces authentication on for service and cloud bootstraps", () => {
    const service = createTrustedRuntime({ environment: "service", requireAuth: false });
    const cloud = createTrustedRuntime({ environment: "cloud", requireAuth: false, allowLocalInjection: true });
    expect(resolveTrustedRuntimeAssembly(service).requireAuth).toBe(true);
    expect(resolveTrustedRuntimeAssembly(service).allowLocalInjection).toBe(false);
    expect(resolveTrustedRuntimeAssembly(cloud).requireAuth).toBe(true);
    expect(resolveTrustedRuntimeAssembly(cloud).allowLocalInjection).toBe(false);
  });
});

describe("CW-09-02-R5 authorizeTrustedExecution and runOptimizationJob (unit)", () => {
  it("rejects a production request that forges a local environment or turns off requireAuth", async () => {
    const runtime = serviceRuntime();
    const envSpoof = { bearerToken: TOKEN, environment: "local" };
    await expect(
      authorizeTrustedExecution({ request: request(), runtime, authorization: envSpoof as never }),
    ).rejects.toBeInstanceOf(SecurityOverrideRejectedError);
    await expect(
      runOptimizationJob({
        tenantId: "t_1",
        subjectId: "u_1",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [makeAtom()],
        executionContext: JOB_CTX,
        runtime,
        authorization: envSpoof as never,
      }),
    ).rejects.toBeInstanceOf(SecurityOverrideRejectedError);

    await expect(
      authorizeTrustedExecution({
        request: request(),
        runtime: createTrustedRuntime({
          environment: "cloud",
          principalProvider: createDenyByDefaultPrincipalProvider([{ token: TOKEN, principal: PRINCIPAL }]),
          bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]),
        }),
        authorization: { bearerToken: TOKEN, requireAuth: false } as never,
      }),
    ).rejects.toBeInstanceOf(SecurityOverrideRejectedError);
  });

  it("rejects production injection of principal, provider, binding query, delegation store, and trusted services", async () => {
    const runtime = serviceRuntime();
    const cases: Array<{ authorization?: never; extra?: Record<string, unknown> }> = [
      { authorization: { bearerToken: TOKEN, principal: PRINCIPAL, allowInjectedPrincipal: true } as never },
      { authorization: { bearerToken: TOKEN, principalProvider: createDenyByDefaultPrincipalProvider([]) } as never },
      { authorization: { bearerToken: TOKEN, bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]) } as never },
      { authorization: { bearerToken: TOKEN, delegationStore: createMemoryDelegationAuthorizationStore() } as never },
      { authorization: { bearerToken: TOKEN, trustedServices: { principalProvider: createDenyByDefaultPrincipalProvider([]) } } as never },
    ];
    for (const testCase of cases) {
      await expect(
        authorizeTrustedExecution({
          request: request(),
          runtime,
          authorization: testCase.authorization,
        }),
      ).rejects.toBeInstanceOf(SecurityOverrideRejectedError);
      await expect(
        runOptimizationJob({
          tenantId: "t_1",
          subjectId: "u_1",
          scope: SCOPE,
          optimizationType: "consolidation",
          atoms: [makeAtom()],
          executionContext: JOB_CTX,
          runtime,
          authorization: testCase.authorization,
        }),
      ).rejects.toBeInstanceOf(SecurityOverrideRejectedError);
    }

    await expect(
      runOptimizationJob({
        tenantId: "t_1",
        subjectId: "u_1",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [makeAtom()],
        executionContext: JOB_CTX,
        runtime,
        authorization: { bearerToken: TOKEN },
        trustedServices: {
          principalProvider: createDenyByDefaultPrincipalProvider([{ token: TOKEN, principal: PRINCIPAL }]),
        },
      } as never),
    ).rejects.toBeInstanceOf(SecurityOverrideRejectedError);
  });

  it("does not let a forged same-shaped runtime or a missing/throwing binding query authorize a job", async () => {
    await expect(
      authorizeTrustedExecution({
        request: request(),
        runtime: { environment: "service", requireAuth: true } as never,
        authorization: { bearerToken: TOKEN },
      }),
    ).rejects.toBeInstanceOf(UntrustedRuntimeError);

    const missing = createTrustedRuntime({
      environment: "service",
      principalProvider: createDenyByDefaultPrincipalProvider([{ token: TOKEN, principal: PRINCIPAL }]),
    });
    await expect(
      authorizeTrustedExecution({ request: request(), runtime: missing, authorization: { bearerToken: TOKEN } }),
    ).rejects.toBeInstanceOf(BindingStoreUnavailableError);

    const throwing = createTrustedRuntime({
      environment: "service",
      principalProvider: createDenyByDefaultPrincipalProvider([{ token: TOKEN, principal: PRINCIPAL }]),
      bindingQuery: {
        async listLiveBindings() {
          throw new Error("binding store down");
        },
      },
    });
    await expect(
      authorizeTrustedExecution({ request: request(), runtime: throwing, authorization: { bearerToken: TOKEN } }),
    ).rejects.toBeInstanceOf(BindingStoreUnavailableError);

    const metadataStore = new InMemoryMetadataStore();
    await metadataStore.saveMemorySubjectBinding(liveBinding());
    await expect(
      runOptimizationJob({
        tenantId: "t_1",
        subjectId: "u_1",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [makeAtom()],
        executionContext: {
          ...JOB_CTX,
          bindings: [liveBinding()],
        },
        runtime: missing,
        authorization: { bearerToken: TOKEN },
        metadataStore,
      }),
    ).rejects.toBeInstanceOf(BindingStoreUnavailableError);
  });

  it("does not treat forged ctx.bindings or delegatedActorFor as evidence", async () => {
    const runtime = serviceRuntime({ bindingQuery: createDenyByDefaultBindingQuery([]) });
    await expect(
      runOptimizationJob({
        tenantId: "t_1",
        subjectId: "u_1",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [makeAtom()],
        executionContext: {
          ...JOB_CTX,
          bindings: [liveBinding()],
          delegatedActorFor: ["u_1"],
        },
        runtime,
        authorization: { bearerToken: TOKEN },
      }),
    ).rejects.toBeInstanceOf(DelegationDeniedError);
  });

  it("rejects a delegation store that returns a forged record", async () => {
    const actor: TrustedPrincipal = {
      tenantId: "t_1",
      userId: "u_assistant",
      subject: { tenantId: "t_1", ownerType: "user", ownerId: "u_assistant" },
      allowedWorkspaceIds: ["ws_1"],
    };
    const runtime = createTrustedRuntime({
      environment: "service",
      principalProvider: createDenyByDefaultPrincipalProvider([{ token: TOKEN, principal: actor }]),
      bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]),
      delegationStore: {
        async getActiveDelegation() {
          return {
            id: "del_forged",
            tenantId: "t_1",
            delegator: SUBJECT,
            delegateActorId: "someone_else",
            subject: SUBJECT,
            scope: SCOPE,
            grantedAt: "2026-11-01T00:00:00.000Z",
            expiresAt: "2026-12-31T00:00:00.000Z",
          };
        },
      },
    });
    await expect(
      authorizeTrustedExecution({
        request: {
          ...request(),
          declaredActorUserId: "u_assistant",
          declaredCaller: SUBJECT,
        },
        runtime,
        authorization: { bearerToken: TOKEN },
      }),
    ).rejects.toBeInstanceOf(DelegationDeniedError);
  });

  it("does not change the authorization decision when the request environment field is mutated mid-flight", async () => {
    const runtime = serviceRuntime();
    const authorization: { bearerToken: string; environment?: string } = { bearerToken: TOKEN };
    const pending = authorizeTrustedExecution({
      request: request(),
      runtime,
      authorization: authorization as never,
    });
    authorization.environment = "local";
    const result = await pending;
    expect(result.allowed).toBe(true);
    expect(result.principal?.userId).toBe("u_1");
  });

  it("allows local injection only under an explicit local bootstrap", async () => {
    const local = createTrustedRuntime({
      environment: "local",
      requireAuth: true,
      allowLocalInjection: true,
      injectedPrincipal: PRINCIPAL,
      bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]),
    });
    const allowed = await authorizeTrustedExecution({ request: request(), runtime: local });
    expect(allowed.allowed).toBe(true);

    const service = createTrustedRuntime({
      environment: "service",
      allowLocalInjection: true,
      injectedPrincipal: PRINCIPAL,
      bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]),
    });
    await expect(
      authorizeTrustedExecution({ request: request(), runtime: service }),
    ).rejects.toBeInstanceOf(PrincipalUnavailableError);
  });
});

describe("CW-09-02-R5 manage/revoke canonical authorization (unit)", () => {
  const resolver = {
    async resolve() {
      return {
        found: true,
        kind: "memory_resource" as const,
        id: "res_1",
        scope: SCOPE,
        tenantId: "t_1",
        owner: { ownerType: "user" as const, ownerId: "u_1" },
        lifecycleStatus: "active" as const,
      };
    },
  };

  it("rejects cross-subject, cross-workspace, admin-only, and revoked-subject manage/revoke without leaking existence", async () => {
    const allowWs = async (workspaceId: string) => workspaceId === "ws_1";
    const bindingQuery = createDenyByDefaultBindingQuery([liveBinding()]);

    const otherPrincipal = { tenantId: "t_1", userId: "u_other", roles: ["tenant_admin"], subject: OTHER };
    for (const mode of ["manage", "revoke"] as const) {
      const decision = await authorizeCanonicalResource({
        kind: "memory_resource",
        id: "res_1",
        principal: otherPrincipal,
        mode,
        resolver,
        authorizeWorkspace: allowWs,
        bindingQuery,
        ensureDataPlaneId: async () => DATA_PLANE,
      });
      expect(decision).toEqual({ allowed: false, httpStatus: 404, error: "not_found" });
    }

    const crossWorkspace = await authorizeCanonicalResource({
      kind: "memory_resource",
      id: "res_1",
      principal: { ...PRINCIPAL, allowedWorkspaceIds: ["ws_other"] },
      mode: "revoke",
      resolver,
      authorizeWorkspace: async () => false,
      bindingQuery,
      ensureDataPlaneId: async () => DATA_PLANE,
    });
    expect(crossWorkspace).toEqual({ allowed: false, httpStatus: 404, error: "not_found" });

    const missing = await authorizeCanonicalResource({
      kind: "memory_resource",
      id: "res_missing",
      principal: PRINCIPAL,
      mode: "revoke",
      resolver: {
        async resolve() {
          return { found: false, kind: "memory_resource" as const, id: "res_missing", unresolvedReason: "not_found" as const };
        },
      },
      authorizeWorkspace: allowWs,
      bindingQuery,
      ensureDataPlaneId: async () => DATA_PLANE,
    });
    expect(missing).toEqual({ allowed: false, httpStatus: 404, error: "not_found" });

    const revokedBinding = await authorizeCanonicalResource({
      kind: "memory_resource",
      id: "res_1",
      principal: PRINCIPAL,
      mode: "manage",
      resolver,
      authorizeWorkspace: allowWs,
      bindingQuery: createDenyByDefaultBindingQuery([]),
      ensureDataPlaneId: async () => DATA_PLANE,
    });
    expect(revokedBinding).toEqual({ allowed: false, httpStatus: 404, error: "not_found" });
  });

  it("allows an owner with a live binding to revoke, and treats a repeat revoke as idempotent success", async () => {
    const allowWs = async () => true;
    const first = await authorizeCanonicalResource({
      kind: "memory_resource",
      id: "res_1",
      principal: PRINCIPAL,
      mode: "revoke",
      resolver,
      authorizeWorkspace: allowWs,
      bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]),
      ensureDataPlaneId: async () => DATA_PLANE,
    });
    expect(first.allowed).toBe(true);

    const repeat = await authorizeCanonicalResource({
      kind: "memory_resource",
      id: "res_1",
      principal: PRINCIPAL,
      mode: "revoke",
      resolver: {
        async resolve() {
          return {
            found: true,
            kind: "memory_resource" as const,
            id: "res_1",
            scope: SCOPE,
            tenantId: "t_1",
            owner: { ownerType: "user" as const, ownerId: "u_1" },
            lifecycleStatus: "revoked" as const,
          };
        },
      },
      authorizeWorkspace: allowWs,
      bindingQuery: createDenyByDefaultBindingQuery([]),
      ensureDataPlaneId: async () => DATA_PLANE,
    });
    expect(repeat.allowed).toBe(true);
  });
});

describe("CW-09-02-R5 REST, engine-direct, and optimization matrix (unit)", () => {
  it("publishes a complete engine-direct entry inventory including rebuild, repair, and recover", () => {
    const methods = ENGINE_DIRECT_AUTH_ENTRYPOINTS.map((entry) => entry.method);
    expect(methods).toEqual(expect.arrayContaining([
      "rebuildFromTruth",
      "repairIndexes",
      "recoverFromCanonical",
      "ensureMemorySubjectBinding",
      "writeBack",
      "queryAtoms",
    ]));
  });

  async function serviceEngine() {
    const metadataStore = new InMemoryMetadataStore();
    const dataPlaneId = await metadataStore.ensureDataPlaneId();
    const binding = createMemorySubjectBinding({
      partition: createMemoryPartitionKeyV1(dataPlaneId, SCOPE),
      scope: SCOPE,
      subject: SUBJECT,
    });
    await metadataStore.saveMemorySubjectBinding(binding);
    const runtime = createTrustedRuntime({
      environment: "service",
      principalProvider: createDenyByDefaultPrincipalProvider([{ token: TOKEN, principal: PRINCIPAL }]),
      bindingQuery: createAuthoritativeBindingQueryFromMetadataStore(metadataStore),
      ensureDataPlaneId: () => metadataStore.ensureDataPlaneId(),
    });
    const engine = new InMemoryCogniWeaveEngine(
      {
        environment: "service",
        metadataBackend: "memory",
        graphBackend: "memory",
        evidenceBackend: "memory",
        vectorBackend: "memory",
      },
      { metadataStore, runtime },
    );
    return { engine, metadataStore, runtime, service: new CogniWeaveRestService(engine) };
  }

  it("rejects unauthenticated and forged REST production requests without honoring request security fields", async () => {
    const { service } = await serviceEngine();
    const denied = await routeCogniWeaveHttpRequest(service, {
      method: "POST",
      url: "/v1/tasks/frame",
      headers: {
        authorization: "Bearer forged",
        "x-cogniweave-tenant-id": "t_1",
      },
      body: JSON.stringify({ rawInput: "plan", scope: SCOPE, environment: "local", requireAuth: false }),
    });
    expect(denied.status).toBe(401);

    const unauth = await routeCogniWeaveHttpRequest(service, {
      method: "POST",
      url: "/v1/repair/indexes",
      headers: { "x-cogniweave-tenant-id": "t_1" },
      body: JSON.stringify({ scope: SCOPE }),
    });
    expect(unauth.status).toBe(401);
  });

  it("rejects engine-direct unauthorized, unresolvable, and binding-provision calls in service runtime", async () => {
    const { engine } = await serviceEngine();
    await expect(engine.repairIndexes({ scope: SCOPE })).rejects.toBeInstanceOf(PrincipalUnavailableError);
    await expect(
      engine.rebuildFromTruth({ objectType: "atom", objectId: "atm_missing", scope: SCOPE }),
    ).rejects.toBeInstanceOf(PrincipalUnavailableError);
    await expect(engine.recoverFromCanonical({ scope: SCOPE })).rejects.toBeInstanceOf(PrincipalUnavailableError);
    await expect(
      engine.repairIndexes({ scope: SCOPE, authorization: { bearerToken: "forged" } }),
    ).rejects.toBeInstanceOf(PrincipalUnavailableError);
    await expect(
      engine.rebuildFromTruth({
        objectType: "atom",
        objectId: "atm_missing",
        scope: SCOPE,
        authorization: { bearerToken: TOKEN },
      }),
    ).rejects.toBeInstanceOf(ScopeViolationError);
    await expect(
      engine.ensureMemorySubjectBinding({
        scope: SCOPE,
        caller: SUBJECT,
        authorization: { bearerToken: TOKEN },
      }),
    ).rejects.toBeInstanceOf(DelegationDeniedError);
  });

  it("still allows an unauthenticated local engine and does not let a local request field downgrade a service engine", async () => {
    const local = new InMemoryCogniWeaveEngine({
      environment: "local",
      metadataBackend: "memory",
      graphBackend: "memory",
      evidenceBackend: "memory",
      vectorBackend: "memory",
    });
    const frame = await local.frameTask("Current throughput is dropping and the API is slow.", { scope: SCOPE });
    expect(frame.scope).toEqual(SCOPE);

    const { engine } = await serviceEngine();
    await expect(
      engine.frameTask("Current throughput is dropping and the API is slow.", {
        scope: SCOPE,
        authorization: { bearerToken: TOKEN, environment: "local" } as never,
      }),
    ).rejects.toBeInstanceOf(SecurityOverrideRejectedError);
  });
});
