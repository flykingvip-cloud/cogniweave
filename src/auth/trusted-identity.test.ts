import { describe, expect, it } from "vitest";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type { MemorySubject, Scope } from "../models.js";
import { InMemoryMetadataStore } from "../storage/in-memory.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import {
  BindingStoreUnavailableError,
  DelegationDeniedError,
  DelegationStoreUnavailableError,
  PrincipalUnavailableError,
} from "../errors.js";
import { authorizeTrustedExecution, type TrustedAuthorizationAssembly } from "./authorize.js";
import { createMemoryDelegationAuthorizationStore, revalidateDelegationRecord, type DelegationAuthorization } from "./delegation.js";
import { createDenyByDefaultPrincipalProvider, isUsableTrustedPrincipal, type TrustedPrincipal } from "./principal.js";
import { createDenyByDefaultBindingQuery } from "./canonical-scope.js";

const SCOPE: Scope = {
  workspaceId: "ws_1",
  projectId: "proj_1",
  agentId: "agent_main",
  visibility: "private",
};

const CALLER: MemorySubject = { tenantId: "t_1", ownerType: "agent", ownerId: "agent_main" };
const ACTOR: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "user_assistant" };
const DATA_PLANE = "dp_1";
const PARTITION = createMemoryPartitionKeyV1(DATA_PLANE, SCOPE);
const NOW = "2026-11-27T12:00:00.000Z";

const principalSelf: TrustedPrincipal = {
  tenantId: "t_1",
  userId: "agent_main",
  subject: CALLER,
  tokenId: "tok_self",
  allowedWorkspaceIds: ["ws_1"],
};

const principalActor: TrustedPrincipal = {
  tenantId: "t_1",
  userId: "user_assistant",
  subject: ACTOR,
  tokenId: "tok_actor",
  allowedWorkspaceIds: ["ws_1"],
};

function liveBinding(subject: MemorySubject = CALLER) {
  return createMemorySubjectBinding({
    partition: PARTITION,
    scope: SCOPE,
    subject,
    now: NOW,
  });
}

function lawfulDelegation(overrides: Partial<DelegationAuthorization> = {}): DelegationAuthorization {
  return {
    id: "del_1",
    tenantId: "t_1",
    delegator: CALLER,
    delegateActorId: "user_assistant",
    subject: CALLER,
    scope: SCOPE,
    grantedAt: "2026-11-01T00:00:00.000Z",
    expiresAt: "2026-12-31T00:00:00.000Z",
    ...overrides,
  };
}


const TEST_TOKEN = "tok";

function serviceTrusted(
  principal: TrustedPrincipal,
  extras: Omit<Partial<TrustedAuthorizationAssembly>, "principalProvider"> = {},
) {
  return {
    authorization: { environment: "service" as const, bearerToken: TEST_TOKEN },
    trustedServices: {
      principalProvider: createDenyByDefaultPrincipalProvider([{ token: TEST_TOKEN, principal }]),
      ...extras,
    },
  };
}

describe("CW-09-02 trusted identity and delegation (unit)", () => {
  it("denies a forged actorUserId that does not match the trusted principal", async () => {
    const binding = liveBinding();
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "u_forged",
          declaredCaller: CALLER,
          now: NOW,
          traceId: "tr_forged_actor",
        },
        ...serviceTrusted(principalSelf, { bindingQuery: createDenyByDefaultBindingQuery([binding]) }),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(DelegationDeniedError);
      const denied = err as DelegationDeniedError<import("./authorize.js").ExecutionAuthorizationDecision>;
      expect(denied.decision.decision).toBe("deny");
      expect(denied.decision.reason).toBe("forged_actor");
      expect(denied.decision.actor.userId).toBe("u_forged");
      expect(denied.decision.traceId).toBe("tr_forged_actor");
      return true;
    });
  });

  it("denies delegation that is claimed only via delegatedActorFor (no store record)", async () => {
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "user_assistant",
          declaredCaller: CALLER,
          now: NOW,
        },
        ...serviceTrusted(principalActor, { bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]) }),
      }),
    ).rejects.toBeInstanceOf(DelegationStoreUnavailableError);
  });

  it("denies expired, revoked, and cross-tenant delegation records", async () => {
    const bindingQuery = createDenyByDefaultBindingQuery([liveBinding()]);
    const expired = createMemoryDelegationAuthorizationStore([
      lawfulDelegation({ id: "del_exp", expiresAt: "2026-11-01T00:00:00.000Z" }),
    ]);
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "user_assistant",
          declaredCaller: CALLER,
          now: NOW,
        },
        ...serviceTrusted(principalActor, { bindingQuery, delegationStore: expired }),
      }),
    ).rejects.toBeInstanceOf(DelegationDeniedError);

    const revoked = createMemoryDelegationAuthorizationStore([
      lawfulDelegation({ id: "del_rev", revokedAt: "2026-11-26T00:00:00.000Z" }),
    ]);
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "user_assistant",
          declaredCaller: CALLER,
          now: NOW,
        },
        ...serviceTrusted(principalActor, { bindingQuery, delegationStore: revoked }),
      }),
    ).rejects.toBeInstanceOf(DelegationDeniedError);

    const crossTenant = createMemoryDelegationAuthorizationStore([
      lawfulDelegation({ id: "del_xt", tenantId: "t_other", delegator: { ...CALLER, tenantId: "t_other" } }),
    ]);
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "user_assistant",
          declaredCaller: CALLER,
          now: NOW,
        },
        ...serviceTrusted(principalActor, { bindingQuery, delegationStore: crossTenant }),
      }),
    ).rejects.toBeInstanceOf(DelegationDeniedError);
  });

  it("allows a lawful unexpired delegation and records audit fields", async () => {
    const binding = liveBinding();
    const store = createMemoryDelegationAuthorizationStore([lawfulDelegation()]);
    const result = await authorizeTrustedExecution({
      request: {
        tenantId: "t_1",
        subjectId: "agent_main",
        scope: SCOPE,
        dataPlaneId: DATA_PLANE,
        declaredActorUserId: "user_assistant",
        declaredCaller: CALLER,
        now: NOW,
        traceId: "tr_lawful",
      },
      ...serviceTrusted(principalActor, {
        delegationStore: store,
        bindingQuery: createDenyByDefaultBindingQuery([binding]),
      }),
    });

    expect(result.allowed).toBe(true);
    expect(result.actorUserId).toBe("user_assistant");
    expect(result.caller).toEqual(CALLER);
    expect(result.subject.ownerId).toBe("agent_main");
    expect(result.bindingId).toBe(binding.id);
    expect(result.delegation?.id).toBe("del_1");
    expect(result.decision).toMatchObject({
      actor: { userId: "user_assistant" },
      delegator: CALLER,
      caller: CALLER,
      subject: { tenantId: "t_1", ownerType: "agent", ownerId: "agent_main" },
      bindingId: binding.id,
      tenantId: "t_1",
      scope: SCOPE,
      decision: "allow",
      traceId: "tr_lawful",
      delegationId: "del_1",
      principalTokenId: "tok_actor",
    });
  });

  it("ignores forged caller-submitted bindings and uses the authoritative query", async () => {
    const forged = liveBinding(CALLER);
    // Authoritative store is empty (deny-by-default). Forged binding is not passed to the query.
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "agent_main",
          declaredCaller: CALLER,
          now: NOW,
        },
        ...serviceTrusted(principalSelf, { bindingQuery: createDenyByDefaultBindingQuery([]) }),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(DelegationDeniedError);
      const denied = err as DelegationDeniedError<import("./authorize.js").ExecutionAuthorizationDecision>;
      expect(denied.decision.reason).toBe("binding_unbound");
      expect(forged.id).toBeTruthy(); // forged binding exists but was not consulted
      return true;
    });
  });

  it("denies cross-subject and cross-tenant job execution", async () => {
    const binding = liveBinding();
    const bindingQuery = createDenyByDefaultBindingQuery([binding]);
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_other",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "agent_main",
          declaredCaller: CALLER,
          now: NOW,
        },
        ...serviceTrusted(principalSelf, { bindingQuery }),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(DelegationDeniedError);
      const denied = err as DelegationDeniedError<import("./authorize.js").ExecutionAuthorizationDecision>;
      expect(denied.decision.reason).toBe("job_subject_mismatch");
      return true;
    });

    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_other",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "agent_main",
          declaredCaller: CALLER,
          now: NOW,
        },
        ...serviceTrusted(principalSelf, { bindingQuery }),
      }),
    ).rejects.toBeInstanceOf(DelegationDeniedError);
  });

  it("denies production execution when the binding query or principal provider is missing or throws", async () => {
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "agent_main",
          declaredCaller: CALLER,
          now: NOW,
        },
        authorization: { environment: "service" },
      }),
    ).rejects.toBeInstanceOf(PrincipalUnavailableError);

    const throwingProvider = {
      async resolvePrincipal() {
        throw new Error("idp down");
      },
    };
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "agent_main",
          declaredCaller: CALLER,
          now: NOW,
        },
        authorization: { environment: "cloud", bearerToken: "tok" },
        trustedServices: { principalProvider: throwingProvider },
      }),
    ).rejects.toBeInstanceOf(PrincipalUnavailableError);

    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "agent_main",
          declaredCaller: CALLER,
          now: NOW,
        },
        ...serviceTrusted(principalSelf),
      }),
    ).rejects.toBeInstanceOf(BindingStoreUnavailableError);

    const throwingQuery = {
      async listLiveBindings() {
        throw new Error("binding db down");
      },
    };
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "agent_main",
          declaredCaller: CALLER,
          now: NOW,
        },
        ...serviceTrusted(principalSelf, { bindingQuery: throwingQuery }),
      }),
    ).rejects.toBeInstanceOf(BindingStoreUnavailableError);
  });

  it("does not treat requireAuth:false as a bypass in service/cloud", async () => {
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "agent_main",
          declaredCaller: CALLER,
          now: NOW,
        },
        authorization: { environment: "service", requireAuth: false },
      }),
    ).rejects.toBeInstanceOf(PrincipalUnavailableError);
  });

  it("deny-by-default principal provider only allows registered tokens", async () => {
    const provider = createDenyByDefaultPrincipalProvider([
      { token: "good", principal: principalSelf },
    ]);
    expect(await provider.resolvePrincipal({ bearerToken: "good", environment: "service" })).toEqual(
      principalSelf,
    );
    expect(await provider.resolvePrincipal({ bearerToken: "forged", environment: "service" })).toBeNull();
    expect(await provider.resolvePrincipal({ environment: "service" })).toBeNull();
  });

  it("local requireAuth false still cannot use a missing binding store or skipped delegation record", async () => {
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "agent_main",
          declaredCaller: CALLER,
          now: NOW,
        },
        authorization: { environment: "local", requireAuth: false },
      }),
    ).rejects.toBeInstanceOf(BindingStoreUnavailableError);

    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "user_assistant",
          declaredCaller: CALLER,
          now: NOW,
        },
        authorization: {
          environment: "local",
          requireAuth: false,
        },
        bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]),
      }),
    ).rejects.toBeInstanceOf(DelegationStoreUnavailableError);
  });

  it("accepts a metadata store as the authoritative binding source", async () => {
    const metadataStore = new InMemoryMetadataStore();
    const binding = liveBinding();
    await metadataStore.saveMemorySubjectBinding(binding);
    const result = await authorizeTrustedExecution({
      request: {
        tenantId: "t_1",
        subjectId: "agent_main",
        scope: SCOPE,
        dataPlaneId: DATA_PLANE,
        declaredActorUserId: "agent_main",
        declaredCaller: CALLER,
        now: NOW,
      },
      ...serviceTrusted(principalSelf, { metadataStore }),
    });
    expect(result.bindingId).toBe(binding.id);
    expect(result.decision.decision).toBe("allow");
  });
});

describe("CW-09-02-R1 production identity injection (unit)", () => {
  it("denies a caller-declared principal in service/cloud even when a forged binding query would allow", async () => {
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "agent_main",
          declaredCaller: CALLER,
          now: NOW,
        },
        authorization: {
          environment: "service",
          principal: principalSelf,
          bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]),
        },
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(PrincipalUnavailableError);
      const denied = err as PrincipalUnavailableError<import("./authorize.js").ExecutionAuthorizationDecision>;
      expect(denied.decision.reason).toBe("untrusted_principal_injection");
      return true;
    });
  });

  it("denies a forged loose Binding Query in production and does not consult it", async () => {
    const forged = createDenyByDefaultBindingQuery([liveBinding()]);
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "agent_main",
          declaredCaller: CALLER,
          now: NOW,
        },
        authorization: {
          environment: "service",
          bearerToken: TEST_TOKEN,
          bindingQuery: forged,
        },
        trustedServices: {
          principalProvider: createDenyByDefaultPrincipalProvider([
            { token: TEST_TOKEN, principal: principalSelf },
          ]),
        },
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(BindingStoreUnavailableError);
      const denied = err as BindingStoreUnavailableError<import("./authorize.js").ExecutionAuthorizationDecision>;
      expect(denied.decision.reason).toBe("untrusted_binding_query");
      return true;
    });
  });

  it("allows direct principal injection only on the isolated local path", async () => {
    const result = await authorizeTrustedExecution({
      request: {
        tenantId: "t_1",
        subjectId: "agent_main",
        scope: SCOPE,
        dataPlaneId: DATA_PLANE,
        declaredActorUserId: "agent_main",
        declaredCaller: CALLER,
        now: NOW,
      },
      authorization: {
        environment: "local",
        allowInjectedPrincipal: true,
        principal: principalSelf,
        bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]),
      },
    });
    expect(result.allowed).toBe(true);
    expect(result.actorUserId).toBe("agent_main");
  });
});

describe("CW-09-02-R2 principal tenant consistency at resolution (unit)", () => {
  it("treats a principal whose tenant differs from its subject tenant as unusable", () => {
    expect(
      isUsableTrustedPrincipal({
        tenantId: "t_a",
        userId: "u_1",
        subject: { tenantId: "t_b", ownerType: "user", ownerId: "u_1" },
      }),
    ).toBe(false);
    expect(isUsableTrustedPrincipal(principalSelf)).toBe(true);
  });

  it("denies a trusted provider that returns mismatched principal and subject tenants", async () => {
    const mismatched: TrustedPrincipal = {
      tenantId: "t_a",
      userId: "agent_main",
      subject: { ...CALLER, tenantId: "t_b" },
    };
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_a",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "agent_main",
          declaredCaller: { ...CALLER, tenantId: "t_a" },
          now: NOW,
        },
        authorization: { environment: "service", bearerToken: TEST_TOKEN },
        trustedServices: {
          principalProvider: createDenyByDefaultPrincipalProvider([
            { token: TEST_TOKEN, principal: mismatched },
          ]),
          bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]),
        },
      }),
    ).rejects.toBeInstanceOf(PrincipalUnavailableError);
  });
});

describe("CW-09-02-R3 delegation store re-validation (unit)", () => {
  const query = {
    tenantId: "t_1",
    actorUserId: "user_assistant",
    subject: CALLER,
    scope: SCOPE,
    now: NOW,
  };

  it("re-validates store records and denies mismatched, incomplete, expired, unparsable, or revoked rows", () => {
    const lawful = lawfulDelegation();
    expect(revalidateDelegationRecord(lawful, query)).toBeNull();
    expect(revalidateDelegationRecord({ ...lawful, delegateActorId: "other" }, query)).toBe("delegate_mismatch");
    expect(revalidateDelegationRecord({ ...lawful, tenantId: "t_other" }, query)).toBe("tenant_mismatch");
    expect(
      revalidateDelegationRecord({ ...lawful, subject: { ...CALLER, ownerId: "other_agent" } }, query),
    ).toBe("subject_mismatch");
    expect(
      revalidateDelegationRecord({ ...lawful, delegator: { ...CALLER, ownerId: "other_agent" } }, query),
    ).toBe("delegator_subject_mismatch");
    expect(revalidateDelegationRecord({ ...lawful, expiresAt: "2026-11-01T00:00:00.000Z" }, query)).toBe(
      "expired_or_unparsable",
    );
    expect(revalidateDelegationRecord({ ...lawful, expiresAt: "not-a-date" }, query)).toBe("expired_or_unparsable");
    expect(revalidateDelegationRecord({ ...lawful, revokedAt: "2026-11-26T00:00:00.000Z" }, query)).toBe("revoked");
    expect(revalidateDelegationRecord({ ...lawful, id: "" }, query)).toBe("missing_or_incomplete");
    expect(revalidateDelegationRecord({ ...lawful, expiresAt: "" }, query)).toBe("missing_or_incomplete");
    expect(revalidateDelegationRecord(null, query)).toBe("missing_or_incomplete");
  });

  it("denies a store that returns a mismatched or unparsable record even if getActiveDelegation is non-empty", async () => {
    const bindingQuery = createDenyByDefaultBindingQuery([liveBinding()]);
    const mismatchedStore = {
      async getActiveDelegation() {
        return lawfulDelegation({ delegateActorId: "someone_else" });
      },
    };
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "user_assistant",
          declaredCaller: CALLER,
          now: NOW,
        },
        ...serviceTrusted(principalActor, { bindingQuery, delegationStore: mismatchedStore }),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(DelegationDeniedError);
      const denied = err as DelegationDeniedError<import("./authorize.js").ExecutionAuthorizationDecision>;
      expect(denied.decision.reason).toBe("delegation_delegate_mismatch");
      return true;
    });

    const unparsableStore = {
      async getActiveDelegation() {
        return lawfulDelegation({ expiresAt: "not-a-date" });
      },
    };
    await expect(
      authorizeTrustedExecution({
        request: {
          tenantId: "t_1",
          subjectId: "agent_main",
          scope: SCOPE,
          dataPlaneId: DATA_PLANE,
          declaredActorUserId: "user_assistant",
          declaredCaller: CALLER,
          now: NOW,
        },
        ...serviceTrusted(principalActor, { bindingQuery, delegationStore: unparsableStore }),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(DelegationDeniedError);
      const denied = err as DelegationDeniedError<import("./authorize.js").ExecutionAuthorizationDecision>;
      expect(denied.decision.reason).toBe("delegation_expired_or_unparsable");
      return true;
    });
  });
});
