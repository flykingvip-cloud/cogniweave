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
import { authorizeTrustedExecution } from "./authorize.js";
import { createMemoryDelegationAuthorizationStore, type DelegationAuthorization } from "./delegation.js";
import { createDenyByDefaultPrincipalProvider, type TrustedPrincipal } from "./principal.js";
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
        authorization: {
          environment: "service",
          principal: principalSelf,
        },
        bindingQuery: createDenyByDefaultBindingQuery([binding]),
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
        authorization: {
          environment: "service",
          principal: principalActor,
          // no delegationStore
        },
        bindingQuery: createDenyByDefaultBindingQuery([liveBinding()]),
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
        authorization: { environment: "service", principal: principalActor, delegationStore: expired },
        bindingQuery,
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
        authorization: { environment: "service", principal: principalActor, delegationStore: revoked },
        bindingQuery,
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
        authorization: { environment: "service", principal: principalActor, delegationStore: crossTenant },
        bindingQuery,
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
      authorization: {
        environment: "service",
        principal: principalActor,
        delegationStore: store,
      },
      bindingQuery: createDenyByDefaultBindingQuery([binding]),
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
        authorization: { environment: "service", principal: principalSelf },
        bindingQuery: createDenyByDefaultBindingQuery([]),
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
        authorization: { environment: "service", principal: principalSelf },
        bindingQuery,
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
        authorization: { environment: "service", principal: principalSelf },
        bindingQuery,
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
        authorization: { environment: "cloud", principalProvider: throwingProvider, bearerToken: "tok" },
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
        authorization: { environment: "service", principal: principalSelf },
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
        authorization: { environment: "service", principal: principalSelf },
        bindingQuery: throwingQuery,
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
      authorization: { environment: "service", principal: principalSelf },
      metadataStore,
    });
    expect(result.bindingId).toBe(binding.id);
    expect(result.decision.decision).toBe("allow");
  });
});
