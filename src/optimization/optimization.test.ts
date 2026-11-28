import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createAuthoritativeBindingQueryFromMetadataStore } from "../auth/authorize.js";
import { createMemoryDelegationAuthorizationStore } from "../auth/delegation.js";
import { createDenyByDefaultPrincipalProvider, type TrustedPrincipal } from "../auth/principal.js";
import { createTrustedRuntime } from "../auth/trusted-runtime.js";
import type { AuthoritativeBindingQuery } from "../auth/canonical-scope.js";
import type { DelegationAuthorizationStore } from "../auth/delegation.js";
import type { MetadataStore } from "../storage/types.js";
import {
  BindingStoreUnavailableError,
  DelegationDeniedError,
  DelegationStoreUnavailableError,
  PrincipalUnavailableError,
  SecurityOverrideRejectedError,
  UntrustedRuntimeError,
} from "../errors.js";
import { FileDurableJobStore } from "../jobs/durable-job-store.js";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type { CognitivePackage, MemoryAtom, MemorySubject, Scope, TaskFrame } from "../models.js";
import { InMemoryGraphStore, InMemoryMetadataStore, InMemoryVectorStore } from "../storage/in-memory.js";
import type { GraphStore, VectorStore } from "../storage/types.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import {
  abstractFromAtoms,
  applyConsolidation,
  applyLifecycleDecisions,
  buildContextPackage,
  computeOptimizationIdempotencyKey,
  consolidateAtoms,
  evaluateAdmission,
  evaluateLifecycle,
  optimizeRetrieval,
  runOptimizationJob,
} from "./index.js";

const SCOPE: Scope = {
  workspaceId: "ws_1",
  projectId: "proj_1",
  agentId: "agent_main",
  visibility: "private",
};

const OTHER_AGENT_SCOPE: Scope = {
  workspaceId: "ws_1",
  projectId: "proj_1",
  agentId: "agent_other",
  visibility: "private",
};

const PARTITION = createMemoryPartitionKeyV1("dp_1", SCOPE);
const CALLER: MemorySubject = { tenantId: "__local__", ownerType: "agent", ownerId: "agent_main" };
const SELF_PRINCIPAL: TrustedPrincipal = {
  tenantId: "__local__",
  userId: "agent_main",
  subject: CALLER,
  tokenId: "tok_agent_main",
};

const TEST_TOKEN = "tok";

function serviceJobAuth(
  principal: TrustedPrincipal,
  extras: {
    bindingQuery?: AuthoritativeBindingQuery;
    delegationStore?: DelegationAuthorizationStore;
    metadataStore?: MetadataStore;
  } = {},
) {
  const bindingQuery =
    extras.bindingQuery ??
    (extras.metadataStore
      ? createAuthoritativeBindingQueryFromMetadataStore(extras.metadataStore)
      : undefined);
  return {
    runtime: createTrustedRuntime({
      environment: "service",
      principalProvider: createDenyByDefaultPrincipalProvider([{ token: TEST_TOKEN, principal }]),
      ...(bindingQuery ? { bindingQuery } : {}),
      ...(extras.delegationStore ? { delegationStore: extras.delegationStore } : {}),
    }),
    authorization: { bearerToken: TEST_TOKEN },
    ...(extras.metadataStore ? { metadataStore: extras.metadataStore } : {}),
  };
}


function makeAtom(overrides: Partial<MemoryAtom> & { id: string }): MemoryAtom {
  return {
    id: overrides.id,
    atomType: overrides.atomType ?? "strategy",
    scope: overrides.scope ?? SCOPE,
    claim: overrides.claim ?? {
      type: "procedural",
      statement: "Always verify forward-only ancestry before production cutover.",
    },
    trigger: overrides.trigger ?? {
      conditions: ["production_cutover"],
      contextTags: ["release"],
    },
    applicability: overrides.applicability ?? { include: ["prod"], exclude: [] },
    provenance: overrides.provenance ?? {
      sourceEventIds: ["evt_1"],
      evidenceRefs: ["evd_1"],
    },
    versioning: overrides.versioning ?? { version: 1 },
    state: overrides.state ?? { status: "active", conflictsWith: [] },
    metrics: overrides.metrics ?? { confidence: 0.85, reuseCount: 3 },
    dedupKey: overrides.dedupKey,
    privacy: overrides.privacy,
    lifecycle: overrides.lifecycle,
    governance: overrides.governance,
  };
}

describe("Memory Optimization Engine (CW-04J)", () => {
  it("CW-04B-R2/MOP-01: isolates admission duplicate & conflict checks by scope", () => {
    const otherAgentExisting = makeAtom({
      id: "atm_other",
      scope: OTHER_AGENT_SCOPE,
      claim: {
        type: "procedural",
        statement: "Never verify forward-only ancestry before production cutover.",
      },
    });
    const newAtom = makeAtom({ id: "atm_new" });
    const res = evaluateAdmission({ atom: newAtom, existingAtoms: [otherAgentExisting] });
    expect(res.disposition).toBe("accepted");
    expect(res.conflictAtomIds).toEqual([]);
  });

  it("CW-04B-R1/MOP-05: rejects caller with Binding A trying to retrieve Scope B atoms via TaskFrame B", () => {
    const bindingForScopeA = createMemorySubjectBinding({
      partition: PARTITION,
      scope: SCOPE,
      subject: CALLER,
    });
    const scopeAAtom = makeAtom({ id: "atm_a", scope: SCOPE });
    const scopeBAtom = makeAtom({ id: "atm_b", scope: OTHER_AGENT_SCOPE });
    const taskFramePointingToB: TaskFrame = {
      id: "tf_b",
      scope: OTHER_AGENT_SCOPE,
      taskType: "operations",
      goals: ["release"],
      problems: [],
      scenarioTags: ["release"],
      constraints: [],
      entities: [],
      requiredAtomTypes: ["strategy"],
    };

    const res = optimizeRetrieval({
      taskFrame: taskFramePointingToB,
      candidates: [scopeAAtom, scopeBAtom],
      auth: { caller: CALLER, bindings: [bindingForScopeA], dataPlaneId: "dp_1" },
    });

    expect(res.selectedAtoms).toEqual([]);
    expect(res.excludedCandidates).toEqual(
      expect.arrayContaining([
        { atomId: "atm_b", reason: "unauthorized" },
        { atomId: "atm_a", reason: "scope_mismatch" },
      ]),
    );
  });

  it("CW-04C-R1/MOP-03: rejects single atom with 2 sourceEventIds and 2 atoms sharing same sourceEventIds", () => {
    const a1 = makeAtom({
      id: "atm_1",
      provenance: { sourceEventIds: ["evt_1", "evt_2"], evidenceRefs: ["evd_1"] },
    });
    const a2 = makeAtom({
      id: "atm_2",
      provenance: { sourceEventIds: ["evt_1", "evt_2"], evidenceRefs: ["evd_2"] },
    });
    expect(abstractFromAtoms({ atoms: [a1, a2] })).toBeNull();
  });

  it("CW-04J-04/MOP-06: preserves original answer.summary and answer.recommendations while enforcing serialized budget", () => {
    const policy = makeAtom({
      id: "atm_pol",
      atomType: "policy",
      claim: { type: "policy", statement: "Never force-push main." },
      provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_pol"] },
    });
    const pkg: CognitivePackage = {
      packageId: "pkg_1",
      taskFrameId: "tf_1",
      answer: {
        summary: "Original business summary",
        recommendations: ["Original recommendation 1"],
        nextSteps: ["step1"],
      },
      why: { summary: "matched", matchedPatterns: [] },
      supportingAtoms: ["atm_pol"],
      reasoningPath: [],
      confidence: 0.9,
      risks: ["risk1"],
      constraints: ["no_force_push"],
      conflicts: [],
      evidenceRefs: ["evd_pol"],
    };

    const fits = buildContextPackage({ pkg, atoms: [policy], budgetTokens: 500 });
    expect(fits.budgetStatus).toBe("within_budget");
    expect(fits.budgetedPackage.answer.summary).toBe("Original business summary");
    expect(fits.budgetedPackage.answer.recommendations).toEqual(["Original recommendation 1"]);
    expect(fits.atomContextNotes).toEqual(["Never force-push main."]);

    const tiny = buildContextPackage({ pkg, atoms: [policy], budgetTokens: 10 });
    expect(tiny.budgetStatus).toBe("unsatisfied_budget");
    expect(tiny.budgetUtilization).toBeGreaterThan(1);
  });

  it("CW-04J-02 & CW-04J-03: marks DERIVED_OUT_OF_SYNC when delete() is missing on stores and journals Lifecycle writes", async () => {
    const store = new InMemoryMetadataStore();
    const a1 = makeAtom({ id: "atm_1", dedupKey: "k1" });
    const a2 = makeAtom({ id: "atm_2", dedupKey: "k1" });
    await store.saveAtom(a1);
    await store.saveAtom(a2);

    const storeWithoutDelete = {
      syncFromDistillation: async () => ({ nodeCount: 0, edgeCount: 0 }),
      rebuildFromBundle: async () => ({ nodeCount: 0, edgeCount: 0 }),
    } as GraphStore;
    const vectorWithoutDelete = {
      syncFromDistillation: async () => ({ documentCount: 0 }),
      rebuildFromBundle: async () => ({ documentCount: 0 }),
    } as VectorStore;

    const plan = consolidateAtoms([a1, a2]);
    const res = await applyConsolidation({
      plan,
      metadataStore: store,
      graphStore: storeWithoutDelete,
      vectorStore: vectorWithoutDelete,
    });
    expect(res.canonicalCommitted).toBe(true);
    expect(res.canonicalCommitStatus).toBe("COMMITTED");
    expect(res.derivedIndexesSynced).toBe(false);
    expect(res.derivedSyncError).toBe("derived_store_delete_unsupported");
    expect((await store.getJournal(res.journalId))?.status).toBe("DERIVED_OUT_OF_SYNC");

    const tombAtom = makeAtom({
      id: "atm_tomb",
      lifecycle: { tombstonedAt: "2026-11-26T00:00:00Z" },
    });
    await store.saveAtom(tombAtom);
    const lifeRes = await applyLifecycleDecisions({
      evaluations: [evaluateLifecycle(tombAtom, { nowMs: Date.parse("2026-11-27T00:00:00Z") })],
      metadataStore: store,
      graphStore: new InMemoryGraphStore(),
      vectorStore: new InMemoryVectorStore(),
    });
    expect(lifeRes.canonicalCommitStatus).toBe("COMMITTED");
    expect(lifeRes.derivedIndexesSynced).toBe(true);
    expect((await store.getJournal(lifeRes.journalId))?.status).toBe("COMPLETED");

    // CW-08-05: MetadataStore without withTransaction must report PARTIAL_COMMIT
    const noTxStore = Object.assign(
      Object.create(Object.getPrototypeOf(store)),
      store,
      { withTransaction: undefined },
    ) as typeof store;
    const b1 = makeAtom({ id: "atm_b1", dedupKey: "k_notx" });
    const b2 = makeAtom({ id: "atm_b2", dedupKey: "k_notx" });
    await noTxStore.saveAtom(b1);
    await noTxStore.saveAtom(b2);
    const noTxConsRes = await applyConsolidation({
      plan: consolidateAtoms([b1, b2]),
      metadataStore: noTxStore,
      graphStore: new InMemoryGraphStore(),
      vectorStore: new InMemoryVectorStore(),
    });
    expect(noTxConsRes.canonicalCommitted).toBe(false);
    expect(noTxConsRes.canonicalCommitStatus).toBe("PARTIAL_COMMIT");
    expect((await noTxStore.getJournal(noTxConsRes.journalId))?.status).toBe("DERIVED_OUT_OF_SYNC");

    const tombNoTx = makeAtom({
      id: "atm_tomb_notx",
      lifecycle: { tombstonedAt: "2026-11-26T00:00:00Z" },
    });
    await noTxStore.saveAtom(tombNoTx);
    const noTxLifeRes = await applyLifecycleDecisions({
      evaluations: [evaluateLifecycle(tombNoTx, { nowMs: Date.parse("2026-11-27T00:00:00Z") })],
      metadataStore: noTxStore,
      graphStore: new InMemoryGraphStore(),
      vectorStore: new InMemoryVectorStore(),
    });
    expect(noTxLifeRes.canonicalCommitStatus).toBe("PARTIAL_COMMIT");
    expect((await noTxStore.getJournal(noTxLifeRes.journalId))?.status).toBe("DERIVED_OUT_OF_SYNC");
  });

  it("CW-04J-01 & CW-04J-05: requires authorized executionContext, rejects explicit idempotencyKey payload conflicts, and reports estimatedCanonicalClaimTokenDelta", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cw-opt-job-"));
    try {
      const jobStore = new FileDurableJobStore(join(dir, "jobs.json"));
      const metadataStore = new InMemoryMetadataStore();
      const a1 = makeAtom({ id: "atm_1", dedupKey: "k1" });
      const a2 = makeAtom({ id: "atm_2", dedupKey: "k1" });
      await metadataStore.saveAtom(a1);
      await metadataStore.saveAtom(a2);

      const binding = createMemorySubjectBinding({
        partition: PARTITION,
        scope: SCOPE,
        subject: CALLER,
      });
      await metadataStore.saveMemorySubjectBinding(binding);

      // CW-08-02 / CW-09-02: Forged actorUserId without a matching principal is rejected fail-closed
      await expect(
        runOptimizationJob({
          tenantId: "__local__",
          subjectId: "agent_main",
          scope: SCOPE,
          optimizationType: "consolidation",
          atoms: [a1, a2],
          executionContext: {
            actorUserId: "u_forged",
            tenantId: "__local__",
            scope: SCOPE,
            caller: CALLER,
            dataPlaneId: "dp_1",
          },
          ...serviceJobAuth(SELF_PRINCIPAL, { metadataStore }),
          jobStore,
          metadataStore,
        }),
      ).rejects.toBeInstanceOf(DelegationDeniedError);

      const job = await runOptimizationJob({
        idempotencyKey: "explicit_key_1",
        tenantId: "__local__",
        subjectId: "agent_main",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1, a2],
        executionContext: {
          actorUserId: "agent_main",
          tenantId: "__local__",
          scope: SCOPE,
          caller: CALLER,
          dataPlaneId: "dp_1",
        },
        ...serviceJobAuth(SELF_PRINCIPAL, { metadataStore }),
        jobStore,
        metadataStore,
        graphStore: new InMemoryGraphStore(),
        vectorStore: new InMemoryVectorStore(),
      });
      expect(job.status).toBe("completed");
      expect(job.result?.estimatedCanonicalClaimTokenDelta).toBeGreaterThan(0);
      expect(job.authorization?.decision).toBe("allow");
      expect(job.authorization?.actor.userId).toBe("agent_main");
      expect(job.authorization?.bindingId).toBe(binding.id);

      // Reusing same explicit idempotencyKey with a mutated atom version must fail with IdempotencyConflictError!
      // Caller-submitted bindings are ignored; the metadata store remains the binding authority.
      await expect(
        runOptimizationJob({
          idempotencyKey: "explicit_key_1",
          tenantId: "__local__",
          subjectId: "agent_main",
          scope: SCOPE,
          optimizationType: "consolidation",
          atoms: [a1, { ...a2, versioning: { version: 2 } }],
          executionContext: {
            actorUserId: "agent_main",
            tenantId: "__local__",
            scope: SCOPE,
            caller: CALLER,
            bindings: [binding],
            dataPlaneId: "dp_1",
          },
          ...serviceJobAuth(SELF_PRINCIPAL, { metadataStore }),
          jobStore,
          metadataStore,
        }),
      ).rejects.toThrow("different payload");

      expect(
        computeOptimizationIdempotencyKey({
          tenantId: "__local__",
          scope: SCOPE,
          optimizationType: "consolidation",
          atoms: [a1, a2],
          policyVersion: "1.0.0",
          pipelineVersion: "1.0.0",
        }),
      ).toHaveLength(32);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("CW-09-02 runOptimizationJob trusted identity (unit)", () => {
  async function setup() {
    const metadataStore = new InMemoryMetadataStore();
    const a1 = makeAtom({ id: "atm_1", dedupKey: "k1" });
    const a2 = makeAtom({ id: "atm_2", dedupKey: "k1" });
    await metadataStore.saveAtom(a1);
    await metadataStore.saveAtom(a2);
    const binding = createMemorySubjectBinding({
      partition: PARTITION,
      scope: SCOPE,
      subject: CALLER,
    });
    await metadataStore.saveMemorySubjectBinding(binding);
    return { metadataStore, a1, a2, binding };
  }

  it("denies forged delegation claimed only through delegatedActorFor", async () => {
    const { metadataStore, a1, a2 } = await setup();
    const actorPrincipal: TrustedPrincipal = {
      tenantId: "__local__",
      userId: "user_assistant",
      subject: { tenantId: "__local__", ownerType: "user", ownerId: "user_assistant" },
    };
    await expect(
      runOptimizationJob({
        tenantId: "__local__",
        subjectId: "agent_main",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1, a2],
        executionContext: {
          actorUserId: "user_assistant",
          tenantId: "__local__",
          scope: SCOPE,
          caller: CALLER,
          delegatedActorFor: ["agent_main"],
          dataPlaneId: "dp_1",
        },
        ...serviceJobAuth(actorPrincipal, { metadataStore }),
        metadataStore,
      }),
    ).rejects.toBeInstanceOf(DelegationStoreUnavailableError);
  });

  it("allows a lawful delegation record and records the audit decision on the job", async () => {
    const { metadataStore, a1, a2, binding } = await setup();
    const actorPrincipal: TrustedPrincipal = {
      tenantId: "__local__",
      userId: "user_assistant",
      subject: { tenantId: "__local__", ownerType: "user", ownerId: "user_assistant" },
      tokenId: "tok_assistant",
    };
    const delegationStore = createMemoryDelegationAuthorizationStore([
      {
        id: "del_job_1",
        tenantId: "__local__",
        delegator: CALLER,
        delegateActorId: "user_assistant",
        subject: CALLER,
        scope: SCOPE,
        grantedAt: "2026-11-01T00:00:00.000Z",
        expiresAt: "2026-12-31T00:00:00.000Z",
      },
    ]);
    const job = await runOptimizationJob({
      tenantId: "__local__",
      subjectId: "agent_main",
      scope: SCOPE,
      optimizationType: "consolidation",
      atoms: [a1, a2],
      executionContext: {
        actorUserId: "user_assistant",
        tenantId: "__local__",
        scope: SCOPE,
        caller: CALLER,
        delegatedActorFor: ["not-evidence"],
        bindings: [],
        dataPlaneId: "dp_1",
      },
      ...serviceJobAuth(actorPrincipal, { metadataStore, delegationStore }),
      metadataStore,
      graphStore: new InMemoryGraphStore(),
      vectorStore: new InMemoryVectorStore(),
    });
    expect(job.status).toBe("completed");
    expect(job.authorization).toMatchObject({
      actor: { userId: "user_assistant" },
      delegator: CALLER,
      caller: CALLER,
      subject: { tenantId: "__local__", ownerType: "agent", ownerId: "agent_main" },
      bindingId: binding.id,
      tenantId: "__local__",
      decision: "allow",
      delegationId: "del_job_1",
      principalTokenId: "tok_assistant",
    });
    expect(job.authorization?.traceId).toBeTruthy();
  });

  it("ignores forged ctx.bindings when the authoritative store has no live binding", async () => {
    const metadataStore = new InMemoryMetadataStore();
    const a1 = makeAtom({ id: "atm_1", dedupKey: "k1" });
    await metadataStore.saveAtom(a1);
    const forged = createMemorySubjectBinding({
      partition: PARTITION,
      scope: SCOPE,
      subject: CALLER,
    });
    await expect(
      runOptimizationJob({
        tenantId: "__local__",
        subjectId: "agent_main",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1],
        executionContext: {
          actorUserId: "agent_main",
          tenantId: "__local__",
          scope: SCOPE,
          caller: CALLER,
          bindings: [forged],
          dataPlaneId: "dp_1",
        },
        ...serviceJobAuth(SELF_PRINCIPAL, { metadataStore }),
        metadataStore,
      }),
    ).rejects.toBeInstanceOf(DelegationDeniedError);
  });

  it("denies production execution when the principal or binding store is unavailable", async () => {
    const a1 = makeAtom({ id: "atm_1", dedupKey: "k1" });
    await expect(
      runOptimizationJob({
        tenantId: "__local__",
        subjectId: "agent_main",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1],
        executionContext: {
          actorUserId: "agent_main",
          tenantId: "__local__",
          scope: SCOPE,
          caller: CALLER,
          dataPlaneId: "dp_1",
        },
        runtime: createTrustedRuntime({ environment: "cloud" }),
        authorization: { bearerToken: TEST_TOKEN },
      }),
    ).rejects.toBeInstanceOf(PrincipalUnavailableError);

    const storeWithoutBindings = {} as InMemoryMetadataStore;
    await expect(
      runOptimizationJob({
        tenantId: "__local__",
        subjectId: "agent_main",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1],
        executionContext: {
          actorUserId: "agent_main",
          tenantId: "__local__",
          scope: SCOPE,
          caller: CALLER,
          bindings: [
            createMemorySubjectBinding({
              partition: PARTITION,
              scope: SCOPE,
              subject: CALLER,
            }),
          ],
          dataPlaneId: "dp_1",
        },
        ...serviceJobAuth(SELF_PRINCIPAL, { metadataStore: storeWithoutBindings }),
        metadataStore: storeWithoutBindings,
      }),
    ).rejects.toBeInstanceOf(BindingStoreUnavailableError);
  });
});

describe("CW-09-02-R1 runOptimizationJob production injection (unit)", () => {
  it("denies a self-declared principal and a forged Binding Query in service/cloud", async () => {
    const a1 = makeAtom({ id: "atm_1", dedupKey: "k1" });
    await expect(
      runOptimizationJob({
        tenantId: "__local__",
        subjectId: "agent_main",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1],
        executionContext: {
          actorUserId: "agent_main",
          tenantId: "__local__",
          scope: SCOPE,
          caller: CALLER,
          dataPlaneId: "dp_1",
        },
        runtime: createTrustedRuntime({ environment: "service" }),
        authorization: {
          principal: SELF_PRINCIPAL,
        } as never,
      }),
    ).rejects.toBeInstanceOf(SecurityOverrideRejectedError);

    const forgedStore = new InMemoryMetadataStore();
    await forgedStore.saveMemorySubjectBinding(
      createMemorySubjectBinding({
        partition: PARTITION,
        scope: SCOPE,
        subject: CALLER,
      }),
    );
    await expect(
      runOptimizationJob({
        tenantId: "__local__",
        subjectId: "agent_main",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1],
        executionContext: {
          actorUserId: "agent_main",
          tenantId: "__local__",
          scope: SCOPE,
          caller: CALLER,
          dataPlaneId: "dp_1",
        },
        runtime: createTrustedRuntime({
          environment: "cloud",
          principalProvider: createDenyByDefaultPrincipalProvider([
            { token: TEST_TOKEN, principal: SELF_PRINCIPAL },
          ]),
        }),
        authorization: {
          bearerToken: TEST_TOKEN,
          bindingQuery: {
            async listLiveBindings() {
              return forgedStore.listMemorySubjectBindings!({ liveOnly: true });
            },
          },
        } as never,
        metadataStore: forgedStore,
      }),
    ).rejects.toBeInstanceOf(SecurityOverrideRejectedError);
  });
});
