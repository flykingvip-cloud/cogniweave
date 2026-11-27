import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
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
    expect(lifeRes.canonicalCommitted).toBe(true);
    expect(lifeRes.derivedIndexesSynced).toBe(true);
    expect((await store.getJournal(lifeRes.journalId))?.status).toBe("COMPLETED");
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

      // Unbound / forged caller rejected fail-closed before job enqueue.
      await expect(
        runOptimizationJob({
          tenantId: "__local__",
          subjectId: "subj_1",
          scope: SCOPE,
          optimizationType: "consolidation",
          atoms: [a1, a2],
          executionContext: {
            actorUserId: "u_forged",
            tenantId: "__local__",
            scope: SCOPE,
            caller: { tenantId: "__local__", ownerType: "agent", ownerId: "forged_agent" },
            bindings: [binding],
            dataPlaneId: "dp_1",
          },
          jobStore,
          metadataStore,
        }),
      ).rejects.toThrow("unauthorized");

      const job = await runOptimizationJob({
        idempotencyKey: "explicit_key_1",
        tenantId: "__local__",
        subjectId: "subj_1",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1, a2],
        executionContext: {
          actorUserId: "u_1",
          tenantId: "__local__",
          scope: SCOPE,
          caller: CALLER,
          bindings: [binding],
          dataPlaneId: "dp_1",
        },
        jobStore,
        metadataStore,
        graphStore: new InMemoryGraphStore(),
        vectorStore: new InMemoryVectorStore(),
      });
      expect(job.status).toBe("completed");
      expect(job.result?.estimatedCanonicalClaimTokenDelta).toBeGreaterThan(0);

      // Reusing same explicit idempotencyKey with a mutated atom version must fail with IdempotencyConflictError!
      await expect(
        runOptimizationJob({
          idempotencyKey: "explicit_key_1",
          tenantId: "__local__",
          subjectId: "subj_1",
          scope: SCOPE,
          optimizationType: "consolidation",
          atoms: [a1, { ...a2, versioning: { version: 2 } }],
          executionContext: {
            actorUserId: "u_1",
            tenantId: "__local__",
            scope: SCOPE,
            caller: CALLER,
            bindings: [binding],
            dataPlaneId: "dp_1",
          },
          jobStore,
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
