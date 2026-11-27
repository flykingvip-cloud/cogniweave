import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FileDurableJobStore } from "../jobs/durable-job-store.js";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type { CognitivePackage, MemoryAtom, MemorySubject, Scope, TaskFrame } from "../models.js";
import { InMemoryGraphStore, InMemoryMetadataStore, InMemoryVectorStore } from "../storage/in-memory.js";
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

describe("Memory Optimization Engine (CW-04B-R1..CW-04H-R1)", () => {
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
    // Cross-agent contradicting claim must NOT trigger conflict or duplicate in agent_main.
    const res = evaluateAdmission({ atom: newAtom, existingAtoms: [otherAgentExisting] });
    expect(res.disposition).toBe("accepted");
    expect(res.conflictAtomIds).toEqual([]);
  });

  it("CW-04B-R1/MOP-05: rejects caller with Binding A trying to retrieve Scope B atoms via TaskFrame B", () => {
    const caller: MemorySubject = { tenantId: "__local__", ownerType: "agent", ownerId: "agent_main" };
    const bindingForScopeA = createMemorySubjectBinding({
      partition: PARTITION,
      scope: SCOPE,
      subject: caller,
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
      auth: { caller, bindings: [bindingForScopeA], dataPlaneId: "dp_1" },
    });

    // scopeBAtom fails per-atom binding check (unauthorized); scopeAAtom fails taskFrame scope_mismatch.
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

    const ind1 = makeAtom({
      id: "atm_i1",
      atomType: "failure_pattern",
      claim: { type: "causal", statement: "Connection pool exhaustion causes timeout." },
      applicability: { include: ["prod", "us-east"], exclude: ["canary"] },
      provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_1"] },
    });
    const ind2 = makeAtom({
      id: "atm_i2",
      atomType: "failure_pattern",
      claim: { type: "causal", statement: "Small connection pool causes timeout." },
      applicability: { include: ["prod", "eu-west"], exclude: ["local"] },
      provenance: { sourceEventIds: ["evt_2"], evidenceRefs: ["evd_2"] },
    });
    const abs = abstractFromAtoms({ atoms: [ind1, ind2] });
    expect(abs).not.toBeNull();
    expect(abs?.requiresReview).toBe(true);
    expect(abs?.applicability.include).toEqual(["prod"]);
  });

  it("CW-04D-R1/MOP-06: enforces hard serialized CognitivePackage budget and reports unsatisfied_budget without clamping >1 utilization", () => {
    const policy = makeAtom({
      id: "atm_pol",
      atomType: "policy",
      claim: { type: "policy", statement: "Never force-push main." },
      provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_pol"] },
    });
    const pkg: CognitivePackage = {
      packageId: "pkg_1",
      taskFrameId: "tf_1",
      answer: { summary: "summary", recommendations: [], nextSteps: ["step1"] },
      why: { summary: "matched", matchedPatterns: [] },
      supportingAtoms: ["atm_pol"],
      reasoningPath: [],
      confidence: 0.9,
      risks: ["risk1"],
      constraints: ["A_VERY_LONG_CONSTRAINT_EXCEEDING_TINY_BUDGET"],
      conflicts: [],
      evidenceRefs: ["evd_pol"],
    };

    const unsatisfied = buildContextPackage({ pkg, atoms: [policy], budgetTokens: 10 });
    expect(unsatisfied.budgetStatus).toBe("unsatisfied_budget");
    expect(unsatisfied.budgetUtilization).toBeGreaterThan(1);

    const fits = buildContextPackage({ pkg, atoms: [policy], budgetTokens: 500 });
    expect(fits.budgetStatus).toBe("within_budget");
    expect(fits.tokenEstimate).toBeLessThanOrEqual(500);
    expect(fits.evidenceCompleteness).toBeLessThanOrEqual(1);
  });

  it("CW-04E-R1 & CW-04F-R1: records journal & reports derivedIndexesSynced=false when derived stores are missing or fail; executes tombstone & revalidate", async () => {
    const store = new InMemoryMetadataStore();
    const a1 = makeAtom({ id: "atm_1", dedupKey: "k1" });
    const a2 = makeAtom({ id: "atm_2", dedupKey: "k1" });
    await store.saveAtom(a1);
    await store.saveAtom(a2);

    const plan = consolidateAtoms([a1, a2]);
    // Missing graphStore/vectorStore -> canonicalCommitted=true, derivedIndexesSynced=false
    const noDerived = await applyConsolidation({ plan, metadataStore: store });
    expect(noDerived.canonicalCommitted).toBe(true);
    expect(noDerived.derivedIndexesSynced).toBe(false);
    expect((await store.getJournal(noDerived.journalId))?.status).toBe("DERIVED_OUT_OF_SYNC");

    // Failing graphStore -> derivedIndexesSynced=false with error
    const failingGraph = new InMemoryGraphStore();
    failingGraph.delete = async () => {
      throw new Error("neo4j_down");
    };
    await store.saveAtom(a2); // restore active for retry
    const failedDerived = await applyConsolidation({
      plan,
      metadataStore: store,
      graphStore: failingGraph,
      vectorStore: new InMemoryVectorStore(),
    });
    expect(failedDerived.derivedIndexesSynced).toBe(false);
    expect(failedDerived.derivedSyncError).toBe("neo4j_down");

    // Lifecycle executes tombstone and revalidate
    const tombAtom = makeAtom({
      id: "atm_tomb",
      lifecycle: { tombstonedAt: "2026-11-26T00:00:00Z" },
    });
    const noDateAtom = makeAtom({ id: "atm_reval" });
    await store.saveAtom(tombAtom);
    await store.saveAtom(noDateAtom);

    const evals = [
      evaluateLifecycle(tombAtom, { nowMs: Date.parse("2026-11-27T00:00:00Z") }),
      evaluateLifecycle(noDateAtom),
    ];
    const lifeRes = await applyLifecycleDecisions({
      evaluations: evals,
      metadataStore: store,
      graphStore: new InMemoryGraphStore(),
      vectorStore: new InMemoryVectorStore(),
    });
    expect(lifeRes.tombstonedIds).toEqual(["atm_tomb"]);
    expect(lifeRes.revalidatedIds).toEqual(["atm_reval"]);
    expect((await store.getAtom("atm_reval"))?.state.status).toBe("tentative");
  });

  it("CW-04G-R1 & CW-04G-R2: rejects cross-scope job inputs, invalidates idempotencyKey on version change, and measures real Canonical Store delta", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cw-opt-job-"));
    try {
      const jobStore = new FileDurableJobStore(join(dir, "jobs.json"));
      const metadataStore = new InMemoryMetadataStore();
      const a1 = makeAtom({ id: "atm_1", dedupKey: "k1" });
      const a2 = makeAtom({ id: "atm_2", dedupKey: "k1" });
      const crossScope = makeAtom({ id: "atm_cross", scope: OTHER_AGENT_SCOPE });
      await metadataStore.saveAtom(a1);
      await metadataStore.saveAtom(a2);

      // P0-02: Cross-scope atom rejected at job entry
      await expect(
        runOptimizationJob({
          tenantId: "t_1",
          subjectId: "subj_1",
          scope: SCOPE,
          optimizationType: "consolidation",
          atoms: [a1, crossScope],
          jobStore,
          metadataStore,
        }),
      ).rejects.toThrow("different scope");

      const keyV1 = computeOptimizationIdempotencyKey({
        tenantId: "t_1",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1, a2],
        policyVersion: "1.0.0",
        pipelineVersion: "1.0.0",
      });
      const keyV2 = computeOptimizationIdempotencyKey({
        tenantId: "t_1",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1, { ...a2, versioning: { version: 2 } }],
        policyVersion: "1.0.0",
        pipelineVersion: "1.0.0",
      });
      expect(keyV1).not.toBe(keyV2);

      const job = await runOptimizationJob({
        tenantId: "t_1",
        subjectId: "subj_1",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1, a2],
        executionContext: { actorUserId: "u_1", tenantId: "t_1", scope: SCOPE },
        jobStore,
        metadataStore,
        graphStore: new InMemoryGraphStore(),
        vectorStore: new InMemoryVectorStore(),
      });
      expect(job.status).toBe("completed");
      expect(job.result?.canonicalTokensBefore).toBeGreaterThan(0);
      expect(job.result?.canonicalTokensAfter).toBeLessThan(job.result!.canonicalTokensBefore!);
      expect(job.result?.verifiedCanonicalTokenDelta).toBe(
        job.result!.canonicalTokensBefore! - job.result!.canonicalTokensAfter!,
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
