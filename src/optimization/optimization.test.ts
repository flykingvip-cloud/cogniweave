import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FileDurableJobStore } from "../jobs/durable-job-store.js";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type { CognitivePackage, MemoryAtom, MemorySubject, Scope, TaskFrame } from "../models.js";
import { InMemoryMetadataStore } from "../storage/in-memory.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import {
  abstractFromAtoms,
  applyConsolidation,
  buildContextPackage,
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

describe("Memory Optimization Engine (CW-04B..04H)", () => {
  it("CW-04B/MOP-01: catches duplicates with differing dedupKeys, enforces authority tiers, and detects polarity conflicts", () => {
    const existing = makeAtom({ id: "atm_0", dedupKey: "key_A" });
    const diffKeySameClaim = makeAtom({ id: "atm_1", dedupKey: "key_B" });
    expect(evaluateAdmission({ atom: diffKeySameClaim, existingAtoms: [existing] }).disposition).toBe(
      "rejected",
    );

    const lowAuth = makeAtom({
      id: "atm_low",
      claim: { type: "heuristic", statement: "Cache warmups reduce cold-start tail latency." },
      metrics: { confidence: 0.4, reuseCount: 0 },
    });
    expect(evaluateAdmission({ atom: lowAuth, sourceAuthority: "low" }).disposition).toBe("tentative");
    expect(evaluateAdmission({ atom: lowAuth, sourceAuthority: "authoritative" }).disposition).toBe(
      "accepted",
    );

    const contradicting = makeAtom({
      id: "atm_contra",
      claim: {
        type: "procedural",
        statement: "Never verify forward-only ancestry before production cutover.",
      },
    });
    const contraResult = evaluateAdmission({ atom: contradicting, existingAtoms: [existing] });
    expect(contraResult.disposition).toBe("pending_review");
    expect(contraResult.conflictAtomIds).toContain("atm_0");
  });

  it("CW-04B/MOP-02: never merges across different scopes, excludes deprecated/tombstoned, and applies canonical write-back", async () => {
    const a1 = makeAtom({
      id: "atm_1",
      provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_1"] },
    });
    const a2 = makeAtom({
      id: "atm_2",
      provenance: { sourceEventIds: ["evt_2"], evidenceRefs: ["evd_2"] },
    });
    const otherAgent = makeAtom({
      id: "atm_other",
      scope: OTHER_AGENT_SCOPE,
      provenance: { sourceEventIds: ["evt_3"], evidenceRefs: ["evd_3"] },
    });
    const deprecated = makeAtom({
      id: "atm_dep",
      state: { status: "deprecated", conflictsWith: [] },
    });

    const plan = consolidateAtoms([a1, a2, otherAgent, deprecated]);
    expect(plan.excludedInactiveIds).toEqual(["atm_dep"]);
    expect(plan.mergedCount).toBe(1);
    const cluster1 = plan.clusters.find((c) => c.canonicalAtomId === "atm_1");
    expect(cluster1?.sourceAtomIds).toEqual(["atm_1", "atm_2"]);
    expect(plan.clusters.some((c) => c.canonicalAtomId === "atm_other")).toBe(true);

    const store = new InMemoryMetadataStore();
    await store.saveAtom(a1);
    await store.saveAtom(a2);
    const applied = await applyConsolidation({ plan, metadataStore: store });
    expect(applied.updatedCanonicalIds).toEqual(["atm_1"]);
    expect(applied.deprecatedSourceIds).toEqual(["atm_2"]);
    expect((await store.getAtom("atm_1"))?.provenance.evidenceRefs).toEqual(["evd_1", "evd_2"]);
    expect((await store.getAtom("atm_2"))?.state.status).toBe("deprecated");
  });

  it("CW-04C/MOP-03: enforces independent source events, intersects applicability.include, and extracts shared invariant terms", () => {
    const sameEvent1 = makeAtom({
      id: "atm_s1",
      provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_1"] },
    });
    const sameEvent2 = makeAtom({
      id: "atm_s2",
      provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_2"] },
    });
    // Single source event is NOT independent -> returns null.
    expect(abstractFromAtoms({ atoms: [sameEvent1, sameEvent2] })).toBeNull();

    const ind1 = makeAtom({
      id: "atm_i1",
      atomType: "failure_pattern",
      claim: { type: "causal", statement: "Database connection pool exhaustion causes timeout." },
      applicability: { include: ["prod", "us-east"], exclude: ["canary"] },
      provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_1"] },
    });
    const ind2 = makeAtom({
      id: "atm_i2",
      atomType: "failure_pattern",
      claim: { type: "causal", statement: "Small connection pool configuration causes timeout." },
      applicability: { include: ["prod", "eu-west"], exclude: ["local"] },
      provenance: { sourceEventIds: ["evt_2"], evidenceRefs: ["evd_2"] },
    });
    const abstracted = abstractFromAtoms({ atoms: [ind1, ind2] });
    expect(abstracted).not.toBeNull();
    expect(abstracted?.commonTokens).toEqual(expect.arrayContaining(["connection", "pool", "causes", "timeout"]));
    // Applicability intersected (not expanded by union!).
    expect(abstracted?.applicability.include).toEqual(["prod"]);
    expect(abstracted?.knownExceptions).toEqual(expect.arrayContaining(["canary", "local"]));
  });

  it("CW-04F/MOP-04: handles missing/invalid dates, triggers purge after grace period, and protects legal_hold", () => {
    const missingDate = makeAtom({ id: "atm_nodate" });
    expect(evaluateLifecycle(missingDate).action).toBe("revalidate");

    const invalidDate = makeAtom({
      id: "atm_baddate",
      lifecycle: { admittedAt: "not-a-date" },
    });
    expect(evaluateLifecycle(invalidDate).action).toBe("revalidate");
    expect(evaluateLifecycle(invalidDate).retrievable).toBe(false);

    const expiredDep = makeAtom({
      id: "atm_purge",
      state: { status: "deprecated", conflictsWith: [] },
      lifecycle: { deprecatedAt: "2025-01-01T00:00:00Z" },
    });
    expect(
      evaluateLifecycle(expiredDep, { nowMs: Date.parse("2025-06-01T00:00:00Z") }).action,
    ).toBe("purge");

    const legal = makeAtom({
      id: "atm_legal",
      lifecycle: { retentionClass: "legal_hold", admittedAt: "2020-01-01T00:00:00Z" },
    });
    expect(evaluateLifecycle(legal).action).toBe("keep_active");
  });

  it("CW-04B/D/MOP-05 & MOP-06: requires auth/preAuthorized, builds trimmed CognitivePackage, and clamps evidenceCompleteness <= 1", () => {
    const taskFrame: TaskFrame = {
      id: "tf_1",
      scope: SCOPE,
      taskType: "operations",
      goals: ["safe release"],
      problems: [],
      scenarioTags: ["release"],
      constraints: ["no_force_push"],
      entities: [],
      requiredAtomTypes: ["policy"],
    };
    const policy = makeAtom({
      id: "atm_pol",
      atomType: "policy",
      claim: { type: "policy", statement: "Never force-push main." },
      provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_pol", "evd_extra"] },
    });

    // Fail-closed when neither auth nor preAuthorized is supplied.
    const denied = optimizeRetrieval({ taskFrame, candidates: [policy] });
    expect(denied.trace.authorizedBy).toBe("denied");
    expect(denied.selectedAtoms).toEqual([]);

    const caller: MemorySubject = { tenantId: "__local__", ownerType: "agent", ownerId: "agent_main" };
    const binding = createMemorySubjectBinding({ partition: PARTITION, scope: SCOPE, subject: caller });
    const allowed = optimizeRetrieval({
      taskFrame,
      candidates: [policy],
      auth: { caller, bindings: [binding], partition: PARTITION },
    });
    expect(allowed.trace.authorizedBy).toBe("subject_binding");
    expect(allowed.selectedAtoms).toHaveLength(1);

    const pkg: CognitivePackage = {
      packageId: "pkg_1",
      taskFrameId: "tf_1",
      answer: { summary: "raw", recommendations: [], nextSteps: [] },
      why: { summary: "matched", matchedPatterns: [] },
      supportingAtoms: ["atm_pol"],
      reasoningPath: [],
      confidence: 0.9,
      risks: [],
      constraints: ["no_force_push"],
      conflicts: [],
      evidenceRefs: ["evd_pol"],
    };
    const ctx = buildContextPackage({ pkg, atoms: [policy], budgetTokens: 100 });
    expect(ctx.evidenceCompleteness).toBeLessThanOrEqual(1);
    expect(ctx.budgetedPackage.supportingAtoms).toEqual(["atm_pol"]);
    expect(ctx.budgetedPackage.answer.recommendations).toEqual(["Never force-push main."]);
  });

  it("CW-04G: Durable OptimizationJob deduplicates by idempotencyKey and reports verifiedTokenReduction", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cw-opt-job-"));
    try {
      const jobStore = new FileDurableJobStore(join(dir, "jobs.json"));
      const metadataStore = new InMemoryMetadataStore();
      const a1 = makeAtom({ id: "atm_1", dedupKey: "k1" });
      const a2 = makeAtom({ id: "atm_2", dedupKey: "k1" });
      await metadataStore.saveAtom(a1);
      await metadataStore.saveAtom(a2);

      const job1 = await runOptimizationJob({
        tenantId: "t_1",
        subjectId: "subj_1",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1, a2],
        nowMs: Date.parse("2026-11-27T00:00:00Z"),
        jobStore,
        metadataStore,
      });
      expect(job1.status).toBe("completed");
      expect(job1.result?.verifiedTokenReduction).toBeGreaterThan(0);

      // Re-running with same inputs returns the completed job idempotently.
      const job2 = await runOptimizationJob({
        tenantId: "t_1",
        subjectId: "subj_1",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [a1, a2],
        nowMs: Date.parse("2026-11-27T00:00:00Z"),
        jobStore,
      });
      expect(job2.jobId).toBe(job1.jobId);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
