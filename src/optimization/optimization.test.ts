import { describe, expect, it } from "vitest";
import type { CognitivePackage, MemoryAtom, Scope, TaskFrame } from "../models.js";
import {
  abstractFromAtoms,
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

function makeAtom(overrides: Partial<MemoryAtom> & { id: string }): MemoryAtom {
  return {
    id: overrides.id,
    atomType: overrides.atomType ?? "strategy",
    scope: overrides.scope ?? SCOPE,
    claim: overrides.claim ?? {
      type: "procedural",
      statement: "Always run forward-only check before production cutover.",
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

describe("Memory Optimization Engine (CW-04 / MOP-01..06)", () => {
  it("MOP-01: evaluates admission using scoreAdmission, rejects exact duplicates, and routes high-risk/conflicts to pending_review", () => {
    const existing = makeAtom({ id: "atm_0", dedupKey: "dup_1" });
    const dup = makeAtom({ id: "atm_1", dedupKey: "dup_1" });
    expect(evaluateAdmission({ atom: dup, existingAtoms: [existing] }).disposition).toBe(
      "rejected",
    );

    const noEv = makeAtom({
      id: "atm_2",
      provenance: { sourceEventIds: [], evidenceRefs: [] },
    });
    expect(evaluateAdmission({ atom: noEv }).disposition).toBe("tentative");

    const highRisk = makeAtom({ id: "atm_3" });
    expect(evaluateAdmission({ atom: highRisk, highRisk: true }).disposition).toBe(
      "pending_review",
    );

    const valid = makeAtom({ id: "atm_4" });
    const admitted = evaluateAdmission({ atom: valid, sourceAuthority: "authoritative" });
    expect(admitted.disposition).toBe("accepted");
    expect(admitted.admissionScore).toBeGreaterThan(0.5);
  });

  it("MOP-02: consolidates compatible duplicates while preserving evidence and never merging conflicts or incompatible applicability", () => {
    const a1 = makeAtom({
      id: "atm_1",
      provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_1"] },
    });
    const a2 = makeAtom({
      id: "atm_2",
      provenance: { sourceEventIds: ["evt_2"], evidenceRefs: ["evd_2"] },
    });
    const incompatible = makeAtom({
      id: "atm_3",
      applicability: { include: ["staging"], exclude: ["prod"] },
    });
    const conflicted = makeAtom({
      id: "atm_4",
      state: { status: "conflicted", conflictsWith: ["atm_1"] },
    });

    const result = consolidateAtoms([a1, a2, incompatible, conflicted]);
    expect(result.mergedCount).toBe(1);
    expect(result.preservedConflictCount).toBe(1);
    const mergedCluster = result.clusters.find((c) => c.canonicalAtomId === "atm_1");
    expect(mergedCluster?.sourceAtomIds).toEqual(["atm_1", "atm_2"]);
    expect(mergedCluster?.evidenceRefs).toEqual(["evd_1", "evd_2"]);
    expect(result.clusters.some((c) => c.canonicalAtomId === "atm_3")).toBe(true);
    expect(result.clusters.some((c) => c.decision === "conflicting")).toBe(true);
  });

  it("MOP-03: abstracts multi-atom patterns while preserving all supporting atom IDs and evidence", () => {
    const a1 = makeAtom({
      id: "atm_1",
      atomType: "failure_pattern",
      provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_1"] },
    });
    const a2 = makeAtom({
      id: "atm_2",
      atomType: "failure_pattern",
      provenance: { sourceEventIds: ["evt_2"], evidenceRefs: ["evd_2"] },
      applicability: { include: ["prod"], exclude: ["canary"] },
    });

    const abstracted = abstractFromAtoms({ atoms: [a1, a2] });
    expect(abstracted).not.toBeNull();
    expect(abstracted?.supportingAtomIds).toEqual(["atm_1", "atm_2"]);
    expect(abstracted?.evidenceRefs).toEqual(["evd_1", "evd_2"]);
    expect(abstracted?.knownExceptions).toContain("canary");
  });

  it("MOP-04: protects legal_hold, flags conflicted/stale atoms for revalidation, and archives deprecated", () => {
    const legal = makeAtom({
      id: "atm_legal",
      lifecycle: { retentionClass: "legal_hold", admittedAt: "2020-01-01T00:00:00Z" },
      metrics: { confidence: 0.2, reuseCount: 0 },
    });
    expect(evaluateLifecycle(legal).action).toBe("keep_active");

    const stale = makeAtom({
      id: "atm_stale",
      lifecycle: { retentionClass: "ephemeral", admittedAt: "2025-01-01T00:00:00Z" },
      metrics: { confidence: 0.8, reuseCount: 0 },
    });
    expect(
      evaluateLifecycle(stale, { nowMs: Date.parse("2025-03-01T00:00:00Z") }).action,
    ).toBe("archive");

    const deprecated = makeAtom({
      id: "atm_dep",
      state: { status: "deprecated", conflictsWith: [] },
    });
    expect(evaluateLifecycle(deprecated).action).toBe("archive");
  });

  it("MOP-05 & MOP-06: excludes deprecated atoms, enforces context budget, and prioritizes policies/constraints", () => {
    const taskFrame: TaskFrame = {
      id: "tf_1",
      scope: SCOPE,
      taskType: "operations",
      goals: ["safe release"],
      problems: [],
      scenarioTags: ["release"],
      constraints: ["no_force_push"],
      entities: [],
      requiredAtomTypes: ["policy", "strategy"],
    };

    const policy = makeAtom({
      id: "atm_pol",
      atomType: "policy",
      claim: { type: "policy", statement: "Never force-push main." },
      provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_pol"] },
    });
    const bg = makeAtom({
      id: "atm_bg",
      atomType: "strategy",
      claim: { type: "procedural", statement: "B".repeat(200) },
      metrics: { confidence: 0.5, reuseCount: 0 },
    });
    const dep = makeAtom({
      id: "atm_dep",
      state: { status: "deprecated", conflictsWith: [] },
    });

    const retrieved = optimizeRetrieval({
      taskFrame,
      candidates: [policy, bg, dep],
      contextBudgetTokens: 30,
    });
    expect(retrieved.selectedAtoms.map((s) => s.atom.id)).toEqual(["atm_pol"]);
    expect(retrieved.excludedCandidates).toEqual(
      expect.arrayContaining([
        { atomId: "atm_dep", reason: "deprecated" },
        { atomId: "atm_bg", reason: "budget_exceeded" },
      ]),
    );

    const pkg: CognitivePackage = {
      packageId: "pkg_1",
      taskFrameId: "tf_1",
      answer: { summary: "ok", recommendations: [], nextSteps: [] },
      why: { summary: "matched", matchedPatterns: [] },
      supportingAtoms: ["atm_bg", "atm_pol"],
      reasoningPath: [],
      confidence: 0.9,
      risks: [],
      constraints: ["no_force_push"],
      conflicts: [],
      evidenceRefs: ["evd_pol"],
    };
    const ctx = buildContextPackage({ pkg, atoms: [bg, policy], budgetTokens: 20 });
    expect(ctx.selectedMemoryIds).toEqual(["atm_pol"]);
    expect(ctx.omittedMemories).toEqual([{ atomId: "atm_bg", reason: "budget_exceeded" }]);
    expect(ctx.evidenceCompleteness).toBe(1);
    expect(ctx.constraintsPreserved).toEqual(["no_force_push"]);
  });

  it("executes deterministic MemoryOptimizationJob and produces OptimizationReport", () => {
    const a1 = makeAtom({ id: "atm_1", dedupKey: "k1" });
    const a2 = makeAtom({ id: "atm_2", dedupKey: "k1" });
    const job = runOptimizationJob({
      tenantId: "t_1",
      subjectId: "subj_1",
      scope: SCOPE,
      optimizationType: "full",
      atoms: [a1, a2],
      nowMs: Date.parse("2026-11-27T00:00:00Z"),
    });

    expect(job.status).toBe("completed");
    expect(job.result?.duplicateReductionCount).toBe(1);
    expect(job.result?.estimatedTokensAfter).toBeLessThan(job.result!.estimatedTokensBefore);
    expect(job.result?.abstraction?.supportingAtomIds).toEqual(["atm_1", "atm_2"]);
  });
});
