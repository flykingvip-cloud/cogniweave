import { describe, expect, it } from "vitest";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type { MemoryAtom, MemorySubject, Scope, WriteJournal } from "../models.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import {
  authorizeCanonicalResource,
  createDenyByDefaultBindingQuery,
  deriveJournalScope,
  isCompleteScope,
  isRebuildObjectType,
  resolveCanonicalResourceScope,
  type CanonicalResourceLookup,
} from "./canonical-scope.js";

const SCOPE: Scope = {
  workspaceId: "ws_1",
  projectId: "proj_1",
  agentId: "agent_main",
  visibility: "private",
};

const OTHER: Scope = { ...SCOPE, workspaceId: "ws_other" };

function emptyJournal(overrides: Partial<WriteJournal> = {}): WriteJournal {
  return {
    id: "jnl_1",
    eventKey: "ek_1",
    objectIds: {
      eventIds: [],
      atomIds: [],
      entityIds: [],
      scenarioIds: [],
      problemIds: [],
      evidenceIds: [],
      relationIds: [],
    },
    derivedPlan: { graphNodeIds: [], graphEdgeIds: [], vectorDocIds: [] },
    status: "COMPLETED",
    phase: "COMPLETED",
    retryCount: 0,
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
}

function atom(id: string, scope: Scope, status: MemoryAtom["state"]["status"] = "active"): MemoryAtom {
  return {
    id,
    atomType: "strategy",
    scope,
    claim: { type: "heuristic", statement: "s" },
    trigger: { conditions: [], contextTags: [] },
    applicability: { include: [], exclude: [] },
    provenance: { sourceEventIds: [], evidenceRefs: [] },
    versioning: { version: 1 },
    state: { status, conflictsWith: [] },
    metrics: { confidence: 1, reuseCount: 0 },
  };
}

function lookup(overrides: Partial<CanonicalResourceLookup> = {}): CanonicalResourceLookup {
  const none = async () => undefined;
  return {
    getAtom: none,
    getEvent: none,
    getJournal: none,
    getEntity: none,
    getScenario: none,
    getProblem: none,
    getEvidence: none,
    getRelation: none,
    getPackageTrace: none,
    getReasoningSession: none,
    ...overrides,
  };
}

describe("CW-09-01 canonical scope resolver", () => {
  it("treats incomplete scope as unusable", () => {
    expect(isCompleteScope({ workspaceId: "", projectId: "p", agentId: "a", visibility: "private" })).toBe(
      false,
    );
    expect(isCompleteScope(SCOPE)).toBe(true);
    expect(isRebuildObjectType("atom")).toBe(true);
    expect(isRebuildObjectType("package")).toBe(false);
  });

  it("derives journal scope from persisted scope, then event, then atom", async () => {
    const withScope = emptyJournal({ scope: SCOPE });
    expect(await deriveJournalScope(withScope, lookup())).toEqual(SCOPE);

    const viaEvent = emptyJournal({ objectIds: { ...emptyJournal().objectIds, eventIds: ["evt_1"] } });
    const derivedEvent = await deriveJournalScope(
      viaEvent,
      lookup({
        getEvent: async (id) => (id === "evt_1" ? { id, scope: SCOPE } : undefined),
      }),
    );
    expect(derivedEvent).toEqual(SCOPE);

    const viaAtom = emptyJournal({ objectIds: { ...emptyJournal().objectIds, atomIds: ["atm_1"] } });
    const derivedAtom = await deriveJournalScope(
      viaAtom,
      lookup({
        getAtom: async (id) => (id === "atm_1" ? atom(id, SCOPE) : undefined),
      }),
    );
    expect(derivedAtom).toEqual(SCOPE);

    const unresolvable = await deriveJournalScope(emptyJournal(), lookup());
    expect(unresolvable).toBeUndefined();
  });

  it("marks missing package taskFrame.scope as ownership_incomplete", async () => {
    const resolved = await resolveCanonicalResourceScope(
      "package",
      "pkg_1",
      lookup({
        getPackageTrace: async () => ({ taskFrame: undefined }),
      }),
    );
    expect(resolved.found).toBe(true);
    expect(resolved.unresolvedReason).toBe("ownership_incomplete");
  });

  it("maps store throws to store_unavailable, not not_found", async () => {
    const resolved = await resolveCanonicalResourceScope(
      "atom",
      "atm_1",
      lookup({
        getAtom: async () => {
          throw new Error("ECONNREFUSED");
        },
      }),
    );
    expect(resolved.found).toBe(false);
    expect(resolved.unresolvedReason).toBe("store_unavailable");
  });
});

describe("CW-09-01 authorizeCanonicalResource", () => {
  const subject: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "u_1" };
  const principal = {
    tenantId: "t_1",
    userId: "u_1",
    allowedWorkspaceIds: ["ws_1"],
    subject,
  };
  const binding = createMemorySubjectBinding({
    partition: createMemoryPartitionKeyV1("dp_1", SCOPE),
    scope: SCOPE,
    subject,
  });

  const resolver = {
    async resolve() {
      return {
        found: true,
        kind: "atom" as const,
        id: "atm_1",
        scope: SCOPE,
        retrievable: true,
      };
    },
  };

  it("returns 503 when the binding query is missing in production-style calls", async () => {
    const decision = await authorizeCanonicalResource({
      kind: "atom",
      id: "atm_1",
      principal,
      resolver,
      authorizeWorkspace: async () => true,
      ensureDataPlaneId: async () => "dp_1",
    });
    expect(decision).toMatchObject({ allowed: false, httpStatus: 503, error: "binding_store_unavailable" });
  });

  it("returns 503 when principal.subject is missing rather than inferring a user subject", async () => {
    const decision = await authorizeCanonicalResource({
      kind: "atom",
      id: "atm_1",
      principal: { tenantId: "t_1", userId: "u_1", allowedWorkspaceIds: ["ws_1"] },
      resolver,
      authorizeWorkspace: async () => true,
      bindingQuery: createDenyByDefaultBindingQuery([binding]),
      ensureDataPlaneId: async () => "dp_1",
    });
    expect(decision).toMatchObject({ allowed: false, httpStatus: 503, error: "principal_unavailable" });
  });

  it("denies by default when the test binding query has no matching live binding", async () => {
    const decision = await authorizeCanonicalResource({
      kind: "atom",
      id: "atm_1",
      principal,
      resolver,
      authorizeWorkspace: async () => true,
      bindingQuery: createDenyByDefaultBindingQuery([]),
      ensureDataPlaneId: async () => "dp_1",
    });
    expect(decision).toMatchObject({ allowed: false, httpStatus: 404, error: "not_found" });
  });

  it("allows only when canonical scope, workspace, and live binding intersect", async () => {
    const decision = await authorizeCanonicalResource({
      kind: "atom",
      id: "atm_1",
      principal,
      resolver,
      authorizeWorkspace: async (ws) => ws === "ws_1",
      bindingQuery: createDenyByDefaultBindingQuery([binding]),
      ensureDataPlaneId: async () => "dp_1",
    });
    expect(decision.allowed).toBe(true);
    if (decision.allowed) expect(decision.scope).toEqual(SCOPE);
  });

  it("does not treat a workspace allow-list hit as sufficient when the resource lives elsewhere", async () => {
    const decision = await authorizeCanonicalResource({
      kind: "atom",
      id: "atm_1",
      principal: { ...principal, allowedWorkspaceIds: ["ws_other"] },
      resolver,
      authorizeWorkspace: async (ws) => ws === "ws_other",
      bindingQuery: createDenyByDefaultBindingQuery([binding]),
      ensureDataPlaneId: async () => "dp_1",
    });
    expect(decision).toMatchObject({ allowed: false, httpStatus: 404, error: "not_found" });
  });
});
