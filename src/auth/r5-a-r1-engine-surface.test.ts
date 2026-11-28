import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { PrincipalUnavailableError, ScopeViolationError, UntrustedRuntimeError } from "../errors.js";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type {
  EvidenceRecord,
  MemoryAtom,
  MemorySubject,
  Scope,
  SourceBinding,
  SourceObjectLink,
  WriteJournal,
} from "../models.js";
import * as pkg from "../index.js";
import {
  getEngineCanonicalAuthorizationResolver,
  registerEngineCanonicalAuthorizationResolver,
} from "../runtime/canonical-resolver-registry.js";
import { InMemoryCogniWeaveEngine } from "../runtime/in-memory-engine.js";
import { InMemoryMetadataStore } from "../storage/in-memory.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import { createAuthoritativeBindingQueryFromMetadataStore } from "./canonical-scope.js";
import { createDenyByDefaultPrincipalProvider, type TrustedPrincipal } from "./principal.js";
import { createTrustedRuntime } from "./trusted-runtime.js";

const NOW = "2026-11-28T00:00:00.000Z";

const ATOM_SCOPE: Scope = {
  workspaceId: "ws_1",
  projectId: "proj_1",
  agentId: "agent_main",
  visibility: "private",
};

const CROSS_WORKSPACE: Scope = {
  workspaceId: "ws_other",
  projectId: "proj_1",
  agentId: "agent_main",
  visibility: "private",
};

const CROSS_SUBJECT: Scope = {
  workspaceId: "ws_1",
  projectId: "proj_1",
  agentId: "agent_other",
  visibility: "private",
};

const CROSS_TENANT: Scope = {
  workspaceId: "ws_tenant_b",
  projectId: "proj_b",
  agentId: "agent_b",
  visibility: "private",
};

const SUBJECT: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "u_1" };
const TOKEN = "tok_r5a_r1";

const PRINCIPAL: TrustedPrincipal = {
  tenantId: "t_1",
  userId: "u_1",
  subject: SUBJECT,
  tokenId: "tok_r5a_r1",
  allowedWorkspaceIds: ["ws_1"],
};

const localConfig = {
  environment: "local" as const,
  metadataBackend: "memory" as const,
  graphBackend: "memory" as const,
  evidenceBackend: "memory" as const,
  vectorBackend: "memory" as const,
};

const serviceConfig = {
  environment: "service" as const,
  metadataBackend: "memory" as const,
  graphBackend: "memory" as const,
  evidenceBackend: "memory" as const,
  vectorBackend: "memory" as const,
};

function bindingIdFor(identity: string, locator: string): string {
  return `sb_${createHash("sha256").update(`${identity}\0${locator}`).digest("hex").slice(0, 20)}`;
}

function linkIdFor(bindingId: string, objectType: string, objectId: string): string {
  return `sol_${createHash("sha256")
    .update(`${bindingId}\0${objectType}\0${objectId}`)
    .digest("hex")
    .slice(0, 20)}`;
}

function makeBinding(id: string, identity: string, locator: string, scope: Scope): SourceBinding {
  return {
    id,
    sourceIdentityId: identity,
    sourceLocator: locator,
    status: "active",
    scope,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function makeLink(
  bindingId: string,
  objectType: "atom" | "evidence",
  objectId: string,
): SourceObjectLink {
  return {
    id: linkIdFor(bindingId, objectType, objectId),
    sourceBindingId: bindingId,
    objectType,
    objectId,
    linkRole: "supporting",
    createdAt: NOW,
  };
}

function makeAtom(id: string, scope: Scope, evidenceRefs: string[]): MemoryAtom {
  return {
    id,
    atomType: "strategy",
    scope,
    claim: { type: "procedural", statement: `atom ${id}` },
    trigger: { conditions: ["auth"], contextTags: ["r5a-r1"] },
    applicability: { include: [], exclude: [] },
    provenance: { sourceEventIds: [], evidenceRefs },
    versioning: { version: 1 },
    state: { status: "active", conflictsWith: [] },
    metrics: { confidence: 0.8, reuseCount: 0 },
    dedupKey: id,
  };
}

function makeEvidence(id: string, uri: string, scope: Scope): EvidenceRecord {
  return {
    id,
    type: "document",
    uri,
    snippet: "shared evidence phrase",
    trustScore: 0.9,
    scope,
    locator: { messageIds: [], toolCallIds: [] },
  };
}

function emptyJournal(id: string, scope: Scope, atomId: string): WriteJournal {
  return {
    id,
    eventKey: `evt_${id}`,
    scope,
    objectIds: {
      eventIds: [],
      atomIds: [atomId],
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
    updatedAt: NOW,
  };
}

async function seedLiveSourceFixture(store: InMemoryMetadataStore) {
  const evidenceUri = "msrc://shared_src";
  const evidence = makeEvidence("ev_shared", evidenceUri, ATOM_SCOPE);
  const atom = makeAtom("atm_owned", ATOM_SCOPE, [evidence.id]);

  const sameDirect = makeBinding("sb_same_direct", "sid_same_direct", "msrc://sid_same_direct", ATOM_SCOPE);
  const sameEvidence = makeBinding(
    "sb_same_evidence",
    "sid_same_evidence",
    "msrc://sid_same_evidence",
    ATOM_SCOPE,
  );
  const sameBackfill = makeBinding("sb_same_backfill", "shared_src", evidenceUri, ATOM_SCOPE);

  const crossWorkspaceDirect = makeBinding(
    "sb_cross_workspace",
    "sid_cross_workspace",
    "msrc://sid_cross_workspace",
    CROSS_WORKSPACE,
  );
  const crossSubjectEvidence = makeBinding(
    "sb_cross_subject",
    "sid_cross_subject",
    "msrc://sid_cross_subject",
    CROSS_SUBJECT,
  );
  const crossTenantBackfill = makeBinding(
    "sb_cross_tenant",
    "shared_src",
    `${evidenceUri}#tenant-b`,
    CROSS_TENANT,
  );

  await store.saveEvidence(evidence);
  await store.saveAtom(atom);
  for (const binding of [
    sameDirect,
    sameEvidence,
    sameBackfill,
    crossWorkspaceDirect,
    crossSubjectEvidence,
    crossTenantBackfill,
  ]) {
    await store.saveSourceBinding(binding);
  }
  await store.saveSourceObjectLink(makeLink(sameDirect.id, "atom", atom.id));
  await store.saveSourceObjectLink(makeLink(sameEvidence.id, "evidence", evidence.id));
  await store.saveSourceObjectLink(makeLink(crossWorkspaceDirect.id, "atom", atom.id));
  await store.saveSourceObjectLink(makeLink(crossSubjectEvidence.id, "evidence", evidence.id));

  return {
    atom,
    evidence,
    sameDirect,
    sameEvidence,
    sameBackfill,
    foreignIds: [crossWorkspaceDirect.id, crossSubjectEvidence.id, crossTenantBackfill.id],
    foreignLocators: [
      crossWorkspaceDirect.sourceLocator,
      crossSubjectEvidence.sourceLocator,
      crossTenantBackfill.sourceLocator,
    ],
    foreignIdentities: [
      crossWorkspaceDirect.sourceIdentityId,
      crossSubjectEvidence.sourceIdentityId,
      crossTenantBackfill.sourceIdentityId,
    ],
  };
}

function assertNoForeignDisclosure(
  result: Array<{
    sourceBindingId: string;
    sourceIdentityId: string;
    sourceLocator: string;
    status: string;
  }>,
  fixture: Awaited<ReturnType<typeof seedLiveSourceFixture>>,
): void {
  const dumped = JSON.stringify(result);
  for (const id of fixture.foreignIds) {
    expect(result.map((row) => row.sourceBindingId)).not.toContain(id);
    expect(dumped).not.toContain(id);
  }
  for (const locator of fixture.foreignLocators) {
    expect(result.map((row) => row.sourceLocator)).not.toContain(locator);
    expect(dumped).not.toContain(locator);
  }
  expect(result.map((row) => row.sourceIdentityId)).not.toContain("sid_cross_workspace");
  expect(result.map((row) => row.sourceIdentityId)).not.toContain("sid_cross_subject");
  expect(dumped).not.toContain("ws_other");
  expect(dumped).not.toContain("ws_tenant_b");
  expect(dumped).not.toContain("agent_other");
}

async function serviceEngine(store = new InMemoryMetadataStore()) {
  const dataPlaneId = await store.ensureDataPlaneId();
  const binding = createMemorySubjectBinding({
    partition: createMemoryPartitionKeyV1(dataPlaneId, ATOM_SCOPE),
    scope: ATOM_SCOPE,
    subject: SUBJECT,
  });
  await store.saveMemorySubjectBinding(binding);
  const runtime = createTrustedRuntime({
    environment: "service",
    principalProvider: createDenyByDefaultPrincipalProvider([{ token: TOKEN, principal: PRINCIPAL }]),
    bindingQuery: createAuthoritativeBindingQueryFromMetadataStore(store),
    ensureDataPlaneId: () => store.ensureDataPlaneId(),
  });
  const engine = new InMemoryCogniWeaveEngine(serviceConfig, { metadataStore: store, runtime });
  return { engine, store, runtime };
}

describe("CW-09-02-R5-A-R1 Engine Direct remaining public-surface remediations", () => {
  it("does not export repair helpers or resolver hooks from the package root", () => {
    expect(Object.hasOwn(pkg, "rebuildFromTruth")).toBe(false);
    expect(Object.hasOwn(pkg, "repairDerivedIndexes")).toBe(false);
    expect(Object.hasOwn(pkg, "getEngineCanonicalAuthorizationResolver")).toBe(false);
    expect(Object.hasOwn(pkg, "registerEngineCanonicalAuthorizationResolver")).toBe(false);
    expect(typeof pkg.InMemoryCogniWeaveEngine).toBe("function");
  });

  it("does not expose the Canonical resolver or lookup on an Engine instance", () => {
    const engine = new InMemoryCogniWeaveEngine(localConfig);
    const proto = Object.getPrototypeOf(engine) as object;
    const names = [
      ...Object.getOwnPropertyNames(engine),
      ...Object.getOwnPropertyNames(proto),
    ];
    expect(names).not.toContain("canonicalResolver");
    expect(names).not.toContain("canonicalLookup");
    expect(names).not.toContain("getEngineCanonicalAuthorizationResolver");
    expect(typeof (engine as { canonicalResolver?: unknown }).canonicalResolver).toBe("undefined");
    expect(typeof (engine as { canonicalLookup?: unknown }).canonicalLookup).toBe("undefined");
  });

  it("filters listLiveSourcesForAtom to the atom Canonical Scope and hides foreign bindings", async () => {
    const store = new InMemoryMetadataStore();
    const fixture = await seedLiveSourceFixture(store);
    const engine = new InMemoryCogniWeaveEngine(localConfig, { metadataStore: store });

    const result = await engine.listLiveSourcesForAtom("atm_owned");
    const ids = result.map((row) => row.sourceBindingId).sort();
    expect(ids).toEqual(["sb_same_backfill", "sb_same_direct", "sb_same_evidence"]);
    expect(result.map((row) => row.sourceIdentityId).sort()).toEqual([
      "shared_src",
      "sid_same_direct",
      "sid_same_evidence",
    ]);
    assertNoForeignDisclosure(result, fixture);
  });

  it("does not disclose cross-tenant, cross-workspace, or cross-subject bindings from a service grant", async () => {
    const store = new InMemoryMetadataStore();
    const fixture = await seedLiveSourceFixture(store);
    const { engine } = await serviceEngine(store);
    const result = await engine.listLiveSourcesForAtom("atm_owned", {
      authorization: { bearerToken: TOKEN },
    });
    expect(result.map((row) => row.sourceBindingId).sort()).toEqual([
      "sb_same_backfill",
      "sb_same_direct",
      "sb_same_evidence",
    ]);
    assertNoForeignDisclosure(result, fixture);
  });

  it("does not let a matching Evidence URI authorize or disclose a foreign Binding", async () => {
    const store = new InMemoryMetadataStore();
    const fixture = await seedLiveSourceFixture(store);
    const engine = new InMemoryCogniWeaveEngine(localConfig, { metadataStore: store });
    const result = await engine.listLiveSourcesForAtom("atm_owned");
    const backfill = result.find((row) => row.sourceBindingId === "sb_same_backfill");
    expect(backfill).toBeDefined();
    expect(result.some((row) => row.sourceBindingId === "sb_cross_tenant")).toBe(false);
    expect(JSON.stringify(result)).not.toContain("sb_cross_tenant");
    expect(JSON.stringify(result)).not.toContain(fixture.foreignLocators[2]);
  });

  it("fails closed when the atom Canonical Scope cannot be resolved", async () => {
    const store = new InMemoryMetadataStore();
    const engine = new InMemoryCogniWeaveEngine(localConfig, { metadataStore: store });
    await expect(engine.listLiveSourcesForAtom("atm_missing")).rejects.toBeInstanceOf(ScopeViolationError);
    await expect(engine.listLiveSourcesForAtom("atm_missing")).rejects.toThrow(
      "listLiveSourcesForAtom cannot resolve authoritative scope",
    );
  });

  it("refuses to replace a sealed Canonical authorization resolver on an Engine instance", async () => {
    const engine = new InMemoryCogniWeaveEngine(localConfig);
    const original = getEngineCanonicalAuthorizationResolver(engine);
    expect(original).toBeDefined();
    expect(() =>
      registerEngineCanonicalAuthorizationResolver(engine, {
        async resolve() {
          return {
            found: true,
            kind: "atom",
            id: "forged",
            scope: CROSS_TENANT,
          };
        },
      }),
    ).toThrow(UntrustedRuntimeError);
    expect(getEngineCanonicalAuthorizationResolver(engine)).toBe(original);
  });

  it("keeps authorized Engine repair methods working and production calls fail closed without auth", async () => {
    const localStore = new InMemoryMetadataStore();
    await localStore.saveAtom(makeAtom("atm_repair", ATOM_SCOPE, []));
    await localStore.putJournal(emptyJournal("jnl_repair", ATOM_SCOPE, "atm_repair"));
    const localEngine = new InMemoryCogniWeaveEngine(localConfig, { metadataStore: localStore });
    const rebuilt = await localEngine.rebuildFromTruth({
      objectType: "atom",
      objectId: "atm_repair",
      scope: ATOM_SCOPE,
    });
    expect(rebuilt).toMatchObject({ status: "REBUILT" });
    const repaired = await localEngine.repairIndexes({ scope: ATOM_SCOPE, journalId: "jnl_repair" });
    expect(repaired.status).toBe("SYNCED");

    const { engine } = await serviceEngine();
    await expect(engine.listLiveSourcesForAtom("atm_owned")).rejects.toBeInstanceOf(
      PrincipalUnavailableError,
    );
    await expect(
      engine.rebuildFromTruth({ objectType: "atom", objectId: "atm_repair", scope: ATOM_SCOPE }),
    ).rejects.toBeInstanceOf(PrincipalUnavailableError);
  });
});
