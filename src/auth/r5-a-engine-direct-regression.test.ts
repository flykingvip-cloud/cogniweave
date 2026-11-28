import { describe, expect, it } from "vitest";
import { PrincipalUnavailableError, ScopeViolationError } from "../errors.js";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type { MemoryAtom, MemorySubject, Scope, SourceBinding, WriteJournal } from "../models.js";
import * as pkg from "../index.js";
import { InMemoryCogniWeaveEngine } from "../runtime/in-memory-engine.js";
import { InMemoryMetadataStore } from "../storage/in-memory.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import { createAuthoritativeBindingQueryFromMetadataStore } from "./canonical-scope.js";
import { ENGINE_DIRECT_AUTH_ENTRYPOINTS } from "./engine-invocation.js";
import { createDenyByDefaultPrincipalProvider, type TrustedPrincipal } from "./principal.js";
import { createTrustedRuntime } from "./trusted-runtime.js";

const SCOPE: Scope = {
  workspaceId: "ws_1",
  projectId: "proj_1",
  agentId: "agent_main",
  visibility: "private",
};

const OTHER_SCOPE: Scope = {
  workspaceId: "ws_1",
  projectId: "proj_other",
  agentId: "agent_other",
  visibility: "private",
};

const SUBJECT: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "u_1" };
const TOKEN = "tok_r5a";
const NOW = "2026-11-28T00:00:00.000Z";

const PRINCIPAL: TrustedPrincipal = {
  tenantId: "t_1",
  userId: "u_1",
  subject: SUBJECT,
  tokenId: "tok_r5a",
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

function emptyJournal(
  id: string,
  scope: Scope,
  status: WriteJournal["status"] = "COMPLETED",
  updatedAt = NOW,
): WriteJournal {
  return {
    id,
    eventKey: `evt_${id}`,
    scope,
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
    status,
    phase: status === "FAILED" ? "METADATA_COMMITTED" : "COMPLETED",
    retryCount: 0,
    updatedAt,
  };
}

function makeAtom(id: string, scope: Scope): MemoryAtom {
  return {
    id,
    atomType: "strategy",
    scope,
    claim: { type: "procedural", statement: `atom ${id}` },
    trigger: { conditions: ["auth"], contextTags: ["r5a"] },
    applicability: { include: [], exclude: [] },
    provenance: { sourceEventIds: [], evidenceRefs: [] },
    versioning: { version: 1 },
    state: { status: "active", conflictsWith: [] },
    metrics: { confidence: 0.8, reuseCount: 0 },
    dedupKey: id,
  };
}

function orphanBinding(id: string, scope: Scope): SourceBinding {
  return {
    id,
    sourceIdentityId: `sid_${id}`,
    sourceLocator: `msrc://sid_${id}`,
    status: "active",
    scope,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

async function serviceEngine(store = new InMemoryMetadataStore()) {
  const dataPlaneId = await store.ensureDataPlaneId();
  const binding = createMemorySubjectBinding({
    partition: createMemoryPartitionKeyV1(dataPlaneId, SCOPE),
    scope: SCOPE,
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

describe("CW-09-02-R5-A Engine Direct authorization remediations", () => {
  it("rejects compactJournals cross-scope deletes and omits foreign journal IDs from the receipt", async () => {
    const store = new InMemoryMetadataStore();
    const engine = new InMemoryCogniWeaveEngine(localConfig, { metadataStore: store });
    await store.putJournal(emptyJournal("jnl_scope_a", SCOPE, "COMPLETED", "2026-11-28T00:00:01.000Z"));
    await store.putJournal(emptyJournal("jnl_scope_b", SCOPE, "COMPLETED", "2026-11-28T00:00:02.000Z"));
    await store.putJournal(emptyJournal("jnl_scope_c", SCOPE, "COMPLETED", "2026-11-28T00:00:03.000Z"));
    await store.putJournal(emptyJournal("jnl_other", OTHER_SCOPE, "COMPLETED"));
    await store.putJournal(emptyJournal("jnl_other_failed", OTHER_SCOPE, "FAILED"));

    const compacted = await engine.compactJournals({ keepCompleted: 1, dryRun: false, scope: SCOPE });
    expect(compacted.status).toBe("COMPACTED");
    expect(compacted.deletedJournalIds.sort()).toEqual(["jnl_scope_a", "jnl_scope_b"]);
    expect(compacted.retainedJournalIds).toContain("jnl_scope_c");
    expect(compacted.deletedJournalIds).not.toContain("jnl_other");
    expect(compacted.retainedJournalIds).not.toContain("jnl_other");
    expect(compacted.retainedJournalIds).not.toContain("jnl_other_failed");
    const remaining = (await store.listJournals()).map((journal) => journal.id).sort();
    expect(remaining).toEqual(["jnl_other", "jnl_other_failed", "jnl_scope_c"]);
  });

  it("rejects source lifecycle selectors for another scope without mutating or disclosing the binding", async () => {
    const store = new InMemoryMetadataStore();
    const engine = new InMemoryCogniWeaveEngine(localConfig, { metadataStore: store });
    const archive = await engine.archiveSource({
      operationId: "op-other-archive",
      selector: { mode: "identity", sourceIdentityId: "sid_foreign" },
      subject: { scope: OTHER_SCOPE },
      reasonCode: "SEED_OTHER",
    });
    expect(archive.currentStatus).toBe("archived");
    const before = (await store.listSourceBindings()).map((binding) => ({
      id: binding.id,
      status: binding.status,
      scope: binding.scope,
    }));

    const cross = engine.forgetSource({
      operationId: "op-cross-forget",
      selector: { mode: "identity", sourceIdentityId: "sid_foreign" },
      subject: { scope: SCOPE },
      reasonCode: "CROSS",
    });
    await expect(cross).rejects.toBeInstanceOf(ScopeViolationError);
    await expect(cross).rejects.toThrow("source binding is not authorized");

    const after = (await store.listSourceBindings()).map((binding) => ({
      id: binding.id,
      status: binding.status,
      scope: binding.scope,
    }));
    expect(after).toEqual(before);
    expect(after).toHaveLength(1);
    expect(after[0]?.status).toBe("archived");
    expect(after[0]?.scope).toEqual(OTHER_SCOPE);

    const replay = engine.archiveSource({
      operationId: "op-other-archive",
      selector: { mode: "identity", sourceIdentityId: "sid_foreign" },
      subject: { scope: SCOPE },
      reasonCode: "REPLAY_CROSS",
    });
    await expect(replay).rejects.toBeInstanceOf(ScopeViolationError);
    await expect(replay).rejects.toThrow("source binding is not authorized");
  });

  it("rejects upsertAtoms mixed-scope batches before any unauthorized write", async () => {
    const store = new InMemoryMetadataStore();
    const engine = new InMemoryCogniWeaveEngine(localConfig, { metadataStore: store });
    await expect(
      engine.upsertAtoms([makeAtom("atm_scope", SCOPE), makeAtom("atm_other", OTHER_SCOPE)]),
    ).rejects.toBeInstanceOf(ScopeViolationError);
    expect(await store.getAtom("atm_scope")).toBeUndefined();
    expect(await store.getAtom("atm_other")).toBeUndefined();

    const kept = await engine.upsertAtoms([makeAtom("atm_ok", SCOPE)]);
    expect(kept).toHaveLength(1);
    expect(await store.getAtom("atm_ok")).toBeDefined();
  });

  it("does not expose ungated lookup or source-binding helpers on the public Engine or package surface", () => {
    expect(Object.hasOwn(pkg, "rebuildFromTruth")).toBe(false);
    expect(Object.hasOwn(pkg, "repairDerivedIndexes")).toBe(false);
    const engine = new InMemoryCogniWeaveEngine(localConfig);
    expect("resolveCanonicalResourceScopeForAuthorization" in engine).toBe(false);
    expect("getSourceBindingStatus" in engine).toBe(false);
    expect("isSourcePathRetrievable" in engine).toBe(false);
    expect("isEvidenceRetrievable" in engine).toBe(false);
    expect(typeof engine.resolveCanonicalResourceScope).toBe("function");
    const inventory = ENGINE_DIRECT_AUTH_ENTRYPOINTS.map((entry) => entry.method);
    expect(inventory).not.toContain("resolveCanonicalResourceScopeForAuthorization");
    expect(inventory).not.toContain("getSourceBindingStatus");
    expect(inventory).not.toContain("isSourcePathRetrievable");
    expect(inventory).not.toContain("isEvidenceRetrievable");
    expect(inventory).toEqual(
      expect.arrayContaining([
        "upsertAtoms",
        "compactJournals",
        "recoverFromCanonical",
        "queryAtoms",
        "queryAtomsHybrid",
        "searchEvidence",
        "archiveSource",
        "resolveCanonicalResourceScope",
      ]),
    );
  });

  it("authorizes queryAtoms and searchEvidence before source-lifecycle hydration I/O", async () => {
    class DeferredBindingStore extends InMemoryMetadataStore {
      listSourceBindingCalls = 0;
      releaseBindings!: (bindings: SourceBinding[]) => void;
      readonly bindingsParked = new Promise<SourceBinding[]>((resolve) => {
        this.releaseBindings = resolve;
      });

      override async listSourceBindings(): Promise<SourceBinding[]> {
        this.listSourceBindingCalls += 1;
        return this.bindingsParked;
      }
    }

    const store = new DeferredBindingStore();
    const { engine } = await serviceEngine(store);
    const started = Date.now();
    while (store.listSourceBindingCalls < 1) {
      if (Date.now() - started > 1000) {
        throw new Error("constructor hydrate never called listSourceBindings");
      }
      await new Promise((resolve) => setTimeout(resolve, 5));
    }

    const query = engine.queryAtoms({ scope: SCOPE, caller: SUBJECT });
    const search = engine.searchEvidence("secret", { scope: SCOPE });
    const outcome = await Promise.race([
      Promise.allSettled([query, search]),
      new Promise<"timeout">((resolve) => {
        setTimeout(() => resolve("timeout"), 250);
      }),
    ]);
    expect(outcome).not.toBe("timeout");
    if (outcome === "timeout") {
      throw new Error("query/search waited on hydrate before authorization");
    }
    expect(outcome[0]?.status).toBe("rejected");
    expect(outcome[1]?.status).toBe("rejected");
    if (outcome[0]?.status === "rejected") {
      expect(outcome[0].reason).toBeInstanceOf(PrincipalUnavailableError);
    }
    if (outcome[1]?.status === "rejected") {
      expect(outcome[1].reason).toBeInstanceOf(PrincipalUnavailableError);
    }
    expect(store.listSourceBindingCalls).toBe(1);
    store.releaseBindings([]);
  });

  it("scopes recoverFromCanonical receipt counts and orphan IDs to the authorized grant", async () => {
    const store = new InMemoryMetadataStore();
    await store.putJournal(emptyJournal("jnl_scope", SCOPE, "COMPLETED"));
    await store.putJournal(emptyJournal("jnl_other", OTHER_SCOPE, "COMPLETED"));
    await store.putWriteOperation({
      writeOperationKey: "wok_scope",
      kind: "WRITE",
      completedAt: NOW,
      result: {
        eventId: "evt_scope",
        atomIds: [],
        journalId: "jnl_scope",
        canonicalStatus: "METADATA_COMMITTED",
        derivedStatus: "SYNCED",
        status: "COMPLETED",
      },
    });
    await store.putWriteOperation({
      writeOperationKey: "wok_other",
      kind: "WRITE",
      completedAt: NOW,
      result: {
        eventId: "evt_other",
        atomIds: [],
        journalId: "jnl_other",
        canonicalStatus: "METADATA_COMMITTED",
        derivedStatus: "SYNCED",
        status: "COMPLETED",
      },
    });
    await store.saveSourceBinding(orphanBinding("sb_scope", SCOPE));
    await store.saveSourceBinding(orphanBinding("sb_other", OTHER_SCOPE));

    const engine = new InMemoryCogniWeaveEngine(localConfig, { metadataStore: store });
    const recovered = await engine.recoverFromCanonical({ scope: SCOPE });
    expect(recovered.status).toBe("RECOVERED");
    expect(recovered.journalCount).toBe(1);
    expect(recovered.writeOperationCount).toBe(1);
    expect(recovered.journalsRebuilt).toBe(1);
    expect(recovered.orphanSourceBindingIds).toEqual(["sb_scope"]);
    expect(recovered.orphanSourceBindingIds).not.toContain("sb_other");
    expect((await store.listJournals()).map((journal) => journal.id).sort()).toEqual([
      "jnl_other",
      "jnl_scope",
    ]);
  });

  it("still requires a token for production Engine Direct calls and rejects mixed-scope upserts under a valid grant", async () => {
    const { engine, store } = await serviceEngine();
    await expect(engine.compactJournals({ scope: SCOPE })).rejects.toBeInstanceOf(
      PrincipalUnavailableError,
    );
    await expect(engine.recoverFromCanonical({ scope: SCOPE })).rejects.toBeInstanceOf(
      PrincipalUnavailableError,
    );
    await expect(
      engine.upsertAtoms([makeAtom("atm_scope", SCOPE), makeAtom("atm_other", OTHER_SCOPE)], {
        authorization: { bearerToken: TOKEN },
      }),
    ).rejects.toBeInstanceOf(ScopeViolationError);
    expect(await store.getAtom("atm_scope")).toBeUndefined();
    expect(await store.getAtom("atm_other")).toBeUndefined();
  });
});
