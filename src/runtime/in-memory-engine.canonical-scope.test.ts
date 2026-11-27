import { describe, expect, it } from "vitest";
import { createAuthoritativeBindingQueryFromMetadataStore } from "../auth/canonical-scope.js";
import { createDenyByDefaultPrincipalProvider } from "../auth/principal.js";
import { createTrustedRuntime } from "../auth/trusted-runtime.js";
import { ScopeViolationError, ValidationError } from "../errors.js";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import { InMemoryMetadataStore } from "../storage/in-memory.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import { InMemoryCogniWeaveEngine } from "./in-memory-engine.js";

const scope = {
  workspaceId: "ws_1",
  projectId: "proj_1",
  agentId: "agent_main",
  visibility: "private" as const,
};

const otherScope = {
  ...scope,
  workspaceId: "ws_other",
};

const serviceAuth = { bearerToken: "svc_tok" };
const serviceSubject = { tenantId: "t_1", ownerType: "user" as const, ownerId: "u_1" };

async function engine(environment: "local" | "service" = "local", metadataStore = new InMemoryMetadataStore()) {
  let runtime = undefined;
  if (environment === "service") {
    const dataPlaneId = await metadataStore.ensureDataPlaneId();
    await metadataStore.saveMemorySubjectBinding(
      createMemorySubjectBinding({
        partition: createMemoryPartitionKeyV1(dataPlaneId, scope),
        scope,
        subject: serviceSubject,
      }),
    );
    runtime = createTrustedRuntime({
      environment: "service",
      principalProvider: createDenyByDefaultPrincipalProvider([
        {
          token: "svc_tok",
          principal: {
            tenantId: "t_1",
            userId: "u_1",
            subject: serviceSubject,
            allowedWorkspaceIds: ["ws_1", "ws_other"],
          },
        },
      ]),
      bindingQuery: createAuthoritativeBindingQueryFromMetadataStore(metadataStore),
      ensureDataPlaneId: () => metadataStore.ensureDataPlaneId(),
    });
  }
  return {
    metadataStore,
    authorization: environment === "service" ? serviceAuth : undefined,
    engine: new InMemoryCogniWeaveEngine(
      {
        environment,
        metadataBackend: "memory",
        graphBackend: "memory",
        evidenceBackend: "memory",
        vectorBackend: "memory",
      },
      { metadataStore, runtime },
    ),
  };
}

const rawInput =
  "Current throughput is dropping and the external API is slow. Should we add synchronous retries?";

describe("CW-09-01 engine canonical scope guards", () => {
  it("persists WriteJournal.scope on writeBack and uses it for getWriteJournal", async () => {
    const { engine: cw } = await engine();
    const write = await cw.writeBack({
      rawInput,
      scope,
      sourceType: "chat",
      sourceSessionId: "sess_journal_scope",
    });
    const journal = await cw.getWriteJournal(write.journalId, scope);
    expect(journal.scope).toEqual(scope);
  });

  it("refuses getWriteJournal when ownership cannot be derived", async () => {
    const { engine: cw, metadataStore } = await engine();
    await metadataStore.putJournal({
      id: "jnl_orphan",
      eventKey: "ek_orphan",
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
    });
    await expect(cw.getWriteJournal("jnl_orphan", scope)).rejects.toBeInstanceOf(ScopeViolationError);
  });

  it("rebuildFromTruth requires caller scope and matching objectType", async () => {
    const { engine: cw } = await engine();
    const write = await cw.writeBack({
      rawInput,
      scope,
      sourceType: "chat",
      sourceSessionId: "sess_rebuild",
    });

    await expect(
      cw.rebuildFromTruth({ objectType: "atom", objectId: write.atomIds[0] }),
    ).rejects.toBeInstanceOf(ScopeViolationError);

    await expect(
      cw.rebuildFromTruth({ objectType: "event", objectId: write.atomIds[0], scope }),
    ).resolves.toMatchObject({ status: "NOT_FOUND" });

    await expect(
      cw.rebuildFromTruth({ objectType: "package", objectId: write.atomIds[0], scope }),
    ).rejects.toBeInstanceOf(ValidationError);

    await expect(
      cw.rebuildFromTruth({ objectType: "atom", objectId: write.atomIds[0], scope: otherScope }),
    ).rejects.toBeInstanceOf(ScopeViolationError);

    const rebuilt = await cw.rebuildFromTruth({
      objectType: "atom",
      objectId: write.atomIds[0],
      scope,
    });
    expect(rebuilt.status).toBe("REBUILT");
  });

  it("repairIndexes in service mode requires scope and excludes unresolvable journals", async () => {
    const { engine: cw, metadataStore, authorization } = await engine("service");
    const write = await cw.writeBack({
      rawInput,
      scope,
      sourceType: "chat",
      sourceSessionId: "sess_repair",
      authorization,
    });
    await metadataStore.updateJournal(write.journalId, { status: "DERIVED_OUT_OF_SYNC" });
    await metadataStore.putJournal({
      id: "jnl_unscoped",
      eventKey: "ek_unscoped",
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
      status: "DERIVED_OUT_OF_SYNC",
      phase: "METADATA_COMMITTED",
      retryCount: 0,
      updatedAt: new Date().toISOString(),
    });

    await expect(cw.repairIndexes({ journalId: write.journalId, authorization })).rejects.toBeInstanceOf(
      ScopeViolationError,
    );

    const repaired = await cw.repairIndexes({ scope, authorization });
    expect(repaired).toMatchObject({ status: "SYNCED", repairedCount: 1 });
  });
});
