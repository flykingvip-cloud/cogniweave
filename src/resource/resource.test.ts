import { describe, expect, it } from "vitest";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type { MemorySubject, Scope } from "../models.js";
import { InMemoryCogniWeaveEngine } from "../runtime/in-memory-engine.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import { CogniWeaveMemoryResourceAdapter } from "./index.js";

const SCOPE: Scope = {
  workspaceId: "ws_1",
  projectId: "proj_1",
  agentId: "agent_main",
  visibility: "shared",
};

const PARTITION = createMemoryPartitionKeyV1("dp_1", SCOPE);

describe("CogniWeaveMemoryResourceAdapter (CW-06)", () => {
  it("registers, discovers, checks fail-closed access, and propagates revocation events", async () => {
    const engine = new InMemoryCogniWeaveEngine({
      environment: "local",
      metadataBackend: "memory",
      graphBackend: "memory",
      evidenceBackend: "memory",
      vectorBackend: "memory",
    });
    const adapter = new CogniWeaveMemoryResourceAdapter(engine);
    const caller: MemorySubject = { tenantId: "t_1", ownerType: "team", ownerId: "team_eng" };
    const binding = createMemorySubjectBinding({
      partition: PARTITION,
      scope: SCOPE,
      subject: caller,
    });

    const registered = adapter.registerResource({
      resourceId: "res_team_1",
      resourceType: "team_memory",
      tenantId: "t_1",
      ownerType: "team",
      ownerId: "team_eng",
      subjectBindingId: binding.id,
      scope: SCOPE,
      visibility: "shared",
      privacyLevel: "shared",
      lifecycleStatus: "active",
      supportedAtomTypes: ["strategy", "policy"],
      capabilities: ["retrieve", "evidence"],
      sourceAuthority: "team_verified",
      evidenceSupport: true,
    });

    expect(registered.version).toBe(1);

    const ctx = {
      userId: "u_1",
      tenantId: "t_1",
      agentId: "agent_main",
      callerSubject: caller,
      bindings: [binding],
      partition: PARTITION,
    };

    expect(adapter.discoverResources(ctx).map((r) => r.resourceId)).toEqual(["res_team_1"]);
    expect(
      adapter.checkAccess("res_team_1", { ...ctx, knowledgePolicyAllows: false }),
    ).toEqual({ allowed: false, denyReason: "knowledge_policy_denied" });
    expect(
      adapter.checkAccess("res_team_1", { ...ctx, tenantId: "t_other" }),
    ).toEqual({ allowed: false, denyReason: "tenant_mismatch" });

    const frame = await engine.frameTask("plan release", { scope: SCOPE });
    const pkg = await adapter.retrieveCognitivePackage("res_team_1", frame, ctx);
    expect(pkg.taskFrameId).toBe(frame.id);

    adapter.revokeAccess("res_team_1");
    expect(adapter.getResourceStatus("res_team_1")).toBe("revoked");
    expect(adapter.checkAccess("res_team_1", ctx)).toEqual({
      allowed: false,
      denyReason: "resource_revoked",
    });

    const events = adapter.drainDomainEvents();
    expect(events.map((e) => e.eventType)).toEqual([
      "memory.resource.registered",
      "memory.resource.access.revoked",
    ]);
  });
});
