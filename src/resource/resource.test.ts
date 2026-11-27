import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

const OTHER_SCOPE: Scope = {
  workspaceId: "ws_other",
  projectId: "proj_other",
  agentId: "agent_other",
  visibility: "private",
};

const PARTITION = createMemoryPartitionKeyV1("dp_1", SCOPE);

describe("CogniWeaveMemoryResourceAdapter (CW-06A/B)", () => {
  it("validates registration consistency, strong subjectBindingId, scope-locked reasoning, and durable outbox ack", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cw-res-"));
    const storagePath = join(dir, "resources.json");
    try {
      const engine = new InMemoryCogniWeaveEngine({
        environment: "local",
        metadataBackend: "memory",
        graphBackend: "memory",
        evidenceBackend: "memory",
        vectorBackend: "memory",
      });
      const revokedIds: string[] = [];
      const adapter = new CogniWeaveMemoryResourceAdapter(engine, {
        storagePath,
        onRevoke: (r) => {
          revokedIds.push(r.resourceId);
        },
      });
      const caller: MemorySubject = { tenantId: "t_1", ownerType: "team", ownerId: "team_eng" };
      const binding = createMemorySubjectBinding({
        partition: PARTITION,
        scope: SCOPE,
        subject: caller,
      });

      // R-05: OwnerType mismatch rejected at registration
      await expect(
        adapter.registerResource({
          resourceId: "res_bad",
          resourceType: "team_memory",
          tenantId: "t_1",
          ownerType: "user",
          ownerId: "u_1",
          subjectBindingId: binding.id,
          scope: SCOPE,
          visibility: "shared",
          privacyLevel: "shared",
          lifecycleStatus: "active",
          supportedAtomTypes: ["strategy"],
          capabilities: ["retrieve"],
          sourceAuthority: "team_verified",
          evidenceSupport: true,
        }),
      ).rejects.toThrow("requires ownerType=team");

      const registered = await adapter.registerResource({
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

      // R-03: Missing or mismatched subjectBindingId fails closed
      expect(
        await adapter.checkAccess("res_team_1", { ...ctx, bindings: [] }),
      ).toEqual({ allowed: false, denyReason: "resource_binding_missing_or_unbound" });

      // R-02: Even if caller passes a wider/different TaskFrame.scope, reasoning is locked to resource.scope
      const widerFrame = await engine.frameTask("plan release", { scope: OTHER_SCOPE });
      const pkg = await adapter.retrieveCognitivePackage("res_team_1", widerFrame, ctx);
      expect(pkg.taskFrameId).toBe(widerFrame.id);

      // R-06: Outbox peek + explicit acknowledge (destructive drain removed)
      const pending = await adapter.peekDomainEvents();
      expect(pending.map((e) => e.eventType)).toEqual(["memory.resource.registered"]);
      await adapter.acknowledgeDomainEvents(pending.map((e) => e.eventId));
      expect(await adapter.peekDomainEvents()).toEqual([]);

      // CW-06A-R1: Non-admin member cannot revoke team resource
      await expect(
        adapter.revokeAccess("res_team_1", { userId: "u_1", tenantId: "t_1", roles: ["member"] }),
      ).rejects.toThrow("not authorized to revoke");

      await adapter.revokeAccess("res_team_1", {
        userId: "u_admin",
        tenantId: "t_1",
        roles: ["tenant_admin"],
      });
      expect(revokedIds).toEqual(["res_team_1"]);
      expect(await adapter.checkAccess("res_team_1", ctx)).toEqual({
        allowed: false,
        denyReason: "resource_revoked",
      });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
