import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type { MemoryAtom, MemorySubject, Scope } from "../models.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import { MemoryGovernanceService, type GovernanceActorContext } from "./index.js";

const SCOPE: Scope = {
  workspaceId: "ws_1",
  projectId: "proj_1",
  agentId: "agent_main",
  visibility: "private",
};

const PARTITION = createMemoryPartitionKeyV1("dp_1", SCOPE);

const ATOM: MemoryAtom = {
  id: "atm_1",
  atomType: "policy",
  scope: SCOPE,
  claim: { type: "policy", statement: "Require peer review before release." },
  trigger: { conditions: ["release"], contextTags: ["governance"] },
  applicability: { include: ["prod"], exclude: [] },
  provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_1"] },
  versioning: { version: 1 },
  state: { status: "active", conflictsWith: [] },
  metrics: { confidence: 0.9, reuseCount: 2 },
};

const TENANT_ADMIN: GovernanceActorContext = {
  userId: "u_admin",
  tenantId: "t_1",
  roles: ["tenant_admin"],
};

const MEMBER: GovernanceActorContext = {
  userId: "u_member",
  tenantId: "t_1",
  roles: ["member"],
};

const SPACE_ADMIN: GovernanceActorContext = {
  userId: "u_space_admin",
  tenantId: "t_1",
  roles: ["space_admin"],
  adminSpaceIds: ["kb_eng"],
};

describe("MemoryGovernanceService (CW-05A/B/C)", () => {
  it("enforces operator authorization for sharing and promotion review", async () => {
    const gov = new MemoryGovernanceService();
    const grantee: MemorySubject = { tenantId: "t_1", ownerType: "team", ownerId: "team_eng" };

    await expect(
      gov.grantSharing({
        actor: MEMBER,
        resourceId: "res_1",
        tenantId: "t_1",
        partition: PARTITION,
        scope: SCOPE,
        grantee,
        ownershipClass: "team",
      }),
    ).rejects.toThrow("not authorized to manage sharing");

    const candidate = await gov.requestPromotion({
      actor: MEMBER,
      tenantId: "t_1",
      atom: ATOM,
      ownershipClass: "team",
      targetSpaceId: "kb_eng",
    });

    await expect(
      gov.reviewPromotion({
        actor: MEMBER,
        candidateId: candidate.candidateId,
        decision: "approved",
      }),
    ).rejects.toThrow("lacks approval authority");
  });

  it("persists governance state across restarts and separates approval from Knowledge SDK publication", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cw-gov-"));
    const storagePath = join(dir, "governance.json");
    try {
      const gov1 = new MemoryGovernanceService({ storagePath });
      const candidate = await gov1.requestPromotion({
        actor: MEMBER,
        tenantId: "t_1",
        atom: ATOM,
        ownershipClass: "team",
        targetSpaceId: "kb_eng",
      });
      const approved = await gov1.reviewPromotion({
        actor: SPACE_ADMIN,
        candidateId: candidate.candidateId,
        decision: "approved",
        reason: "verified",
      });
      expect(approved.status).toBe("approved");

      const withdrawnAssets: string[] = [];
      const publisher = {
        publishAtom: async () => ({ assetId: "kb_asset_99" }),
        withdrawAsset: async (assetId: string) => {
          withdrawnAssets.push(assetId);
        },
      };

      const published = await gov1.publishPromotion({
        actor: SPACE_ADMIN,
        candidateId: candidate.candidateId,
        atom: ATOM,
        publisher,
      });
      expect(published.status).toBe("published");
      expect(published.publishedAssetId).toBe("kb_asset_99");

      // Reload in fresh instance
      const gov2 = new MemoryGovernanceService({ storagePath });
      const reloaded = await gov2.getPromotionCandidate(candidate.candidateId);
      expect(reloaded?.status).toBe("published");

      const withdrawn = await gov2.withdrawPromotion({
        actor: TENANT_ADMIN,
        candidateId: candidate.candidateId,
        publisher,
        reason: "superseded",
      });
      expect(withdrawn.status).toBe("withdrawn");
      expect(withdrawnAssets).toEqual(["kb_asset_99"]);

      const audits = await gov2.listAuditEvents();
      expect(audits.every((a) => Boolean(a.correlationId && a.traceId && a.policyVersion))).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("isolates private user bindings from other users in same tenant", async () => {
    const gov = new MemoryGovernanceService();
    const owner: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "u_1" };
    const other: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "u_2" };
    const binding = createMemorySubjectBinding({
      partition: PARTITION,
      scope: SCOPE,
      subject: owner,
    });
    expect(
      await gov.authorizeAccess({
        bindings: [binding],
        partition: PARTITION,
        caller: other,
        actor: MEMBER,
      }),
    ).toBe(false);
  });
});
