import { describe, expect, it } from "vitest";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type { MemoryAtom, MemorySubject, Scope } from "../models.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import { MemoryGovernanceService } from "./index.js";

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

describe("MemoryGovernanceService (CW-05)", () => {
  it("blocks sharing personal or agent_private memory and cross-tenant grants", () => {
    const gov = new MemoryGovernanceService();
    const grantee: MemorySubject = { tenantId: "t_1", ownerType: "team", ownerId: "team_eng" };

    expect(() =>
      gov.grantSharing({
        actorUserId: "u_1",
        tenantId: "t_1",
        partition: PARTITION,
        scope: SCOPE,
        grantee,
        ownershipClass: "personal",
      }),
    ).toThrow("Cannot share personal memory");

    expect(() =>
      gov.grantSharing({
        actorUserId: "u_1",
        tenantId: "t_1",
        partition: PARTITION,
        scope: SCOPE,
        grantee: { tenantId: "t_2", ownerType: "team", ownerId: "team_other" },
        ownershipClass: "team",
      }),
    ).toThrow("Cross-tenant sharing grant is forbidden");
  });

  it("grants and revokes team sharing with audit trail", () => {
    const gov = new MemoryGovernanceService();
    const grantee: MemorySubject = { tenantId: "t_1", ownerType: "team", ownerId: "team_eng" };
    const granted = gov.grantSharing({
      actorUserId: "u_1",
      tenantId: "t_1",
      partition: PARTITION,
      scope: SCOPE,
      grantee,
      ownershipClass: "team",
    });

    expect(
      gov.authorizeAccess({
        bindings: [granted.binding],
        partition: PARTITION,
        caller: grantee,
        actorUserId: "u_2",
      }),
    ).toBe(true);

    const revoked = gov.revokeSharing({
      actorUserId: "u_1",
      binding: granted.binding,
      reason: "offboarded",
    });

    expect(
      gov.authorizeAccess({
        bindings: [revoked.binding],
        partition: PARTITION,
        caller: grantee,
        actorUserId: "u_2",
      }),
    ).toBe(false);

    expect(gov.listAuditEvents().map((e) => e.action)).toEqual([
      "sharing.granted",
      "sharing.revoked",
      "access.denied",
    ]);
  });

  it("blocks auto/direct promotion of personal/agent_private/task memory and supports approval/withdrawal", () => {
    const gov = new MemoryGovernanceService();
    expect(() =>
      gov.requestPromotion({
        tenantId: "t_1",
        atom: ATOM,
        ownershipClass: "personal",
        requestedByUserId: "u_1",
        targetSpaceId: "kb_eng",
      }),
    ).toThrow("Promotion blocked by default policy");

    const candidate = gov.requestPromotion({
      tenantId: "t_1",
      atom: ATOM,
      ownershipClass: "team",
      requestedByUserId: "u_1",
      targetSpaceId: "kb_eng",
    });
    expect(candidate.status).toBe("pending");

    const approved = gov.reviewPromotion({
      candidateId: candidate.candidateId,
      reviewerUserId: "u_admin",
      decision: "approved",
      reason: "verified",
    });
    expect(approved.status).toBe("approved");

    const withdrawn = gov.withdrawPromotion({
      candidateId: candidate.candidateId,
      actorUserId: "u_admin",
      reason: "superseded",
    });
    expect(withdrawn.status).toBe("withdrawn");
  });

  it("isolates private user bindings from other users in same tenant", () => {
    const gov = new MemoryGovernanceService();
    const owner: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "u_1" };
    const other: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "u_2" };
    const binding = createMemorySubjectBinding({
      partition: PARTITION,
      scope: SCOPE,
      subject: owner,
    });
    expect(
      gov.authorizeAccess({
        bindings: [binding],
        partition: PARTITION,
        caller: other,
        actorUserId: "u_2",
      }),
    ).toBe(false);
  });
});
