import { randomUUID } from "node:crypto";
import type { MemoryAtom, MemorySubject, MemorySubjectBinding, Scope } from "../models.js";
import { authorizeMemoryAccess, createMemorySubjectBinding, markMemorySubjectBindingUnbound } from "../subject/binding.js";

export type PromotionCandidateStatus = "pending" | "approved" | "rejected" | "withdrawn";

export type MemoryOwnershipClass =
  | "personal"
  | "agent_private"
  | "seat"
  | "team"
  | "organization"
  | "task";

export interface PromotionCandidate {
  candidateId: string;
  tenantId: string;
  atomId: string;
  ownershipClass: MemoryOwnershipClass;
  requestedByUserId: string;
  targetSpaceId: string;
  evidenceRefs: string[];
  status: PromotionCandidateStatus;
  reviewedByUserId?: string;
  decisionReason?: string;
  createdAt: string;
  updatedAt: string;
}

export interface GovernanceAuditEvent {
  auditId: string;
  tenantId: string;
  actorUserId: string;
  action:
    | "sharing.granted"
    | "sharing.revoked"
    | "promotion.requested"
    | "promotion.approved"
    | "promotion.rejected"
    | "promotion.withdrawn"
    | "access.denied";
  targetId: string;
  reason?: string;
  occurredAt: string;
}

export interface SharingGrantResult {
  binding: MemorySubjectBinding;
  audit: GovernanceAuditEvent;
}

export interface SharingRevokeResult {
  binding: MemorySubjectBinding;
  audit: GovernanceAuditEvent;
}

/**
 * CW-05 Enterprise Memory Governance Store.
 * Manages controlled sharing grants/revocations, personal memory isolation,
 * and promotion candidate approval/withdrawal workflows.
 */
export class MemoryGovernanceService {
  private readonly auditLog: GovernanceAuditEvent[] = [];
  private readonly promotions = new Map<string, PromotionCandidate>();

  listAuditEvents(): GovernanceAuditEvent[] {
    return [...this.auditLog];
  }

  getPromotionCandidate(candidateId: string): PromotionCandidate | undefined {
    return this.promotions.get(candidateId);
  }

  grantSharing(params: {
    actorUserId: string;
    tenantId: string;
    partition: MemorySubjectBinding["partition"];
    scope: Scope;
    grantee: MemorySubject;
    ownershipClass: MemoryOwnershipClass;
    now?: string;
  }): SharingGrantResult {
    if (params.ownershipClass === "personal" || params.ownershipClass === "agent_private") {
      this.recordAudit(params.tenantId, params.actorUserId, "access.denied", params.grantee.ownerId, "personal_or_agent_private_cannot_be_shared");
      throw new Error(`Cannot share ${params.ownershipClass} memory without explicit reclassification`);
    }
    if (params.grantee.tenantId !== params.tenantId) {
      this.recordAudit(params.tenantId, params.actorUserId, "access.denied", params.grantee.ownerId, "cross_tenant_grant_forbidden");
      throw new Error("Cross-tenant sharing grant is forbidden");
    }

    const binding = createMemorySubjectBinding({
      partition: params.partition,
      scope: { ...params.scope, visibility: "shared" },
      subject: params.grantee,
      scopeType: params.ownershipClass === "seat" ? "seat" : "space",
      now: params.now,
    });
    const audit = this.recordAudit(
      params.tenantId,
      params.actorUserId,
      "sharing.granted",
      binding.id,
      undefined,
      params.now,
    );
    return { binding, audit };
  }

  revokeSharing(params: {
    actorUserId: string;
    binding: MemorySubjectBinding;
    reason?: string;
    now?: string;
  }): SharingRevokeResult {
    const unbound = markMemorySubjectBindingUnbound(params.binding, params.now);
    const audit = this.recordAudit(
      params.binding.subject.tenantId,
      params.actorUserId,
      "sharing.revoked",
      unbound.id,
      params.reason,
      params.now,
    );
    return { binding: unbound, audit };
  }

  authorizeAccess(params: {
    bindings: ReadonlyArray<MemorySubjectBinding>;
    partition: MemorySubjectBinding["partition"];
    caller: MemorySubject;
    actorUserId: string;
  }): boolean {
    const res = authorizeMemoryAccess(params.bindings, {
      partition: params.partition,
      caller: params.caller,
    });
    if (!res.allowed) {
      this.recordAudit(
        params.caller.tenantId,
        params.actorUserId,
        "access.denied",
        params.caller.ownerId,
        res.reason,
      );
    }
    return res.allowed;
  }

  requestPromotion(params: {
    tenantId: string;
    atom: MemoryAtom;
    ownershipClass: MemoryOwnershipClass;
    requestedByUserId: string;
    targetSpaceId: string;
    now?: string;
  }): PromotionCandidate {
    if (
      params.ownershipClass === "personal" ||
      params.ownershipClass === "agent_private" ||
      params.ownershipClass === "task"
    ) {
      this.recordAudit(
        params.tenantId,
        params.requestedByUserId,
        "access.denied",
        params.atom.id,
        `auto_or_direct_promotion_blocked:${params.ownershipClass}`,
      );
      throw new Error(`Promotion blocked by default policy for ${params.ownershipClass} memory`);
    }
    if ((params.atom.provenance?.evidenceRefs?.length ?? 0) === 0) {
      throw new Error("Promotion requires at least one evidence reference");
    }
    if (params.atom.state.status === "deprecated" || params.atom.state.status === "conflicted") {
      throw new Error(`Cannot promote ${params.atom.state.status} memory`);
    }

    const now = params.now ?? new Date().toISOString();
    const candidate: PromotionCandidate = {
      candidateId: `prc_${randomUUID().slice(0, 12)}`,
      tenantId: params.tenantId,
      atomId: params.atom.id,
      ownershipClass: params.ownershipClass,
      requestedByUserId: params.requestedByUserId,
      targetSpaceId: params.targetSpaceId,
      evidenceRefs: [...params.atom.provenance.evidenceRefs],
      status: "pending",
      createdAt: now,
      updatedAt: now,
    };
    this.promotions.set(candidate.candidateId, candidate);
    this.recordAudit(params.tenantId, params.requestedByUserId, "promotion.requested", candidate.candidateId, undefined, now);
    return candidate;
  }

  reviewPromotion(params: {
    candidateId: string;
    reviewerUserId: string;
    decision: "approved" | "rejected";
    reason?: string;
    now?: string;
  }): PromotionCandidate {
    const existing = this.promotions.get(params.candidateId);
    if (!existing) {
      throw new Error(`Promotion candidate not found: ${params.candidateId}`);
    }
    if (existing.status !== "pending") {
      throw new Error(`Promotion candidate ${params.candidateId} is already ${existing.status}`);
    }
    const now = params.now ?? new Date().toISOString();
    const updated: PromotionCandidate = {
      ...existing,
      status: params.decision,
      reviewedByUserId: params.reviewerUserId,
      decisionReason: params.reason,
      updatedAt: now,
    };
    this.promotions.set(updated.candidateId, updated);
    this.recordAudit(
      existing.tenantId,
      params.reviewerUserId,
      params.decision === "approved" ? "promotion.approved" : "promotion.rejected",
      updated.candidateId,
      params.reason,
      now,
    );
    return updated;
  }

  withdrawPromotion(params: {
    candidateId: string;
    actorUserId: string;
    reason?: string;
    now?: string;
  }): PromotionCandidate {
    const existing = this.promotions.get(params.candidateId);
    if (!existing) {
      throw new Error(`Promotion candidate not found: ${params.candidateId}`);
    }
    const now = params.now ?? new Date().toISOString();
    const updated: PromotionCandidate = {
      ...existing,
      status: "withdrawn",
      decisionReason: params.reason,
      updatedAt: now,
    };
    this.promotions.set(updated.candidateId, updated);
    this.recordAudit(existing.tenantId, params.actorUserId, "promotion.withdrawn", updated.candidateId, params.reason, now);
    return updated;
  }

  private recordAudit(
    tenantId: string,
    actorUserId: string,
    action: GovernanceAuditEvent["action"],
    targetId: string,
    reason?: string,
    occurredAt = new Date().toISOString(),
  ): GovernanceAuditEvent {
    const event: GovernanceAuditEvent = {
      auditId: `aud_${randomUUID().slice(0, 12)}`,
      tenantId,
      actorUserId,
      action,
      targetId,
      ...(reason ? { reason } : {}),
      occurredAt,
    };
    this.auditLog.push(event);
    return event;
  }
}
