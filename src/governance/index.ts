import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { MemoryAtom, MemorySubject, MemorySubjectBinding, Scope } from "../models.js";
import {
  authorizeMemoryAccess,
  createMemorySubjectBinding,
  markMemorySubjectBindingUnbound,
} from "../subject/binding.js";

export type PromotionCandidateStatus =
  | "pending"
  | "approved"
  | "published"
  | "rejected"
  | "withdrawn";

export type MemoryOwnershipClass =
  | "personal"
  | "agent_private"
  | "seat"
  | "team"
  | "organization"
  | "task";

export type GovernanceRole = "tenant_admin" | "space_admin" | "governance_reviewer" | "member";

export interface GovernanceActorContext {
  userId: string;
  tenantId: string;
  roles: GovernanceRole[];
  ownedResourceIds?: string[];
  adminSpaceIds?: string[];
  correlationId?: string;
  traceId?: string;
}

export interface KnowledgePublisher {
  publishAtom(input: {
    candidate: PromotionCandidate;
    atom: MemoryAtom;
  }): Promise<{ assetId: string }>;
  withdrawAsset?(assetId: string, reason?: string): Promise<void>;
}

export interface PromotionCandidate {
  candidateId: string;
  tenantId: string;
  atomId: string;
  ownershipClass: MemoryOwnershipClass;
  requestedByUserId: string;
  targetSpaceId: string;
  evidenceRefs: string[];
  approvedAtomVersion?: number;
  approvedEvidenceDigest?: string;
  status: PromotionCandidateStatus;
  reviewedByUserId?: string;
  publishedAssetId?: string;
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
    | "promotion.published"
    | "promotion.rejected"
    | "promotion.withdrawn"
    | "access.denied";
  targetId: string;
  policyVersion: string;
  correlationId: string;
  traceId: string;
  beforeState?: string;
  afterState?: string;
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

type PersistedGovernanceState = {
  promotions: PromotionCandidate[];
  auditLog: GovernanceAuditEvent[];
};

/**
 * CW-05 Enterprise Memory Governance Service.
 * - Enforces operator authorization (CW-05A)
 * - Supports durable file-backed persistence (CW-05B)
 * - Separates approval from Knowledge SDK publication & supports withdrawal propagation (CW-05C)
 */
export class MemoryGovernanceService {
  private readonly auditLog: GovernanceAuditEvent[] = [];
  private readonly promotions = new Map<string, PromotionCandidate>();
  private loadPromise: Promise<void> | null = null;
  private readonly policyVersion: string;
  private readonly storagePath?: string;

  constructor(options?: { storagePath?: string; policyVersion?: string }) {
    this.storagePath = options?.storagePath;
    this.policyVersion = options?.policyVersion ?? "1.0.0";
  }

  private ensureLoaded(): Promise<void> {
    if (!this.storagePath) return Promise.resolve();
    if (!this.loadPromise) {
      this.loadPromise = this.loadFromDisk();
    }
    return this.loadPromise;
  }

  private async loadFromDisk(): Promise<void> {
    if (!this.storagePath) return;
    try {
      const raw = await readFile(this.storagePath, "utf8");
      const parsed = JSON.parse(raw) as PersistedGovernanceState;
      for (const p of parsed.promotions ?? []) {
        this.promotions.set(p.candidateId, p);
      }
      this.auditLog.push(...(parsed.auditLog ?? []));
    } catch (err) {
      if ((err as NodeJS.ErrnoException | null)?.code === "ENOENT") return;
      this.loadPromise = null;
      throw err;
    }
  }

  private async persist(): Promise<void> {
    if (!this.storagePath) return;
    await mkdir(dirname(this.storagePath), { recursive: true });
    const tmp = `${this.storagePath}.tmp.${randomUUID().slice(0, 8)}`;
    const payload: PersistedGovernanceState = {
      promotions: [...this.promotions.values()],
      auditLog: this.auditLog,
    };
    await writeFile(tmp, JSON.stringify(payload, null, 2), "utf8");
    await rename(tmp, this.storagePath);
  }

  private assertSharingOperator(
    actor: GovernanceActorContext,
    tenantId: string,
    resourceId: string,
  ): void {
    const allowed =
      actor.tenantId === tenantId &&
      (actor.roles.includes("tenant_admin") ||
        (actor.ownedResourceIds?.includes(resourceId) ?? false));
    if (!allowed) {
      this.recordAudit(tenantId, actor, "access.denied", resourceId, undefined, undefined, "operator_unauthorized_for_sharing");
      throw new Error(`Operator ${actor.userId} is not authorized to manage sharing for ${resourceId}`);
    }
  }

  async listAuditEvents(): Promise<GovernanceAuditEvent[]> {
    await this.ensureLoaded();
    return [...this.auditLog];
  }

  async getPromotionCandidate(candidateId: string): Promise<PromotionCandidate | undefined> {
    await this.ensureLoaded();
    return this.promotions.get(candidateId);
  }

  async grantSharing(params: {
    actor: GovernanceActorContext;
    resourceId: string;
    tenantId: string;
    partition: MemorySubjectBinding["partition"];
    scope: Scope;
    grantee: MemorySubject;
    ownershipClass: MemoryOwnershipClass;
    now?: string;
  }): Promise<SharingGrantResult> {
    await this.ensureLoaded();
    this.assertSharingOperator(params.actor, params.tenantId, params.resourceId);

    if (params.ownershipClass === "personal" || params.ownershipClass === "agent_private") {
      this.recordAudit(params.tenantId, params.actor, "access.denied", params.grantee.ownerId, undefined, undefined, "personal_or_agent_private_cannot_be_shared");
      await this.persist();
      throw new Error(`Cannot share ${params.ownershipClass} memory without explicit reclassification`);
    }
    if (params.grantee.tenantId !== params.tenantId) {
      this.recordAudit(params.tenantId, params.actor, "access.denied", params.grantee.ownerId, undefined, undefined, "cross_tenant_grant_forbidden");
      await this.persist();
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
      params.actor,
      "sharing.granted",
      binding.id,
      "unbound",
      "bound",
      undefined,
      params.now,
    );
    await this.persist();
    return { binding, audit };
  }

  async revokeSharing(params: {
    actor: GovernanceActorContext;
    resourceId: string;
    binding: MemorySubjectBinding;
    reason?: string;
    now?: string;
  }): Promise<SharingRevokeResult> {
    await this.ensureLoaded();
    this.assertSharingOperator(params.actor, params.binding.subject.tenantId, params.resourceId);

    const unbound = markMemorySubjectBindingUnbound(params.binding, params.now);
    const audit = this.recordAudit(
      params.binding.subject.tenantId,
      params.actor,
      "sharing.revoked",
      unbound.id,
      "bound",
      "unbound",
      params.reason,
      params.now,
    );
    await this.persist();
    return { binding: unbound, audit };
  }

  async authorizeAccess(params: {
    bindings: ReadonlyArray<MemorySubjectBinding>;
    partition: MemorySubjectBinding["partition"];
    caller: MemorySubject;
    actor: GovernanceActorContext;
  }): Promise<boolean> {
    await this.ensureLoaded();
    const res = authorizeMemoryAccess(params.bindings, {
      partition: params.partition,
      caller: params.caller,
    });
    if (!res.allowed) {
      this.recordAudit(
        params.caller.tenantId,
        params.actor,
        "access.denied",
        params.caller.ownerId,
        undefined,
        undefined,
        res.reason,
      );
      await this.persist();
    }
    return res.allowed;
  }

  async requestPromotion(params: {
    actor: GovernanceActorContext;
    tenantId: string;
    atom: MemoryAtom;
    ownershipClass: MemoryOwnershipClass;
    targetSpaceId: string;
    now?: string;
  }): Promise<PromotionCandidate> {
    await this.ensureLoaded();
    if (params.actor.tenantId !== params.tenantId) {
      throw new Error("Cross-tenant promotion request forbidden");
    }
    if (
      params.ownershipClass === "personal" ||
      params.ownershipClass === "agent_private" ||
      params.ownershipClass === "task"
    ) {
      this.recordAudit(
        params.tenantId,
        params.actor,
        "access.denied",
        params.atom.id,
        undefined,
        undefined,
        `auto_or_direct_promotion_blocked:${params.ownershipClass}`,
      );
      await this.persist();
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
      requestedByUserId: params.actor.userId,
      targetSpaceId: params.targetSpaceId,
      evidenceRefs: [...params.atom.provenance.evidenceRefs],
      status: "pending",
      createdAt: now,
      updatedAt: now,
    };
    this.promotions.set(candidate.candidateId, candidate);
    this.recordAudit(
      params.tenantId,
      params.actor,
      "promotion.requested",
      candidate.candidateId,
      undefined,
      "pending",
      undefined,
      now,
    );
    await this.persist();
    return candidate;
  }

  async reviewPromotion(params: {
    actor: GovernanceActorContext;
    candidateId: string;
    decision: "approved" | "rejected";
    approvedAtom?: MemoryAtom;
    approvedAtomVersion?: number;
    reason?: string;
    now?: string;
  }): Promise<PromotionCandidate> {
    await this.ensureLoaded();
    const existing = this.promotions.get(params.candidateId);
    if (!existing) throw new Error(`Promotion candidate not found: ${params.candidateId}`);

    const canReview =
      params.actor.tenantId === existing.tenantId &&
      (params.actor.roles.includes("tenant_admin") ||
        (params.actor.roles.includes("space_admin") &&
          (params.actor.adminSpaceIds?.includes(existing.targetSpaceId) ?? false)));
    if (!canReview) {
      this.recordAudit(
        existing.tenantId,
        params.actor,
        "access.denied",
        existing.candidateId,
        existing.status,
        existing.status,
        "reviewer_not_authorized_for_target_space",
      );
      await this.persist();
      throw new Error(`Reviewer ${params.actor.userId} lacks approval authority for space ${existing.targetSpaceId}`);
    }
    if (existing.status !== "pending") {
      throw new Error(`Promotion candidate ${params.candidateId} is already ${existing.status}`);
    }

    const approvedVersion = params.approvedAtom?.versioning.version ?? params.approvedAtomVersion;
    if (params.decision === "approved" && approvedVersion === undefined) {
      throw new Error("Approving a promotion requires approvedAtom or approvedAtomVersion");
    }
    const evidenceForDigest = params.approvedAtom?.provenance.evidenceRefs ?? existing.evidenceRefs;
    const approvedEvidenceDigest = createHash("sha256")
      .update(JSON.stringify([...evidenceForDigest].toSorted()))
      .digest("hex")
      .slice(0, 32);

    const now = params.now ?? new Date().toISOString();
    const updated: PromotionCandidate = {
      ...existing,
      status: params.decision,
      reviewedByUserId: params.actor.userId,
      ...(params.decision === "approved"
        ? { approvedAtomVersion: approvedVersion, approvedEvidenceDigest }
        : {}),
      decisionReason: params.reason,
      updatedAt: now,
    };
    this.promotions.set(updated.candidateId, updated);
    this.recordAudit(
      existing.tenantId,
      params.actor,
      params.decision === "approved" ? "promotion.approved" : "promotion.rejected",
      updated.candidateId,
      "pending",
      params.decision,
      params.reason,
      now,
    );
    await this.persist();
    return updated;
  }

  async publishPromotion(params: {
    actor: GovernanceActorContext;
    candidateId: string;
    atom: MemoryAtom;
    publisher: KnowledgePublisher;
    now?: string;
  }): Promise<PromotionCandidate> {
    await this.ensureLoaded();
    const existing = this.promotions.get(params.candidateId);
    if (!existing) throw new Error(`Promotion candidate not found: ${params.candidateId}`);

    const canPublish =
      params.actor.tenantId === existing.tenantId &&
      (params.actor.roles.includes("tenant_admin") ||
        (params.actor.roles.includes("space_admin") &&
          (params.actor.adminSpaceIds?.includes(existing.targetSpaceId) ?? false)));
    if (!canPublish) {
      this.recordAudit(
        existing.tenantId,
        params.actor,
        "access.denied",
        existing.candidateId,
        existing.status,
        existing.status,
        "publisher_not_authorized_for_target_space",
      );
      await this.persist();
      throw new Error(`Actor ${params.actor.userId} lacks publish authority for space ${existing.targetSpaceId}`);
    }
    if (existing.status !== "approved") {
      throw new Error(`Candidate ${params.candidateId} must be approved before publishing (status=${existing.status})`);
    }
    if (params.atom.id !== existing.atomId) {
      throw new Error(`Atom mismatch: expected ${existing.atomId}, got ${params.atom.id}`);
    }
    if (existing.approvedAtomVersion === undefined || !existing.approvedEvidenceDigest) {
      throw new Error("Promotion candidate is missing mandatory approval version/evidence fingerprint");
    }
    if (params.atom.versioning.version !== existing.approvedAtomVersion) {
      throw new Error(
        `Atom version mismatch: approved version ${existing.approvedAtomVersion}, got ${params.atom.versioning.version}`,
      );
    }
    const currentEvidenceDigest = createHash("sha256")
      .update(JSON.stringify([...(params.atom.provenance?.evidenceRefs ?? [])].toSorted()))
      .digest("hex")
      .slice(0, 32);
    if (currentEvidenceDigest !== existing.approvedEvidenceDigest) {
      throw new Error("Evidence fingerprint changed since approval; re-approval required");
    }
    if (params.atom.state.status !== "active") {
      throw new Error(`Cannot publish non-active atom (status=${params.atom.state.status})`);
    }

    const { assetId } = await params.publisher.publishAtom({
      candidate: existing,
      atom: params.atom,
    });
    const now = params.now ?? new Date().toISOString();
    const updated: PromotionCandidate = {
      ...existing,
      status: "published",
      publishedAssetId: assetId,
      updatedAt: now,
    };
    this.promotions.set(updated.candidateId, updated);
    this.recordAudit(
      existing.tenantId,
      params.actor,
      "promotion.published",
      updated.candidateId,
      "approved",
      `published:${assetId}`,
      undefined,
      now,
    );
    await this.persist();
    return updated;
  }

  async withdrawPromotion(params: {
    actor: GovernanceActorContext;
    candidateId: string;
    publisher?: KnowledgePublisher;
    reason?: string;
    now?: string;
  }): Promise<PromotionCandidate> {
    await this.ensureLoaded();
    const existing = this.promotions.get(params.candidateId);
    if (!existing) throw new Error(`Promotion candidate not found: ${params.candidateId}`);
    const canWithdraw =
      params.actor.tenantId === existing.tenantId &&
      (params.actor.roles.includes("tenant_admin") ||
        (params.actor.roles.includes("space_admin") &&
          (params.actor.adminSpaceIds?.includes(existing.targetSpaceId) ?? false)) ||
        (existing.status !== "published" && existing.requestedByUserId === params.actor.userId));
    if (!canWithdraw) {
      this.recordAudit(
        existing.tenantId,
        params.actor,
        "access.denied",
        existing.candidateId,
        existing.status,
        existing.status,
        "actor_not_authorized_to_withdraw",
      );
      await this.persist();
      throw new Error(`Actor ${params.actor.userId} is not authorized to withdraw ${params.candidateId}`);
    }
    if (existing.publishedAssetId && params.publisher?.withdrawAsset) {
      await params.publisher.withdrawAsset(existing.publishedAssetId, params.reason);
    }

    const now = params.now ?? new Date().toISOString();
    const updated: PromotionCandidate = {
      ...existing,
      status: "withdrawn",
      decisionReason: params.reason,
      updatedAt: now,
    };
    this.promotions.set(updated.candidateId, updated);
    this.recordAudit(
      existing.tenantId,
      params.actor,
      "promotion.withdrawn",
      updated.candidateId,
      existing.status,
      "withdrawn",
      params.reason,
      now,
    );
    await this.persist();
    return updated;
  }

  private recordAudit(
    tenantId: string,
    actor: GovernanceActorContext,
    action: GovernanceAuditEvent["action"],
    targetId: string,
    beforeState?: string,
    afterState?: string,
    reason?: string,
    occurredAt = new Date().toISOString(),
  ): GovernanceAuditEvent {
    const event: GovernanceAuditEvent = {
      auditId: `aud_${randomUUID().slice(0, 12)}`,
      tenantId,
      actorUserId: actor.userId,
      action,
      targetId,
      policyVersion: this.policyVersion,
      correlationId: actor.correlationId ?? randomUUID(),
      traceId: actor.traceId ?? randomUUID(),
      ...(beforeState ? { beforeState } : {}),
      ...(afterState ? { afterState } : {}),
      ...(reason ? { reason } : {}),
      occurredAt,
    };
    this.auditLog.push(event);
    return event;
  }
}
