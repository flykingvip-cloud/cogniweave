import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { CogniWeaveEngine } from "../contracts.js";
import { computeScopeFingerprint } from "../keys.js";
import type {
  CognitivePackage,
  MemoryAtom,
  MemorySubject,
  MemorySubjectBinding,
  Scope,
  TaskFrame,
} from "../models.js";
import { validateScope } from "../scope.js";
import { authorizeMemoryAccess, isLiveMemorySubjectBinding } from "../subject/binding.js";

export type MemoryResourceType =
  | "agent_private_memory"
  | "user_memory"
  | "seat_memory"
  | "team_memory"
  | "organization_memory"
  | "task_memory";

export interface MemoryResourceDescriptor {
  resourceId: string;
  resourceType: MemoryResourceType;
  tenantId: string;
  ownerType: MemorySubject["ownerType"];
  ownerId: string;
  subjectBindingId: string;
  scope: Scope;
  visibility: Scope["visibility"];
  privacyLevel: "private" | "shared" | "org" | "public";
  lifecycleStatus: "active" | "revoked" | "archived";
  supportedAtomTypes: string[];
  capabilities: string[];
  sourceAuthority: string;
  freshness?: string;
  evidenceSupport: boolean;
  policyReference?: string;
  version: number;
  updatedAt: string;
}

export type MemoryResourceDomainEventType =
  | "memory.resource.registered"
  | "memory.resource.updated"
  | "memory.resource.access.revoked"
  | "memory.evidence.invalidated";

export interface MemoryResourceDomainEvent {
  eventId: string;
  eventType: MemoryResourceDomainEventType;
  tenantId: string;
  subjectId: string;
  resourceId: string;
  aggregateVersion: number;
  occurredAt: string;
  policyVersion: string;
  correlationId: string;
  traceId: string;
}

export interface ResourceAccessContext {
  userId: string;
  tenantId: string;
  agentId: string;
  allowedResourceTypes?: MemoryResourceType[];
  knowledgePolicyAllows?: boolean;
  callerSubject: MemorySubject;
  bindings: ReadonlyArray<MemorySubjectBinding>;
  partition: MemorySubjectBinding["partition"];
  correlationId?: string;
  traceId?: string;
}

export interface ResourceAccessDecision {
  allowed: boolean;
  denyReason?: string;
}

const EXPECTED_OWNER_TYPE: Partial<Record<MemoryResourceType, MemorySubject["ownerType"]>> = {
  agent_private_memory: "agent",
  user_memory: "user",
  seat_memory: "seat",
  team_memory: "team",
  organization_memory: "organization",
};

type PersistedResourceState = {
  resources: MemoryResourceDescriptor[];
  outboxEvents: MemoryResourceDomainEvent[];
};

/**
 * CW-06 CogniWeaveMemoryResourceAdapter.
 * - Validates descriptor consistency at registration (R-05)
 * - Enforces strong subjectBindingId binding in checkAccess() (R-03)
 * - Locks TaskFrame.scope to resource.scope in retrieveCognitivePackage() (R-02)
 * - Verifies evidence belongs to authorized resource scope/atoms (R-04)
 * - Supports durable persistence & explicit outbox acknowledgment (R-01, R-06)
 * - Supports revocation callback propagation (R-07)
 */
export class CogniWeaveMemoryResourceAdapter {
  private readonly resources = new Map<string, MemoryResourceDescriptor>();
  private readonly outboxEvents: MemoryResourceDomainEvent[] = [];
  private loadPromise: Promise<void> | null = null;
  private readonly storagePath?: string;
  private readonly onRevoke?: (resource: MemoryResourceDescriptor) => Promise<void> | void;

  constructor(
    private readonly engine: CogniWeaveEngine,
    options?: {
      storagePath?: string;
      onRevoke?: (resource: MemoryResourceDescriptor) => Promise<void> | void;
    },
  ) {
    this.storagePath = options?.storagePath;
    this.onRevoke = options?.onRevoke;
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
      const parsed = JSON.parse(raw) as PersistedResourceState;
      for (const r of parsed.resources ?? []) {
        this.resources.set(r.resourceId, r);
      }
      this.outboxEvents.push(...(parsed.outboxEvents ?? []));
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
    const payload: PersistedResourceState = {
      resources: [...this.resources.values()],
      outboxEvents: this.outboxEvents,
    };
    await writeFile(tmp, JSON.stringify(payload, null, 2), "utf8");
    await rename(tmp, this.storagePath);
  }

  async registerResource(
    descriptor: Omit<MemoryResourceDescriptor, "version" | "updatedAt"> & {
      version?: number;
      updatedAt?: string;
    },
    ctx?: { correlationId?: string; traceId?: string; policyVersion?: string },
  ): Promise<MemoryResourceDescriptor> {
    await this.ensureLoaded();
    validateScope(descriptor.scope);
    if (!descriptor.subjectBindingId.trim()) {
      throw new Error("registerResource requires a non-empty subjectBindingId");
    }
    const expectedOwner = EXPECTED_OWNER_TYPE[descriptor.resourceType];
    if (expectedOwner && descriptor.ownerType !== expectedOwner) {
      throw new Error(
        `Resource type ${descriptor.resourceType} requires ownerType=${expectedOwner}, got ${descriptor.ownerType}`,
      );
    }
    if (descriptor.visibility === "private" && descriptor.privacyLevel !== "private") {
      throw new Error("Private visibility resource must use privacyLevel=private");
    }
    if (descriptor.privacyLevel === "private" && descriptor.visibility !== "private") {
      throw new Error("Private privacyLevel resource must use visibility=private");
    }

    const existing = this.resources.get(descriptor.resourceId);
    const version = existing ? existing.version + 1 : (descriptor.version ?? 1);
    const saved: MemoryResourceDescriptor = {
      ...descriptor,
      version,
      updatedAt: descriptor.updatedAt ?? new Date().toISOString(),
    };
    this.resources.set(saved.resourceId, saved);
    this.emitEvent(
      existing ? "memory.resource.updated" : "memory.resource.registered",
      saved,
      ctx,
    );
    await this.persist();
    return saved;
  }

  async listResources(tenantId?: string): Promise<MemoryResourceDescriptor[]> {
    await this.ensureLoaded();
    const all = [...this.resources.values()];
    return tenantId ? all.filter((r) => r.tenantId === tenantId) : all;
  }

  async describeResource(resourceId: string): Promise<MemoryResourceDescriptor | undefined> {
    await this.ensureLoaded();
    return this.resources.get(resourceId);
  }

  async discoverResources(ctx: ResourceAccessContext): Promise<MemoryResourceDescriptor[]> {
    const list = await this.listResources(ctx.tenantId);
    const allowed: MemoryResourceDescriptor[] = [];
    for (const resource of list) {
      if ((await this.checkAccess(resource.resourceId, ctx)).allowed) {
        allowed.push(resource);
      }
    }
    return allowed;
  }

  async checkAccess(resourceId: string, ctx: ResourceAccessContext): Promise<ResourceAccessDecision> {
    await this.ensureLoaded();
    const resource = this.resources.get(resourceId);
    if (!resource) {
      return { allowed: false, denyReason: "resource_not_found" };
    }
    if (!ctx.userId.trim()) {
      return { allowed: false, denyReason: "missing_user_id" };
    }
    if (resource.tenantId !== ctx.tenantId || ctx.callerSubject.tenantId !== ctx.tenantId) {
      return { allowed: false, denyReason: "tenant_mismatch" };
    }
    if (ctx.knowledgePolicyAllows === false) {
      return { allowed: false, denyReason: "knowledge_policy_denied" };
    }
    if (ctx.allowedResourceTypes && !ctx.allowedResourceTypes.includes(resource.resourceType)) {
      return { allowed: false, denyReason: "agent_scope_denied" };
    }
    if (resource.lifecycleStatus !== "active") {
      return { allowed: false, denyReason: `resource_${resource.lifecycleStatus}` };
    }
    if (
      resource.privacyLevel === "private" &&
      !(resource.ownerType === "user" && resource.ownerId === ctx.userId) &&
      !(resource.ownerType === "agent" && resource.ownerId === ctx.agentId)
    ) {
      return { allowed: false, denyReason: "privacy_policy_denied" };
    }

    // R-03: Strong subjectBindingId validation against live bindings & resource scope.
    const bound = ctx.bindings.find((b) => b.id === resource.subjectBindingId);
    if (!bound || !isLiveMemorySubjectBinding(bound)) {
      return { allowed: false, denyReason: "resource_binding_missing_or_unbound" };
    }
    if (
      computeScopeFingerprint(bound.scope) !== computeScopeFingerprint(resource.scope) ||
      bound.subject.tenantId !== resource.tenantId ||
      bound.subject.ownerType !== resource.ownerType ||
      bound.subject.ownerId !== resource.ownerId
    ) {
      return { allowed: false, denyReason: "resource_binding_mismatch" };
    }

    const acl = authorizeMemoryAccess(ctx.bindings, {
      partition: ctx.partition,
      caller: ctx.callerSubject,
    });
    if (!acl.allowed) {
      return { allowed: false, denyReason: acl.reason ?? "subject_binding_denied" };
    }
    return { allowed: true };
  }

  async retrieveCognitivePackage(
    resourceId: string,
    taskFrame: TaskFrame,
    ctx: ResourceAccessContext,
  ): Promise<CognitivePackage> {
    await this.ensureLoaded();
    const access = await this.checkAccess(resourceId, ctx);
    if (!access.allowed) {
      throw new Error(`Memory resource access denied: ${access.denyReason}`);
    }
    const resource = this.resources.get(resourceId)!;
    // R-02: Lock TaskFrame.scope & requiredAtomTypes to the authorized resource boundaries.
    const scopedFrame: TaskFrame = {
      ...taskFrame,
      scope: { ...resource.scope },
      requiredAtomTypes:
        resource.supportedAtomTypes.length > 0
          ? taskFrame.requiredAtomTypes.filter((t) => resource.supportedAtomTypes.includes(t))
          : taskFrame.requiredAtomTypes,
    };
    return this.engine.reason(scopedFrame);
  }

  async retrieveAtoms(
    resourceId: string,
    ctx: ResourceAccessContext,
    atomTypes?: string[],
  ): Promise<MemoryAtom[]> {
    await this.ensureLoaded();
    const access = await this.checkAccess(resourceId, ctx);
    if (!access.allowed) {
      throw new Error(`Memory resource access denied: ${access.denyReason}`);
    }
    const resource = this.resources.get(resourceId)!;
    const allowedTypes = atomTypes
      ? atomTypes.filter(
          (t) => resource.supportedAtomTypes.length === 0 || resource.supportedAtomTypes.includes(t),
        )
      : resource.supportedAtomTypes.length > 0
        ? resource.supportedAtomTypes
        : undefined;
    const hits = await this.engine.queryAtoms({
      scope: resource.scope,
      caller: ctx.callerSubject,
      filter: allowedTypes ? { atomTypes: allowedTypes } : undefined,
    });
    return hits.map((h) => h.atom);
  }

  async resolveEvidence(
    resourceId: string,
    evidenceId: string,
    ctx: ResourceAccessContext,
  ): Promise<unknown> {
    await this.ensureLoaded();
    const access = await this.checkAccess(resourceId, ctx);
    if (!access.allowed) {
      throw new Error(`Memory resource access denied: ${access.denyReason}`);
    }
    const resource = this.resources.get(resourceId)!;
    // R-04: Verify evidenceId is referenced by at least one authorized atom in this resource.
    const authorizedAtoms = await this.retrieveAtoms(resourceId, ctx);
    const hasLink = authorizedAtoms.some((a) => a.provenance.evidenceRefs.includes(evidenceId));
    if (!hasLink) {
      throw new Error(`Evidence ${evidenceId} is not bound to authorized atoms in resource ${resourceId}`);
    }
    return this.engine.resolveEvidence({
      evidenceId,
      includeContent: true,
      scope: resource.scope,
    });
  }

  async getResourceStatus(
    resourceId: string,
  ): Promise<MemoryResourceDescriptor["lifecycleStatus"] | "not_found"> {
    await this.ensureLoaded();
    return this.resources.get(resourceId)?.lifecycleStatus ?? "not_found";
  }

  authorizeResourceManagement(
    resource: MemoryResourceDescriptor,
    actor: {
      userId: string;
      tenantId: string;
      roles?: string[];
      subject?: { tenantId: string; ownerType: MemorySubject["ownerType"]; ownerId: string };
    },
  ): boolean {
    // Tenant/Workspace admin roles alone cannot bypass Canonical Ownership.
    if (actor.tenantId !== resource.tenantId) return false;
    if (resource.ownerType === "user" && resource.ownerId === actor.userId) return true;
    if (
      actor.subject &&
      actor.subject.tenantId === resource.tenantId &&
      actor.subject.ownerType === resource.ownerType &&
      actor.subject.ownerId === resource.ownerId
    ) {
      return true;
    }
    return false;
  }

  async revokeAccess(
    resourceId: string,
    actor: {
      userId: string;
      tenantId: string;
      roles?: string[];
      subject?: { tenantId: string; ownerType: MemorySubject["ownerType"]; ownerId: string };
    },
    ctx?: { correlationId?: string; traceId?: string; policyVersion?: string },
  ): Promise<MemoryResourceDescriptor> {
    await this.ensureLoaded();
    const existing = this.resources.get(resourceId);
    if (!existing) {
      throw new Error(`Memory resource not found: ${resourceId}`);
    }
    if (!this.authorizeResourceManagement(existing, actor)) {
      throw new Error(`Actor ${actor.userId} is not authorized to revoke resource ${resourceId}`);
    }
    // Idempotent repeat revocation
    if (existing.lifecycleStatus === "revoked") {
      return existing;
    }
    const updated: MemoryResourceDescriptor = {
      ...existing,
      lifecycleStatus: "revoked",
      version: existing.version + 1,
      updatedAt: new Date().toISOString(),
    };
    // CW-08-06: Persist canonical revoked state + outbox event BEFORE external propagation.
    this.resources.set(resourceId, updated);
    this.emitEvent("memory.resource.access.revoked", updated, ctx);
    await this.persist();
    return updated;
  }

  /**
   * CW-08-06: Transactional Outbox consumer dispatcher.
   * Only acknowledges events after the external consumer succeeds; failed events remain in outbox for retry.
   */
  async dispatchOutboxEvents(
    consumer: (event: MemoryResourceDomainEvent) => Promise<void> | void,
  ): Promise<{ delivered: number; failed: number }> {
    const pending = await this.peekDomainEvents();
    let delivered = 0;
    let failed = 0;
    const acked: string[] = [];
    for (const event of pending) {
      try {
        if (event.eventType === "memory.resource.access.revoked" && this.onRevoke) {
          const res = this.resources.get(event.resourceId);
          if (res) await this.onRevoke(res);
        }
        await consumer(event);
        acked.push(event.eventId);
        delivered += 1;
      } catch {
        failed += 1;
      }
    }
    if (acked.length > 0) {
      await this.acknowledgeDomainEvents(acked);
    }
    return { delivered, failed };
  }

  async peekDomainEvents(): Promise<MemoryResourceDomainEvent[]> {
    await this.ensureLoaded();
    return [...this.outboxEvents];
  }

  async acknowledgeDomainEvents(eventIds: ReadonlyArray<string>): Promise<number> {
    await this.ensureLoaded();
    const ackSet = new Set(eventIds);
    const before = this.outboxEvents.length;
    const remaining = this.outboxEvents.filter((e) => !ackSet.has(e.eventId));
    this.outboxEvents.splice(0, this.outboxEvents.length, ...remaining);
    const removed = before - remaining.length;
    if (removed > 0) {
      await this.persist();
    }
    return removed;
  }

  private emitEvent(
    eventType: MemoryResourceDomainEventType,
    resource: MemoryResourceDescriptor,
    ctx?: { correlationId?: string; traceId?: string; policyVersion?: string },
  ): void {
    this.outboxEvents.push({
      eventId: `evt_${randomUUID().slice(0, 12)}`,
      eventType,
      tenantId: resource.tenantId,
      subjectId: resource.ownerId,
      resourceId: resource.resourceId,
      aggregateVersion: resource.version,
      occurredAt: resource.updatedAt,
      policyVersion: ctx?.policyVersion ?? "1.0.0",
      correlationId: ctx?.correlationId ?? randomUUID(),
      traceId: ctx?.traceId ?? randomUUID(),
    });
  }
}
