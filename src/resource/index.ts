import { randomUUID } from "node:crypto";
import type { CogniWeaveEngine } from "../contracts.js";
import type {
  CognitivePackage,
  MemoryAtom,
  MemorySubject,
  MemorySubjectBinding,
  Scope,
  TaskFrame,
} from "../models.js";
import { authorizeMemoryAccess } from "../subject/binding.js";

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
  subjectBindingId?: string;
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

/**
 * CW-06 CogniWeaveMemoryResourceAdapter.
 * Exposes governed memory resources to Knowledge SDK without copying all MemoryAtoms.
 * Enforces fail-closed intersection across User, Agent, Tenant, Knowledge Policy,
 * Subject Binding, Privacy, and Lifecycle policies.
 */
export class CogniWeaveMemoryResourceAdapter {
  private readonly resources = new Map<string, MemoryResourceDescriptor>();
  private readonly outboxEvents: MemoryResourceDomainEvent[] = [];

  constructor(private readonly engine: CogniWeaveEngine) {}

  registerResource(
    descriptor: Omit<MemoryResourceDescriptor, "version" | "updatedAt"> & {
      version?: number;
      updatedAt?: string;
    },
    ctx?: { correlationId?: string; traceId?: string; policyVersion?: string },
  ): MemoryResourceDescriptor {
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
    return saved;
  }

  listResources(tenantId?: string): MemoryResourceDescriptor[] {
    const all = [...this.resources.values()];
    return tenantId ? all.filter((r) => r.tenantId === tenantId) : all;
  }

  describeResource(resourceId: string): MemoryResourceDescriptor | undefined {
    return this.resources.get(resourceId);
  }

  discoverResources(ctx: ResourceAccessContext): MemoryResourceDescriptor[] {
    return this.listResources(ctx.tenantId).filter(
      (resource) => this.checkAccess(resource.resourceId, ctx).allowed,
    );
  }

  checkAccess(resourceId: string, ctx: ResourceAccessContext): ResourceAccessDecision {
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
    if (
      ctx.allowedResourceTypes &&
      !ctx.allowedResourceTypes.includes(resource.resourceType)
    ) {
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
    const access = this.checkAccess(resourceId, ctx);
    if (!access.allowed) {
      throw new Error(`Memory resource access denied: ${access.denyReason}`);
    }
    return this.engine.reason(taskFrame);
  }

  async retrieveAtoms(
    resourceId: string,
    ctx: ResourceAccessContext,
    atomTypes?: string[],
  ): Promise<MemoryAtom[]> {
    const access = this.checkAccess(resourceId, ctx);
    if (!access.allowed) {
      throw new Error(`Memory resource access denied: ${access.denyReason}`);
    }
    const resource = this.resources.get(resourceId)!;
    const hits = await this.engine.queryAtoms({
      scope: resource.scope,
      caller: ctx.callerSubject,
      filter: atomTypes ? { atomTypes } : undefined,
    });
    return hits.map((h) => h.atom);
  }

  async resolveEvidence(
    resourceId: string,
    evidenceId: string,
    ctx: ResourceAccessContext,
  ): Promise<unknown> {
    const access = this.checkAccess(resourceId, ctx);
    if (!access.allowed) {
      throw new Error(`Memory resource access denied: ${access.denyReason}`);
    }
    const resource = this.resources.get(resourceId)!;
    return this.engine.resolveEvidence({
      evidenceId,
      includeContent: true,
      scope: resource.scope,
    });
  }

  getResourceStatus(resourceId: string): MemoryResourceDescriptor["lifecycleStatus"] | "not_found" {
    return this.resources.get(resourceId)?.lifecycleStatus ?? "not_found";
  }

  revokeAccess(
    resourceId: string,
    ctx?: { correlationId?: string; traceId?: string; policyVersion?: string },
  ): MemoryResourceDescriptor {
    const existing = this.resources.get(resourceId);
    if (!existing) {
      throw new Error(`Memory resource not found: ${resourceId}`);
    }
    const updated: MemoryResourceDescriptor = {
      ...existing,
      lifecycleStatus: "revoked",
      version: existing.version + 1,
      updatedAt: new Date().toISOString(),
    };
    this.resources.set(resourceId, updated);
    this.emitEvent("memory.resource.access.revoked", updated, ctx);
    return updated;
  }

  drainDomainEvents(): MemoryResourceDomainEvent[] {
    return this.outboxEvents.splice(0, this.outboxEvents.length);
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
