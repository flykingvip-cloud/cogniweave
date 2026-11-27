import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  authorizeCanonicalResource,
  isRebuildObjectType,
  type AuthoritativeBindingQuery,
  type CanonicalResourceKind,
  type CanonicalResourceScope,
  type CanonicalResourceScopeResolver,
} from "../auth/canonical-scope.js";
import type { TrustedPrincipalProvider } from "../auth/principal.js";
import { isUsableTrustedPrincipal } from "../auth/principal.js";
import { ScopeViolationError, StoreUnavailableError } from "../errors.js";
import type { EngineEnvironment } from "../models.js";
import type { CogniWeaveMemoryResourceAdapter, MemoryResourceDescriptor } from "../resource/index.js";
import type {
  DistillRequest,
  FrameTaskRequest,
  ReasonRequest,
  RebuildFromTruthRequest,
  RepairIndexesRequest,
  ResolveEvidenceRequest,
  RestContext,
  RestHeaders,
  RestPrincipal,
  RestResponse,
  WriteBackRequest,
} from "./contracts.js";
import type { CogniWeaveRestService } from "./service.js";

export type CogniWeaveHttpAuthPrincipal = RestPrincipal;

export interface CogniWeaveHttpServerOptions {
  basePath?: string;
  /** Defaults to true for service/cloud environments (fail-closed); false only if explicitly disabled for local dev. */
  requireAuth?: boolean;
  validateToken?: (token: string) => Promise<CogniWeaveHttpAuthPrincipal | null>;
  /** Optional tenant-to-workspace authorization hook for body.scope validation. */
  authorizeTenantScope?: (principal: RestPrincipal, workspaceId: string) => Promise<boolean> | boolean;
  /** Optional Memory Resource Adapter to expose /v1/memory-resources/* HTTP routes. */
  resourceAdapter?: CogniWeaveMemoryResourceAdapter;
  /**
   * CW-09-02: OpenBot-provided principal resolver. Alternative to validateToken.
   * CogniWeave does not implement an IdP. Missing in service/cloud => 401/503, never request-field fallback.
   */
  trustedPrincipalProvider?: TrustedPrincipalProvider;
  /** CW-09-01: required in service/cloud for Subject Binding intersection. Missing => 503. */
  authoritativeBindingQuery?: AuthoritativeBindingQuery;
  ensureDataPlaneId?: () => Promise<string>;
  knowledgePolicyAllows?: (params: {
    principal: RestPrincipal;
    resolved: CanonicalResourceScope;
  }) => Promise<boolean> | boolean;
}

export interface CogniWeaveRequestEnvelope {
  method: string;
  url: string;
  headers: RestHeaders;
  body?: string;
}

export const RESOURCE_ID_ROUTE_REGISTRY = [
  { name: "atom.trace", method: "GET", pathTemplate: "/v1/atoms/:id/trace", kind: "atom" },
  { name: "atom.evidence-refs", method: "GET", pathTemplate: "/v1/atoms/:id/evidence-refs", kind: "atom" },
  { name: "package.trace", method: "GET", pathTemplate: "/v1/packages/:id/trace", kind: "package" },
  {
    name: "reasoning-session.trace",
    method: "GET",
    pathTemplate: "/v1/reasoning-sessions/:id/trace",
    kind: "session",
  },
  { name: "journal.get", method: "GET", pathTemplate: "/v1/journals/:id", kind: "journal" },
  {
    name: "rebuild.from-truth",
    method: "POST",
    pathTemplate: "/v1/rebuild/from-truth",
    kind: "rebuild",
  },
  {
    name: "memory-resource.get",
    method: "GET",
    pathTemplate: "/v1/memory-resources/:id",
    kind: "memory_resource",
  },
  {
    name: "memory-resource.revoke",
    method: "POST",
    pathTemplate: "/v1/memory-resources/:id/revoke",
    kind: "memory_resource",
  },
] as const;

export type ResourceIdRouteName = (typeof RESOURCE_ID_ROUTE_REGISTRY)[number]["name"];

const metrics = {
  requestsTotal: 0,
  errorsTotal: 0,
  unauthorizedTotal: 0,
};

function normalizeHeaders(headers: IncomingMessage["headers"]): RestHeaders {
  return Object.fromEntries(
    Object.entries(headers).flatMap(([key, value]) => {
      if (value === undefined) return [];
      if (Array.isArray(value)) return [[key.toLowerCase(), value.join(",")]];
      return [[key.toLowerCase(), value]];
    }),
  );
}

function normalizeBasePath(basePath = "/"): string {
  if (!basePath || basePath === "/") return "";
  return `/${basePath.replace(/^\/+|\/+$/g, "")}`;
}

function parseBody<T>(body: string | undefined): T {
  if (!body || !body.trim()) return {} as T;
  return JSON.parse(body) as T;
}

function responseBody(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): RestResponse<unknown> {
  return { status, body, headers };
}

function writeJsonResponse(res: ServerResponse, response: RestResponse<unknown>): void {
  res.statusCode = response.status;
  for (const [key, value] of Object.entries({
    "content-type": "application/json; charset=utf-8",
    ...response.headers,
  })) {
    res.setHeader(key, value);
  }
  res.end(JSON.stringify(response.body));
}

function stripBasePath(pathname: string, basePath: string): string | null {
  if (!basePath) return pathname;
  if (!pathname.startsWith(basePath)) return null;
  const next = pathname.slice(basePath.length);
  return next.startsWith("/") ? next : `/${next}`;
}

function mapAuthorizationThrownError(error: unknown): RestResponse<unknown> | null {
  if (error instanceof ScopeViolationError) {
    return responseBody(404, { error: "not_found" });
  }
  if (error instanceof StoreUnavailableError) {
    return responseBody(503, { error: "store_unavailable" });
  }
  return null;
}

function toMemoryResourceScope(
  id: string,
  desc: MemoryResourceDescriptor | undefined,
): CanonicalResourceScope {
  if (!desc) {
    return { found: false, kind: "memory_resource", id, unresolvedReason: "not_found" };
  }
  return {
    found: true,
    kind: "memory_resource",
    id,
    scope: desc.scope,
    tenantId: desc.tenantId,
    owner: { ownerType: desc.ownerType, ownerId: desc.ownerId },
    privacyLevel: desc.privacyLevel,
    lifecycleStatus: desc.lifecycleStatus,
    subjectBindingId: desc.subjectBindingId,
    retrievable: desc.lifecycleStatus === "active",
  };
}

async function routeEnvelopeInner(
  service: CogniWeaveRestService,
  envelope: CogniWeaveRequestEnvelope,
  options?: CogniWeaveHttpServerOptions,
): Promise<RestResponse<unknown>> {
  metrics.requestsTotal += 1;
  const url = new URL(envelope.url, "http://localhost");
  const basePath = normalizeBasePath(options?.basePath);
  const pathname = stripBasePath(url.pathname, basePath);
  if (!pathname) {
    return responseBody(404, { error: "not found" });
  }

  const method = envelope.method.toUpperCase();

  // Only /healthz is unauthenticated. /v1/metrics and all /v1/* routes require auth in service/cloud mode.
  if (method === "GET" && pathname === "/healthz") {
    return responseBody(200, { ok: true, service: "cogniweave" });
  }

  const env = (service as unknown as { engine?: { config?: { environment?: string } } }).engine?.config
    ?.environment;
  const requireAuth = options?.requireAuth ?? env !== "local";

  let principal: RestPrincipal | undefined;
  if (requireAuth) {
    const authHeader = envelope.headers.authorization;
    const token = authHeader?.startsWith("Bearer ") ? authHeader.slice("Bearer ".length).trim() : "";
    const environment: EngineEnvironment =
      env === "local" || env === "service" || env === "cloud" ? env : "service";
    if (options?.trustedPrincipalProvider) {
      if (!token) {
        metrics.unauthorizedTotal += 1;
        return responseBody(401, { error: "unauthorized" });
      }
      try {
        const resolved = await options.trustedPrincipalProvider.resolvePrincipal({
          bearerToken: token,
          environment,
        });
        if (!isUsableTrustedPrincipal(resolved)) {
          metrics.unauthorizedTotal += 1;
          return responseBody(401, { error: "invalid_token" });
        }
        principal = {
          tenantId: resolved.tenantId,
          userId: resolved.userId,
          roles: resolved.roles,
          allowedWorkspaceIds: resolved.allowedWorkspaceIds,
          subject: resolved.subject,
        };
      } catch {
        metrics.unauthorizedTotal += 1;
        return responseBody(503, { error: "principal_unavailable" });
      }
    } else if (options?.validateToken) {
      if (!token) {
        metrics.unauthorizedTotal += 1;
        return responseBody(401, { error: "unauthorized" });
      }
      const validated = await options.validateToken(token);
      if (!validated) {
        metrics.unauthorizedTotal += 1;
        return responseBody(401, { error: "invalid_token" });
      }
      principal = validated;
    } else {
      metrics.unauthorizedTotal += 1;
      return responseBody(401, { error: "unauthorized" });
    }
    const headerTenant = envelope.headers["x-cogniweave-tenant-id"];
    if (!headerTenant || headerTenant !== principal.tenantId) {
      metrics.unauthorizedTotal += 1;
      return responseBody(403, { error: "tenant_mismatch_or_missing" });
    }
  }

  const context: RestContext = {
    headers: {
      ...envelope.headers,
      ...(principal
        ? { "x-cogniweave-tenant-id": principal.tenantId, "x-cogniweave-user-id": principal.userId }
        : {}),
    },
    ...(principal ? { principal } : {}),
  };

  if (method === "GET" && pathname === "/v1/metrics") {
    return responseBody(200, {
      ok: true,
      ...metrics,
      timestamp: new Date().toISOString(),
    });
  }

  const workspaceAllowed = async (workspaceId: string): Promise<boolean> => {
    if (!principal) return false;
    if (options?.authorizeTenantScope) {
      return Boolean(await options.authorizeTenantScope(principal, workspaceId));
    }
    return Boolean(principal.allowedWorkspaceIds?.includes(workspaceId));
  };

  // CW-09-01: declared scope only. Never fall back to request headers.
  const authorizeDeclaredWorkspace = async (
    workspaceId?: string,
  ): Promise<RestResponse<unknown> | null> => {
    if (!requireAuth) return null;
    if (!principal) {
      return responseBody(401, { error: "unauthorized" });
    }
    const targetWs = (workspaceId ?? "").trim();
    if (!targetWs) {
      metrics.unauthorizedTotal += 1;
      return responseBody(403, { error: "missing_workspace_scope" });
    }
    if (!(await workspaceAllowed(targetWs))) {
      metrics.unauthorizedTotal += 1;
      return responseBody(403, { error: "scope_tenant_forbidden" });
    }
    return null;
  };

  const engineResolver: CanonicalResourceScopeResolver = {
    resolve: (kind, id) => service.resolveCanonicalResourceScope(kind, id),
  };

  const memoryResourceResolver = (id: string): CanonicalResourceScopeResolver => ({
    async resolve() {
      if (!options?.resourceAdapter) {
        return { found: false, kind: "memory_resource", id, unresolvedReason: "not_found" };
      }
      try {
        const desc = await options.resourceAdapter.describeResource(id);
        return toMemoryResourceScope(id, desc);
      } catch {
        return { found: false, kind: "memory_resource", id, unresolvedReason: "store_unavailable" };
      }
    },
  });

  const authorizeCanonical = async (
    kind: CanonicalResourceKind,
    id: string,
    mode: "read" | "manage" = "read",
  ): Promise<RestResponse<unknown> | null> => {
    if (!requireAuth) return null;
    const decision = await authorizeCanonicalResource({
      kind,
      id,
      principal,
      mode,
      resolver: kind === "memory_resource" ? memoryResourceResolver(id) : engineResolver,
      authorizeWorkspace: workspaceAllowed,
      bindingQuery: options?.authoritativeBindingQuery,
      ensureDataPlaneId: options?.ensureDataPlaneId,
      knowledgePolicyAllows: options?.knowledgePolicyAllows,
    });
    if (!decision.allowed) {
      metrics.unauthorizedTotal += 1;
      return responseBody(decision.httpStatus, { error: decision.error });
    }
    context.authorizedScope = decision.scope;
    return null;
  };

  if (method === "POST" && pathname === "/v1/tasks/frame") {
    const body = parseBody<FrameTaskRequest>(envelope.body);
    const denied = await authorizeDeclaredWorkspace(body.scope?.workspaceId);
    if (denied) return denied;
    return service.handleFrameTask(body, context);
  }
  if (method === "POST" && pathname === "/v1/reason") {
    const body = parseBody<ReasonRequest>(envelope.body);
    const denied = await authorizeDeclaredWorkspace(body.taskFrame?.scope?.workspaceId);
    if (denied) return denied;
    return service.handleReason(body, context);
  }
  if (method === "POST" && pathname === "/v1/reason/debug") {
    const body = parseBody<ReasonRequest>(envelope.body);
    const denied = await authorizeDeclaredWorkspace(body.taskFrame?.scope?.workspaceId);
    if (denied) return denied;
    return service.handleReasonDebug(body, context);
  }
  if (method === "POST" && pathname === "/v1/ingest") {
    const body = parseBody<DistillRequest>(envelope.body);
    const denied = await authorizeDeclaredWorkspace(body.scope?.workspaceId);
    if (denied) return denied;
    return service.handleIngest(body, context);
  }
  if (method === "POST" && pathname === "/v1/distill") {
    const body = parseBody<DistillRequest>(envelope.body);
    const denied = await authorizeDeclaredWorkspace(body.scope?.workspaceId);
    if (denied) return denied;
    return service.handleDistill(body, context);
  }
  if (method === "POST" && pathname === "/v1/write-back") {
    const body = parseBody<WriteBackRequest>(envelope.body);
    const denied = await authorizeDeclaredWorkspace(body.scope?.workspaceId);
    if (denied) return denied;
    return service.handleWriteBack(body, context);
  }

  // CW-06 Memory Resource HTTP routes
  if (options?.resourceAdapter) {
    if (method === "GET" && pathname === "/v1/memory-resources") {
      const declaredWorkspace = (envelope.headers["x-cogniweave-workspace-id"] ?? "").trim();
      const denied = await authorizeDeclaredWorkspace(declaredWorkspace);
      if (denied) return denied;
      const listed = await options.resourceAdapter.listResources(principal?.tenantId);
      return responseBody(
        200,
        declaredWorkspace
          ? listed.filter((desc) => desc.scope.workspaceId === declaredWorkspace)
          : listed,
      );
    }
    const resMatch = pathname.match(/^\/v1\/memory-resources\/([^/]+)$/);
    if (method === "GET" && resMatch) {
      const denied = await authorizeCanonical("memory_resource", resMatch[1], "read");
      if (denied) return denied;
      const desc = await options.resourceAdapter.describeResource(resMatch[1]);
      if (!desc) return responseBody(404, { error: "not_found" });
      return responseBody(200, desc);
    }
    const revokeMatch = pathname.match(/^\/v1\/memory-resources\/([^/]+)\/revoke$/);
    if (method === "POST" && revokeMatch) {
      const denied = await authorizeCanonical("memory_resource", revokeMatch[1], "manage");
      if (denied) return denied;
      const desc = await options.resourceAdapter.describeResource(revokeMatch[1]);
      if (!desc) return responseBody(404, { error: "not_found" });
      if (!principal) {
        return responseBody(401, { error: "unauthorized" });
      }
      if (!options.resourceAdapter.authorizeResourceManagement(desc, principal)) {
        metrics.unauthorizedTotal += 1;
        // After authoritative lookup, management ACL denial still uses 403 (not enumeration of existence).
        // Cross-tenant already mapped to 404 by the canonical gate.
        return responseBody(403, { error: "resource_management_forbidden" });
      }
      return responseBody(200, await options.resourceAdapter.revokeAccess(revokeMatch[1], principal));
    }
  }

  const traceAtomMatch = pathname.match(/^\/v1\/atoms\/([^/]+)\/trace$/);
  if (method === "GET" && traceAtomMatch) {
    const denied = await authorizeCanonical("atom", traceAtomMatch[1]);
    if (denied) return denied;
    return service.handleTraceAtom(traceAtomMatch[1], context);
  }

  const evidenceRefsMatch = pathname.match(/^\/v1\/atoms\/([^/]+)\/evidence-refs$/);
  if (method === "GET" && evidenceRefsMatch) {
    const denied = await authorizeCanonical("atom", evidenceRefsMatch[1]);
    if (denied) return denied;
    return service.handleGetEvidenceRefs(evidenceRefsMatch[1], context);
  }

  const packageTraceMatch = pathname.match(/^\/v1\/packages\/([^/]+)\/trace$/);
  if (method === "GET" && packageTraceMatch) {
    const denied = await authorizeCanonical("package", packageTraceMatch[1]);
    if (denied) return denied;
    return service.handleTracePackage(packageTraceMatch[1], context);
  }

  const reasoningSessionTraceMatch = pathname.match(/^\/v1\/reasoning-sessions\/([^/]+)\/trace$/);
  if (method === "GET" && reasoningSessionTraceMatch) {
    const denied = await authorizeCanonical("session", reasoningSessionTraceMatch[1]);
    if (denied) return denied;
    return service.handleTraceReasoningSession(reasoningSessionTraceMatch[1], context);
  }

  if (method === "POST" && pathname === "/v1/evidence/resolve") {
    const body = parseBody<ResolveEvidenceRequest>(envelope.body);
    const denied = await authorizeDeclaredWorkspace(body.scope?.workspaceId);
    if (denied) return denied;
    return service.handleResolveEvidence(body, context);
  }
  if (method === "POST" && pathname === "/v1/repair/indexes") {
    const body = parseBody<RepairIndexesRequest>(envelope.body);
    const denied = await authorizeDeclaredWorkspace(body.scope?.workspaceId);
    if (denied) return denied;
    return service.handleRepairIndexes(body, context);
  }
  if (method === "POST" && pathname === "/v1/rebuild/from-truth") {
    const body = parseBody<RebuildFromTruthRequest>(envelope.body);
    if (requireAuth && !isRebuildObjectType(body.objectType ?? "")) {
      return responseBody(404, { error: "not_found" });
    }
    if (requireAuth) {
      const denied = await authorizeCanonical(body.objectType as CanonicalResourceKind, body.objectId);
      if (denied) return denied;
    }
    return service.handleRebuildFromTruth(body, context);
  }

  const journalMatch = pathname.match(/^\/v1\/journals\/([^/]+)$/);
  if (method === "GET" && journalMatch) {
    const denied = await authorizeCanonical("journal", journalMatch[1]);
    if (denied) return denied;
    return service.handleGetWriteJournal(journalMatch[1], context);
  }

  return responseBody(404, { error: "not found" });
}

async function routeEnvelope(
  service: CogniWeaveRestService,
  envelope: CogniWeaveRequestEnvelope,
  options?: CogniWeaveHttpServerOptions,
): Promise<RestResponse<unknown>> {
  try {
    return await routeEnvelopeInner(service, envelope, options);
  } catch (error) {
    const mapped = mapAuthorizationThrownError(error);
    if (mapped) {
      metrics.unauthorizedTotal += 1;
      return mapped;
    }
    throw error;
  }
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function handleCogniWeaveHttpRequest(
  service: CogniWeaveRestService,
  req: IncomingMessage,
  res: ServerResponse,
  options?: CogniWeaveHttpServerOptions,
): Promise<void> {
  try {
    const envelope: CogniWeaveRequestEnvelope = {
      method: req.method ?? "GET",
      url: req.url ?? "/",
      headers: normalizeHeaders(req.headers),
      body: await readBody(req),
    };
    const response = await routeEnvelope(service, envelope, options);
    writeJsonResponse(res, response);
  } catch (error) {
    const mapped = mapAuthorizationThrownError(error);
    if (mapped) {
      metrics.unauthorizedTotal += 1;
      writeJsonResponse(res, mapped);
      return;
    }
    metrics.errorsTotal += 1;
    writeJsonResponse(res, {
      status: 500,
      headers: {},
      body: {
        error: error instanceof Error ? error.message : String(error),
      },
    });
  }
}

export function createCogniWeaveHttpServer(
  service: CogniWeaveRestService,
  options?: CogniWeaveHttpServerOptions,
): Server {
  return createServer((req, res) => {
    void handleCogniWeaveHttpRequest(service, req, res, options);
  });
}

export { routeEnvelope as routeCogniWeaveHttpRequest };
