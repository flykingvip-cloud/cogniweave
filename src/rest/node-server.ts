import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { CogniWeaveMemoryResourceAdapter } from "../resource/index.js";
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
}

export interface CogniWeaveRequestEnvelope {
  method: string;
  url: string;
  headers: RestHeaders;
  body?: string;
}

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

async function routeEnvelope(
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

  const env = (service as unknown as { engine?: { config?: { environment?: string } } }).engine?.config?.environment;
  const requireAuth = options?.requireAuth ?? (env !== "local");

  let principal: RestPrincipal | undefined;
  if (requireAuth) {
    const authHeader = envelope.headers.authorization;
    const token = authHeader?.startsWith("Bearer ") ? authHeader.slice("Bearer ".length).trim() : "";
    if (!token || !options?.validateToken) {
      metrics.unauthorizedTotal += 1;
      return responseBody(401, { error: "unauthorized" });
    }
    const validated = await options.validateToken(token);
    if (!validated) {
      metrics.unauthorizedTotal += 1;
      return responseBody(401, { error: "invalid_token" });
    }
    principal = validated;
    const headerTenant = envelope.headers["x-cogniweave-tenant-id"];
    if (!headerTenant || headerTenant !== principal.tenantId) {
      metrics.unauthorizedTotal += 1;
      return responseBody(403, { error: "tenant_mismatch_or_missing" });
    }
  }

  const context: RestContext = {
    headers: {
      ...envelope.headers,
      ...(principal ? { "x-cogniweave-tenant-id": principal.tenantId, "x-cogniweave-user-id": principal.userId } : {}),
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

  // Optional body.scope tenant validation when authorizeTenantScope is configured.
  const checkBodyScope = async (body: { scope?: { workspaceId?: string } }) => {
    if (principal && options?.authorizeTenantScope && body.scope?.workspaceId) {
      const ok = await options.authorizeTenantScope(principal, body.scope.workspaceId);
      if (!ok) {
        return responseBody(403, { error: "scope_tenant_forbidden" });
      }
    }
    return null;
  };

  if (method === "POST" && pathname === "/v1/tasks/frame") {
    const body = parseBody<FrameTaskRequest>(envelope.body);
    const denied = await checkBodyScope(body);
    if (denied) return denied;
    return service.handleFrameTask(body, context);
  }
  if (method === "POST" && pathname === "/v1/reason") {
    return service.handleReason(parseBody<ReasonRequest>(envelope.body), context);
  }
  if (method === "POST" && pathname === "/v1/reason/debug") {
    return service.handleReasonDebug(parseBody<ReasonRequest>(envelope.body), context);
  }
  if (method === "POST" && pathname === "/v1/ingest") {
    const body = parseBody<DistillRequest>(envelope.body);
    const denied = await checkBodyScope(body);
    if (denied) return denied;
    return service.handleIngest(body, context);
  }
  if (method === "POST" && pathname === "/v1/distill") {
    const body = parseBody<DistillRequest>(envelope.body);
    const denied = await checkBodyScope(body);
    if (denied) return denied;
    return service.handleDistill(body, context);
  }
  if (method === "POST" && pathname === "/v1/write-back") {
    const body = parseBody<WriteBackRequest>(envelope.body);
    const denied = await checkBodyScope(body);
    if (denied) return denied;
    return service.handleWriteBack(body, context);
  }

  // CW-06 Memory Resource HTTP routes
  if (options?.resourceAdapter) {
    if (method === "GET" && pathname === "/v1/memory-resources") {
      return responseBody(200, options.resourceAdapter.listResources(principal?.tenantId));
    }
    const resMatch = pathname.match(/^\/v1\/memory-resources\/([^/]+)$/);
    if (method === "GET" && resMatch) {
      const desc = options.resourceAdapter.describeResource(resMatch[1]);
      if (!desc || (principal && desc.tenantId !== principal.tenantId)) {
        return responseBody(404, { error: "resource_not_found" });
      }
      return responseBody(200, desc);
    }
    const revokeMatch = pathname.match(/^\/v1\/memory-resources\/([^/]+)\/revoke$/);
    if (method === "POST" && revokeMatch) {
      const desc = options.resourceAdapter.describeResource(revokeMatch[1]);
      if (!desc || (principal && desc.tenantId !== principal.tenantId)) {
        return responseBody(404, { error: "resource_not_found" });
      }
      return responseBody(200, await options.resourceAdapter.revokeAccess(revokeMatch[1]));
    }
  }

  const traceAtomMatch = pathname.match(/^\/v1\/atoms\/([^/]+)\/trace$/);
  if (method === "GET" && traceAtomMatch) {
    return service.handleTraceAtom(traceAtomMatch[1], context);
  }

  const evidenceRefsMatch = pathname.match(/^\/v1\/atoms\/([^/]+)\/evidence-refs$/);
  if (method === "GET" && evidenceRefsMatch) {
    return service.handleGetEvidenceRefs(evidenceRefsMatch[1], context);
  }

  const packageTraceMatch = pathname.match(/^\/v1\/packages\/([^/]+)\/trace$/);
  if (method === "GET" && packageTraceMatch) {
    return service.handleTracePackage(packageTraceMatch[1], context);
  }

  const reasoningSessionTraceMatch = pathname.match(/^\/v1\/reasoning-sessions\/([^/]+)\/trace$/);
  if (method === "GET" && reasoningSessionTraceMatch) {
    return service.handleTraceReasoningSession(reasoningSessionTraceMatch[1], context);
  }

  if (method === "POST" && pathname === "/v1/evidence/resolve") {
    return service.handleResolveEvidence(parseBody<ResolveEvidenceRequest>(envelope.body), context);
  }
  if (method === "POST" && pathname === "/v1/repair/indexes") {
    return service.handleRepairIndexes(parseBody<RepairIndexesRequest>(envelope.body), context);
  }
  if (method === "POST" && pathname === "/v1/rebuild/from-truth") {
    return service.handleRebuildFromTruth(
      parseBody<RebuildFromTruthRequest>(envelope.body),
      context,
    );
  }

  const journalMatch = pathname.match(/^\/v1\/journals\/([^/]+)$/);
  if (method === "GET" && journalMatch) {
    return service.handleGetWriteJournal(journalMatch[1], context);
  }

  return responseBody(404, { error: "not found" });
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
