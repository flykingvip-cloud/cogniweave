import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createAuthoritativeBindingQueryFromMetadataStore, createDenyByDefaultBindingQuery } from "../auth/canonical-scope.js";
import { createDenyByDefaultPrincipalProvider } from "../auth/principal.js";
import { createTrustedRuntime } from "../auth/trusted-runtime.js";
import type { TrustedPrincipal } from "../auth/principal.js";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type { MemorySubject, Scope } from "../models.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import { CogniWeaveMemoryResourceAdapter } from "../resource/index.js";
import {
  InMemoryCogniWeaveEngine,
  registerEngineCanonicalAuthorizationResolver,
} from "../runtime/in-memory-engine.js";
import { InMemoryMetadataStore } from "../storage/in-memory.js";
import { handleCogniWeaveHttpRequest, RESOURCE_ID_ROUTE_REGISTRY, routeCogniWeaveHttpRequest } from "./node-server.js";
import { CogniWeaveRestService } from "./service.js";
import type { CogniWeaveRestService as CogniWeaveRestServiceClass } from "./service.js";

class MockResponse {
  statusCode = 200;
  private readonly headers = new Map<string, string>();
  body = "";

  setHeader(name: string, value: string): void {
    this.headers.set(name.toLowerCase(), value);
  }

  end(chunk?: string | Uint8Array | Buffer): void {
    if (chunk === undefined) {
      return;
    }
    this.body += chunk.toString();
  }

  getHeader(name: string): string | undefined {
    return this.headers.get(name.toLowerCase());
  }
}

function makeRequest(
  method: string,
  url: string,
  body?: string,
  headers: Record<string, string> = {},
) {
  return {
    method,
    url,
    headers,
    async *[Symbol.asyncIterator]() {
      if (body) {
        yield Buffer.from(body);
      }
    },
  } as unknown as IncomingMessage;
}

describe("CogniWeave HTTP server", () => {
  const scope = {
    workspaceId: "ws_1",
    projectId: "proj_1",
    agentId: "agent_main",
    visibility: "private" as const,
  };

  it("serves the minimal frame -> write-back -> journal loop through the HTTP handler", async () => {
    const engine = new InMemoryCogniWeaveEngine({
      environment: "local",
      metadataBackend: "memory",
      graphBackend: "memory",
      evidenceBackend: "memory",
      vectorBackend: "memory",
    });
    const service = new CogniWeaveRestService(engine);

    const frameRes = new MockResponse();
    await handleCogniWeaveHttpRequest(
      service,
      makeRequest(
        "POST",
        "/v1/tasks/frame",
        JSON.stringify({
          rawInput:
            "Current throughput is dropping and the external API is slow. Should we add synchronous retries?",
          scope,
        }),
      ),
      frameRes as unknown as ServerResponse,
    );
    const frame = JSON.parse(frameRes.body) as { taskType: string };

    const writeRes = new MockResponse();
    await handleCogniWeaveHttpRequest(
      service,
      makeRequest(
        "POST",
        "/v1/write-back",
        JSON.stringify({
          rawInput:
            "Current throughput is dropping and the external API is slow. Should we add synchronous retries?",
          scope,
          sourceType: "chat",
          sourceSessionId: "sess_http",
        }),
        { "Idempotency-Key": "idem_http_001" },
      ),
      writeRes as unknown as ServerResponse,
    );
    const write = JSON.parse(writeRes.body) as { status: string; journalId: string };

    const journalRes = new MockResponse();
    await handleCogniWeaveHttpRequest(
      service,
      makeRequest("GET", `/v1/journals/${write.journalId}`, undefined, {
        "x-cogniweave-workspace-id": scope.workspaceId,
        "x-cogniweave-project-id": scope.projectId,
        "x-cogniweave-agent-id": scope.agentId,
        "x-cogniweave-visibility": scope.visibility,
      }),
      journalRes as unknown as ServerResponse,
    );
    const journal = JSON.parse(journalRes.body) as { id: string };

    expect(frameRes.statusCode).toBe(200);
    expect(frame.taskType).toBe("debugging");
    expect(writeRes.statusCode).toBe(200);
    expect(writeRes.getHeader("x-cogniweave-journal-id")).toBeTruthy();
    expect(write.status).toBe("COMPLETED");
    expect(journal.id).toBe(write.journalId);
  });

  it("routes atom trace endpoints without a network server", async () => {
    const service = {
      engine: {
        config: { environment: "local" },
      },
      async handleTraceAtom(atomId: string) {
        return { status: 200, headers: {}, body: { atomId } };
      },
      async handleGetEvidenceRefs(atomId: string) {
        return { status: 200, headers: {}, body: [atomId] };
      },
    } as unknown as CogniWeaveRestServiceClass;

    const traceResponse = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: "/v1/atoms/atm_1/trace",
        headers: {},
      },
    );
    const evidenceRefsResponse = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: "/v1/atoms/atm_1/evidence-refs",
        headers: {},
      },
    );

    expect(traceResponse.status).toBe(200);
    expect(traceResponse.body).toEqual({ atomId: "atm_1" });
    expect(evidenceRefsResponse.status).toBe(200);
    expect(evidenceRefsResponse.body).toEqual(["atm_1"]);
  });

  it("enforces fail-closed auth, tenant matching, and protects /v1/metrics in service mode (CW-07A)", async () => {
    const service = new CogniWeaveRestService(
      new InMemoryCogniWeaveEngine(
        {
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        },
        {
          runtime: createTrustedRuntime({
            environment: "service",
            principalProvider: createDenyByDefaultPrincipalProvider([
              {
                token: "valid_tok",
                principal: {
                  tenantId: "t_1",
                  userId: "u_1",
                  allowedWorkspaceIds: ["ws_1"],
                  subject: { tenantId: "t_1", ownerType: "user", ownerId: "u_1" },
                },
              },
            ]),
          }),
        },
      ),
    );
    const opts = {};

    const health = await routeCogniWeaveHttpRequest(
      service,
      { method: "GET", url: "/healthz", headers: {} },
      opts,
    );
    expect(health.status).toBe(200);

    const unauthMetrics = await routeCogniWeaveHttpRequest(
      service,
      { method: "GET", url: "/v1/metrics", headers: {} },
      opts,
    );
    expect(unauthMetrics.status).toBe(401);

    const missingTenant = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: "/v1/metrics",
        headers: { authorization: "Bearer valid_tok" },
      },
      opts,
    );
    expect(missingTenant.status).toBe(403);

    const authedMetrics = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: "/v1/metrics",
        headers: {
          authorization: "Bearer valid_tok",
          "x-cogniweave-tenant-id": "t_1",
        },
      },
      opts,
    );
    expect(authedMetrics.status).toBe(200);

    // CW-08-01: Missing workspace scope on /v1/reason is rejected (403)
    const missingWs = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "POST",
        url: "/v1/reason",
        headers: {
          authorization: "Bearer valid_tok",
          "x-cogniweave-tenant-id": "t_1",
        },
        body: JSON.stringify({
          taskFrame: {
            id: "tf_1",
            scope: { workspaceId: "", projectId: "p1", agentId: "a1", visibility: "private" },
            taskType: "operations",
            goals: [],
            problems: [],
            scenarioTags: [],
            constraints: [],
            entities: [],
            requiredAtomTypes: [],
          },
        }),
      },
      opts,
    );
    expect(missingWs.status).toBe(403);

    // CW-08-01: Cross-workspace body.scope fails with 403
    const crossScopeReason = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "POST",
        url: "/v1/reason",
        headers: {
          authorization: "Bearer valid_tok",
          "x-cogniweave-tenant-id": "t_1",
        },
        body: JSON.stringify({
          taskFrame: {
            id: "tf_1",
            scope: { workspaceId: "ws_other", projectId: "p1", agentId: "a1", visibility: "private" },
            taskType: "operations",
            goals: [],
            problems: [],
            scenarioTags: [],
            constraints: [],
            entities: [],
            requiredAtomTypes: [],
          },
        }),
      },
      opts,
    );
    expect(crossScopeReason.status).toBe(403);
  });
});


const RAW_INPUT =
  "Current throughput is dropping and the external API is slow. Should we add synchronous retries?";

describe("CW-09-01 REST canonical scope authorization", () => {
  const scope: Scope = {
    workspaceId: "ws_1",
    projectId: "proj_1",
    agentId: "agent_main",
    visibility: "private",
  };
  const otherScope: Scope = { ...scope, workspaceId: "ws_other" };
  const subject: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "u_1" };

  const otherSubject: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "u_other" };

  function principalFor(
    overrides: Partial<TrustedPrincipal> & { userId?: string; subject?: MemorySubject } = {},
  ): TrustedPrincipal {
    const resolvedSubject = overrides.subject ?? subject;
    return {
      tenantId: overrides.tenantId ?? resolvedSubject.tenantId,
      userId: overrides.userId ?? "u_1",
      roles: overrides.roles,
      allowedWorkspaceIds: overrides.allowedWorkspaceIds ?? ["ws_1"],
      subject: resolvedSubject,
    };
  }

  async function setup(args?: { allowedWorkspaces?: string[]; roles?: string[] }) {
    const metadataStore = new InMemoryMetadataStore();
    const dataPlaneId = await metadataStore.ensureDataPlaneId();
    const binding = createMemorySubjectBinding({
      partition: createMemoryPartitionKeyV1(dataPlaneId, scope),
      scope,
      subject,
    });
    await metadataStore.saveMemorySubjectBinding(binding);
    const bindingQuery = createAuthoritativeBindingQueryFromMetadataStore(metadataStore)!;
    const runtime = createTrustedRuntime({
      environment: "service",
      principalProvider: createDenyByDefaultPrincipalProvider([
        {
          token: "valid_tok",
          principal: principalFor({
            roles: args?.roles,
            allowedWorkspaceIds: args?.allowedWorkspaces ?? ["ws_1"],
          }),
        },
        {
          token: "tok_seed",
          principal: principalFor(),
        },
        {
          token: "tok_cross_tenant",
          principal: principalFor({
            tenantId: "t_other",
            subject: { ...subject, tenantId: "t_other" },
          }),
        },
        {
          token: "tok_cross_ws",
          principal: principalFor({ allowedWorkspaceIds: ["ws_other"] }),
        },
        {
          token: "tok_other_subject",
          principal: principalFor({ userId: "u_other", subject: otherSubject }),
        },
        {
          token: "tok_admin",
          principal: principalFor({ userId: "admin", roles: ["tenant_admin"] }),
        },
        {
          token: "tok_mismatch",
          principal: {
            tenantId: "t_a",
            userId: "u_1",
            allowedWorkspaceIds: ["ws_1"],
            subject: { tenantId: "t_b", ownerType: "user", ownerId: "u_1" },
          },
        },
      ]),
      bindingQuery,
      ensureDataPlaneId: () => metadataStore.ensureDataPlaneId(),
    });
    const engine = new InMemoryCogniWeaveEngine(
      {
        environment: "service",
        metadataBackend: "memory",
        graphBackend: "memory",
        evidenceBackend: "memory",
        vectorBackend: "memory",
      },
      { metadataStore, runtime },
    );
    const service = new CogniWeaveRestService(engine);
    const adapter = new CogniWeaveMemoryResourceAdapter(engine);
    const bindings = await metadataStore.listMemorySubjectBindings!({ scope, liveOnly: true });
    const opts = {
      resourceAdapter: adapter,
    };
    return { engine, service, adapter, metadataStore, opts, bindings, bindingQuery, runtime };
  }

  function authHeaders(extra: Record<string, string> = {}, token = "valid_tok") {
    return {
      authorization: `Bearer ${token}`,
      "x-cogniweave-tenant-id": extra["x-cogniweave-tenant-id"] ?? "t_1",
      ...extra,
    };
  }

  async function seed(service: CogniWeaveRestService, engine: InMemoryCogniWeaveEngine) {
    const authorization = { bearerToken: "tok_seed" };
    const write = await engine.writeBack({
      rawInput: RAW_INPUT,
      scope,
      sourceType: "chat",
      sourceSessionId: "sess_cw0901",
      authorization,
    });
    const frame = await engine.frameTask(RAW_INPUT, { scope, authorization });
    const reasoned = await engine.reason(frame, { authorization });
    return { write, frame, reasoned };
  }

  it("registers every resource-ID route against the unified canonical gate and forbids header fallback", () => {
    const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "node-server.ts"), "utf8");
    expect(RESOURCE_ID_ROUTE_REGISTRY.map((route) => route.name).sort()).toEqual(
      [
        "atom.evidence-refs",
        "atom.trace",
        "journal.get",
        "memory-resource.get",
        "memory-resource.revoke",
        "package.trace",
        "reasoning-session.trace",
        "rebuild.from-truth",
      ].sort(),
    );
    expect(source).toContain('authorizeCanonical("atom"');
    expect(source).toContain('authorizeCanonical("package"');
    expect(source).toContain('authorizeCanonical("session"');
    expect(source).toContain('authorizeCanonical("journal"');
    expect(source).toContain('authorizeCanonical("memory_resource"');
    expect(source).toContain("authorizeCanonical(body.objectType");
    expect(source).toContain("authorizeDeclared(body.scope)");
    expect(source).toContain("authorizeDeclared(body.taskFrame?.scope)");
    expect(source).toContain("authorizeDeclaredScope");
    expect(source).not.toContain("authorizeDeclaredWorkspace");
    expect(source).not.toContain('workspaceId ?? envelope.headers["x-cogniweave-workspace-id"]');
    expect(source).toContain("Never fall back to request headers");
  });

  it("ignores forged workspace headers and uses only canonical ownership", async () => {
    const { service, engine, opts, metadataStore } = await setup();
    const { write, reasoned } = await seed(service, engine);
    const forgedHeader = authHeaders({
      "x-cogniweave-workspace-id": "ws_other",
      "x-cogniweave-project-id": scope.projectId,
      "x-cogniweave-agent-id": scope.agentId,
    });

    const routes = [
      `/v1/journals/${write.journalId}`,
      `/v1/atoms/${write.atomIds[0]}/trace`,
      `/v1/atoms/${write.atomIds[0]}/evidence-refs`,
      `/v1/packages/${reasoned.packageId}/trace`,
      `/v1/reasoning-sessions/${reasoned.sessionId}/trace`,
    ];
    for (const url of routes) {
      const allowed = await routeCogniWeaveHttpRequest(
        service,
        { method: "GET", url, headers: forgedHeader },
        opts,
      );
      expect({ url, status: allowed.status }).toEqual({ url, status: 200 });
    }

    await metadataStore.putJournal({
      id: "jnl_foreign",
      eventKey: "ek_foreign",
      scope: otherScope,
      objectIds: {
        eventIds: [],
        atomIds: [],
        entityIds: [],
        scenarioIds: [],
        problemIds: [],
        evidenceIds: [],
        relationIds: [],
      },
      derivedPlan: { graphNodeIds: [], graphEdgeIds: [], vectorDocIds: [] },
      status: "COMPLETED",
      phase: "COMPLETED",
      retryCount: 0,
      updatedAt: new Date().toISOString(),
    });
    const forgedForeign = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: "/v1/journals/jnl_foreign",
        headers: authHeaders({ "x-cogniweave-workspace-id": "ws_1" }),
      },
      opts,
    );
    expect(forgedForeign.status).toBe(404);
    expect(forgedForeign.body).toEqual({ error: "not_found" });
  });

  it("returns 404 for cross-tenant, cross-workspace, and cross-subject reads", async () => {
    const { service, engine, metadataStore, opts } = await setup();
    const { write } = await seed(service, engine);

    const crossTenant = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: `/v1/journals/${write.journalId}`,
        headers: authHeaders({ "x-cogniweave-tenant-id": "t_other" }, "tok_cross_tenant"),
      },
      opts,
    );
    expect(crossTenant.status).toBe(404);

    const crossWorkspace = await routeCogniWeaveHttpRequest(
      service,
      { method: "GET", url: `/v1/journals/${write.journalId}`, headers: authHeaders({}, "tok_cross_ws") },
      opts,
    );
    expect(crossWorkspace.status).toBe(404);

    const crossSubject = await routeCogniWeaveHttpRequest(
      service,
      { method: "GET", url: `/v1/journals/${write.journalId}`, headers: authHeaders({}, "tok_other_subject") },
      opts,
    );
    expect(crossSubject.status).toBe(404);
  });

  it("returns 404 when journal ownership cannot be derived", async () => {
    const { service, metadataStore, opts } = await setup();
    await metadataStore.putJournal({
      id: "jnl_incomplete",
      eventKey: "ek_incomplete",
      objectIds: {
        eventIds: [],
        atomIds: [],
        entityIds: [],
        scenarioIds: [],
        problemIds: [],
        evidenceIds: [],
        relationIds: [],
      },
      derivedPlan: { graphNodeIds: [], graphEdgeIds: [], vectorDocIds: [] },
      status: "COMPLETED",
      phase: "COMPLETED",
      retryCount: 0,
      updatedAt: new Date().toISOString(),
    });
    const response = await routeCogniWeaveHttpRequest(
      service,
      { method: "GET", url: "/v1/journals/jnl_incomplete", headers: authHeaders() },
      opts,
    );
    expect(response.status).toBe(404);
    expect(response.body).toEqual({ error: "not_found" });
  });

  it("returns 503 when the canonical store or binding query is unavailable", async () => {
    const seeded = await setup();
    const { write } = await seed(seeded.service, seeded.engine);
    const missingRuntime = createTrustedRuntime({
      environment: "service",
      principalProvider: createDenyByDefaultPrincipalProvider([
        { token: "valid_tok", principal: principalFor() },
      ]),
    });
    const missingEngine = new InMemoryCogniWeaveEngine(
      {
        environment: "service",
        metadataBackend: "memory",
        graphBackend: "memory",
        evidenceBackend: "memory",
        vectorBackend: "memory",
      },
      { metadataStore: seeded.metadataStore, runtime: missingRuntime },
    );
    const missingBinding = await routeCogniWeaveHttpRequest(
      new CogniWeaveRestService(missingEngine),
      { method: "GET", url: `/v1/journals/${write.journalId}`, headers: authHeaders() },
    );
    expect(missingBinding.status).toBe(503);
    expect(missingBinding.body).toEqual({ error: "binding_store_unavailable" });

    const throwingEngine = {
      trustedRuntime: seeded.runtime,
      config: { environment: "service" },
    };
    registerEngineCanonicalAuthorizationResolver(throwingEngine, {
      async resolve() {
        throw new Error("canonical store down");
      },
    });
    const throwingStore = new CogniWeaveRestService(throwingEngine as never);
    const storeDown = await routeCogniWeaveHttpRequest(
      throwingStore,
      { method: "GET", url: `/v1/journals/${write.journalId}`, headers: authHeaders() },
    );
    expect(storeDown.status).toBe(503);
    expect(storeDown.body).toEqual({ error: "store_unavailable" });
  });

  it("does not let tenant_admin skip canonical ownership lookup", async () => {
    const { service, engine, opts } = await setup({
      allowedWorkspaces: ["ws_admin"],
      roles: ["tenant_admin"],
    });
    const { write } = await seed(service, engine);
    const response = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: `/v1/journals/${write.journalId}`,
        headers: authHeaders({ "x-cogniweave-workspace-id": "ws_admin" }),
      },
      opts,
    );
    expect(response.status).toBe(404);
  });

  it("rejects rebuild for missing, mistyped, or cross-workspace objects without rebuilding", async () => {
    const { service, engine, opts, metadataStore } = await setup();
    const { write } = await seed(service, engine);
    const before = (await metadataStore.listJournals()).map((journal) => journal.updatedAt);

    const missing = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "POST",
        url: "/v1/rebuild/from-truth",
        headers: authHeaders(),
        body: JSON.stringify({ objectType: "atom", objectId: "atm_missing" }),
      },
      opts,
    );
    const wrongType = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "POST",
        url: "/v1/rebuild/from-truth",
        headers: authHeaders({ "x-cogniweave-workspace-id": "ws_1" }),
        body: JSON.stringify({ objectType: "event", objectId: write.atomIds[0] }),
      },
      opts,
    );
    const unknownType = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "POST",
        url: "/v1/rebuild/from-truth",
        headers: authHeaders(),
        body: JSON.stringify({ objectType: "package", objectId: write.atomIds[0] }),
      },
      opts,
    );
    const cross = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "POST",
        url: "/v1/rebuild/from-truth",
        headers: authHeaders({ "x-cogniweave-workspace-id": "ws_other" }, "tok_cross_ws"),
        body: JSON.stringify({ objectType: "atom", objectId: write.atomIds[0] }),
      },
      opts,
    );

    expect(missing.status).toBe(404);
    expect(wrongType.status).toBe(404);
    expect(unknownType.status).toBe(404);
    expect(cross.status).toBe(404);
    expect((await metadataStore.listJournals()).map((journal) => journal.updatedAt)).toEqual(before);

    const ok = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "POST",
        url: "/v1/rebuild/from-truth",
        headers: authHeaders(),
        body: JSON.stringify({ objectType: "atom", objectId: write.atomIds[0] }),
      },
      opts,
    );
    expect(ok.status).toBe(200);
    expect((ok.body as { status: string }).status).toBe("REBUILT");
  });

  it("filters GET /v1/memory-resources to the declared workspace and authorizes GET/revoke after lookup", async () => {
    const { service, engine, adapter, opts, metadataStore } = await setup();
    await seed(service, engine);
    const live = await metadataStore.listMemorySubjectBindings!({
      tenantId: subject.tenantId,
      dataPlaneId: await metadataStore.ensureDataPlaneId(),
      scope,
      liveOnly: true,
    });
    const bindingId = live[0]?.id;
    expect(bindingId).toBeTruthy();

    await adapter.registerResource({
      resourceId: "res_ws_1",
      resourceType: "user_memory",
      tenantId: "t_1",
      ownerType: "user",
      ownerId: "u_1",
      subjectBindingId: bindingId!,
      scope,
      visibility: "private",
      privacyLevel: "private",
      lifecycleStatus: "active",
      supportedAtomTypes: [],
      capabilities: ["retrieve"],
      sourceAuthority: "user",
      evidenceSupport: true,
    });
    await adapter.registerResource({
      resourceId: "res_ws_other",
      resourceType: "user_memory",
      tenantId: "t_1",
      ownerType: "user",
      ownerId: "u_1",
      subjectBindingId: bindingId!,
      scope: otherScope,
      visibility: "private",
      privacyLevel: "private",
      lifecycleStatus: "active",
      supportedAtomTypes: [],
      capabilities: ["retrieve"],
      sourceAuthority: "user",
      evidenceSupport: true,
    });

    const missingDeclared = await routeCogniWeaveHttpRequest(
      service,
      { method: "GET", url: "/v1/memory-resources", headers: authHeaders() },
      opts,
    );
    expect(missingDeclared.status).toBe(403);

    const listed = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: "/v1/memory-resources",
        headers: authHeaders({ "x-cogniweave-workspace-id": "ws_1" }),
      },
      opts,
    );
    expect(listed.status).toBe(200);
    const ids = (listed.body as Array<{ resourceId: string }>).map((row) => row.resourceId);
    expect(ids).toEqual(["res_ws_1"]);

    const forgedGet = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: "/v1/memory-resources/res_ws_1",
        headers: authHeaders({ "x-cogniweave-workspace-id": "ws_other" }),
      },
      opts,
    );
    expect(forgedGet.status).toBe(200);

    const otherGet = await routeCogniWeaveHttpRequest(
      service,
      { method: "GET", url: "/v1/memory-resources/res_ws_other", headers: authHeaders() },
      opts,
    );
    expect(otherGet.status).toBe(404);

    const honestGet = await routeCogniWeaveHttpRequest(
      service,
      { method: "GET", url: "/v1/memory-resources/res_ws_1", headers: authHeaders() },
      opts,
    );
    expect(honestGet.status).toBe(200);

    const adminRevokeLookup = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "POST",
        url: "/v1/memory-resources/res_missing/revoke",
        headers: authHeaders(),
        body: "{}",
      },
      opts,
    );
    expect(adminRevokeLookup.status).toBe(404);
  });

  it("does not fill a missing create-route workspace from request headers", async () => {
    const { service, opts } = await setup();
    const response = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "POST",
        url: "/v1/tasks/frame",
        headers: authHeaders({ "x-cogniweave-workspace-id": "ws_1" }),
        body: JSON.stringify({ rawInput: RAW_INPUT }),
      },
      opts,
    );
    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: "missing_workspace_scope" });
  });

  it("denies declared-scope create and write routes without a live subject binding", async () => {
    const { service, opts, metadataStore } = await setup();
    const live = await metadataStore.listMemorySubjectBindings!({ liveOnly: true });
    for (const binding of live) {
      await metadataStore.saveMemorySubjectBinding({ ...binding, unboundAt: "2026-11-27T00:00:00.000Z" });
    }
    const noBinding = opts;
    const routes: Array<{ method: string; url: string; body: unknown }> = [
      { method: "POST", url: "/v1/tasks/frame", body: { rawInput: RAW_INPUT, scope } },
      {
        method: "POST",
        url: "/v1/reason",
        body: {
          taskFrame: {
            id: "tf_1",
            scope,
            taskType: "operations",
            goals: [],
            problems: [],
            scenarioTags: [],
            constraints: [],
            entities: [],
            requiredAtomTypes: [],
          },
        },
      },
      {
        method: "POST",
        url: "/v1/ingest",
        body: { rawInput: RAW_INPUT, scope, sourceType: "chat", sourceSessionId: "sess_1" },
      },
      {
        method: "POST",
        url: "/v1/distill",
        body: { rawInput: RAW_INPUT, scope, sourceType: "chat", sourceSessionId: "sess_1" },
      },
      {
        method: "POST",
        url: "/v1/write-back",
        body: { rawInput: RAW_INPUT, scope, sourceType: "chat", sourceSessionId: "sess_1" },
      },
      { method: "POST", url: "/v1/evidence/resolve", body: { scope, atomId: "atm_1" } },
      { method: "POST", url: "/v1/repair/indexes", body: { scope } },
    ];
    for (const route of routes) {
      const response = await routeCogniWeaveHttpRequest(
        service,
        {
          method: route.method,
          url: route.url,
          headers: authHeaders(),
          body: JSON.stringify(route.body),
        },
        noBinding,
      );
      expect({ url: route.url, status: response.status, body: response.body }).toEqual({
        url: route.url,
        status: 403,
        body: { error: "subject_binding_denied" },
      });
    }
  });

  it("denies declared-scope writes for a cross-subject principal in an allowed workspace", async () => {
    const { service, opts } = await setup();
    const response = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "POST",
        url: "/v1/tasks/frame",
        headers: authHeaders({}, "tok_other_subject"),
        body: JSON.stringify({ rawInput: RAW_INPUT, scope }),
      },
      opts,
    );
    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: "subject_binding_denied" });
  });

  it("denies declared-scope writes after the subject binding is revoked", async () => {
    const { service, metadataStore, opts } = await setup();
    const live = await metadataStore.listMemorySubjectBindings!({ scope, liveOnly: true });
    for (const binding of live) {
      await metadataStore.saveMemorySubjectBinding({ ...binding, unboundAt: "2026-11-27T00:00:00.000Z" });
    }
    const response = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "POST",
        url: "/v1/write-back",
        headers: authHeaders(),
        body: JSON.stringify({ rawInput: RAW_INPUT, scope, sourceType: "chat", sourceSessionId: "sess_revoked" }),
      },
      opts,
    );
    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: "subject_binding_denied" });
  });

  it("filters /v1/memory-resources so same-workspace resources for other subjects are not listed", async () => {
    const { service, engine, adapter, opts, metadataStore } = await setup();
    await seed(service, engine);
    const dataPlaneId = await metadataStore.ensureDataPlaneId();
    const live = await metadataStore.listMemorySubjectBindings!({
      tenantId: subject.tenantId,
      dataPlaneId,
      scope,
      liveOnly: true,
    });
    const bindingId = live[0]?.id;
    expect(bindingId).toBeTruthy();

    const otherSubject: MemorySubject = { tenantId: "t_1", ownerType: "user", ownerId: "u_other" };
    const otherBinding = createMemorySubjectBinding({
      partition: createMemoryPartitionKeyV1(dataPlaneId, scope),
      scope,
      subject: otherSubject,
    });

    await adapter.registerResource({
      resourceId: "res_self",
      resourceType: "user_memory",
      tenantId: "t_1",
      ownerType: "user",
      ownerId: "u_1",
      subjectBindingId: bindingId!,
      scope,
      visibility: "private",
      privacyLevel: "private",
      lifecycleStatus: "active",
      supportedAtomTypes: [],
      capabilities: ["retrieve"],
      sourceAuthority: "user",
      evidenceSupport: true,
    });
    await adapter.registerResource({
      resourceId: "res_other_subject",
      resourceType: "user_memory",
      tenantId: "t_1",
      ownerType: "user",
      ownerId: "u_other",
      subjectBindingId: otherBinding.id,
      scope,
      visibility: "private",
      privacyLevel: "private",
      lifecycleStatus: "active",
      supportedAtomTypes: [],
      capabilities: ["retrieve"],
      sourceAuthority: "user",
      evidenceSupport: true,
    });

    const listed = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: "/v1/memory-resources",
        headers: authHeaders({ "x-cogniweave-workspace-id": "ws_1" }),
      },
      opts,
    );
    expect(listed.status).toBe(200);
    expect((listed.body as Array<{ resourceId: string }>).map((row) => row.resourceId)).toEqual(["res_self"]);
  });

  it("rejects a REST principal whose tenant differs from its subject tenant", async () => {
    const { service, opts } = await setup();
    const response = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "POST",
        url: "/v1/tasks/frame",
        headers: { authorization: "Bearer tok_mismatch", "x-cogniweave-tenant-id": "t_a" },
        body: JSON.stringify({ rawInput: RAW_INPUT, scope }),
      },
      opts,
    );
    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: "invalid_token" });
  });
});

describe("CW-09-02 REST trusted principal provider (unit)", () => {
  it("resolves a provider principal and fails closed when the provider throws or the token is unknown", async () => {
    const provider = createDenyByDefaultPrincipalProvider([
      {
        token: "good_tok",
        principal: {
          tenantId: "t_1",
          userId: "u_1",
          subject: { tenantId: "t_1", ownerType: "user", ownerId: "u_1" },
        },
      },
    ]);
    const engine = new InMemoryCogniWeaveEngine(
      {
        environment: "service",
        metadataBackend: "memory",
        graphBackend: "memory",
        evidenceBackend: "memory",
        vectorBackend: "memory",
      },
      { runtime: createTrustedRuntime({ environment: "service", principalProvider: provider }) },
    );
    const service = new CogniWeaveRestService(engine);

    const ok = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: "/v1/metrics",
        headers: { authorization: "Bearer good_tok", "x-cogniweave-tenant-id": "t_1" },
      },
    );
    expect(ok.status).toBe(200);

    const forged = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: "/v1/metrics",
        headers: { authorization: "Bearer forged", "x-cogniweave-tenant-id": "t_1" },
      },
    );
    expect(forged.status).toBe(401);
    expect(forged.body).toEqual({ error: "invalid_token" });

    const throwingEngine = new InMemoryCogniWeaveEngine(
      {
        environment: "service",
        metadataBackend: "memory",
        graphBackend: "memory",
        evidenceBackend: "memory",
        vectorBackend: "memory",
      },
      {
        runtime: createTrustedRuntime({
          environment: "service",
          principalProvider: {
            async resolvePrincipal() {
              throw new Error("idp down");
            },
          },
        }),
      },
    );
    const down = await routeCogniWeaveHttpRequest(
      new CogniWeaveRestService(throwingEngine),
      {
        method: "GET",
        url: "/v1/metrics",
        headers: { authorization: "Bearer good_tok", "x-cogniweave-tenant-id": "t_1" },
      },
    );
    expect(down.status).toBe(503);
    expect(down.body).toEqual({ error: "principal_unavailable" });
  });
});
