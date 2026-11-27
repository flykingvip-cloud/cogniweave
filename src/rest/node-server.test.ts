import type { IncomingMessage, ServerResponse } from "node:http";
import { describe, expect, it } from "vitest";
import { InMemoryCogniWeaveEngine } from "../runtime/in-memory-engine.js";
import { handleCogniWeaveHttpRequest, routeCogniWeaveHttpRequest } from "./node-server.js";
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
      { requireAuth: false },
    );
    const evidenceRefsResponse = await routeCogniWeaveHttpRequest(
      service,
      {
        method: "GET",
        url: "/v1/atoms/atm_1/evidence-refs",
        headers: {},
      },
      { requireAuth: false },
    );

    expect(traceResponse.status).toBe(200);
    expect(traceResponse.body).toEqual({ atomId: "atm_1" });
    expect(evidenceRefsResponse.status).toBe(200);
    expect(evidenceRefsResponse.body).toEqual(["atm_1"]);
  });

  it("enforces fail-closed auth, tenant matching, and protects /v1/metrics in service mode (CW-07A)", async () => {
    const engine = new InMemoryCogniWeaveEngine({
      environment: "service",
      metadataBackend: "memory",
      graphBackend: "memory",
      evidenceBackend: "memory",
      vectorBackend: "memory",
    });
    const service = new CogniWeaveRestService(engine);
    const opts = {
      validateToken: async (token: string) =>
        token === "valid_tok" ? { tenantId: "t_1", userId: "u_1" } : null,
    };

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
  });
});
