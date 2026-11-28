import { describe, expect, it } from "vitest";
import { createDenyByDefaultPrincipalProvider } from "../auth/principal.js";
import { createTrustedRuntime } from "../auth/trusted-runtime.js";
import { createCogniWeaveRuntime } from "../index.js";
import { routeCogniWeaveHttpRequest } from "../rest/node-server.js";

const localConfig = {
  environment: "local" as const,
  metadataBackend: "memory" as const,
  graphBackend: "memory" as const,
  evidenceBackend: "memory" as const,
  vectorBackend: "memory" as const,
};

const serviceConfig = {
  environment: "service" as const,
  metadataBackend: "memory" as const,
  graphBackend: "memory" as const,
  evidenceBackend: "memory" as const,
  vectorBackend: "memory" as const,
};

describe("createCogniWeaveRuntime", () => {
  it("creates a connected engine, service, and server", () => {
    const runtime = createCogniWeaveRuntime(localConfig);

    expect(runtime.engine).toBeDefined();
    expect(runtime.service).toBeDefined();
    expect(runtime.server).toBeDefined();
    expect(runtime.config.metadataBackend).toBe("memory");
  });

  it("wires the engine-held runtime into HTTP routing without a public handle", async () => {
    const created = createCogniWeaveRuntime(localConfig);
    expect((created.engine as { trustedRuntime?: unknown }).trustedRuntime).toBeUndefined();
    expect("trustedRuntime" in created.engine).toBe(false);
    const health = await routeCogniWeaveHttpRequest(created.service, {
      method: "GET",
      url: "/healthz",
      headers: {},
    });
    expect(health.status).toBe(200);
  });

  it("keeps authorized service REST working and missing identity fail-closed", async () => {
    const sealed = createTrustedRuntime({
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
    });
    const created = createCogniWeaveRuntime(serviceConfig, { runtime: sealed });
    expect((created.engine as { trustedRuntime?: unknown }).trustedRuntime).toBeUndefined();

    const unauth = await routeCogniWeaveHttpRequest(created.service, {
      method: "GET",
      url: "/v1/metrics",
      headers: {},
    });
    expect(unauth.status).toBe(401);

    const authed = await routeCogniWeaveHttpRequest(created.service, {
      method: "GET",
      url: "/v1/metrics",
      headers: {
        authorization: "Bearer valid_tok",
        "x-cogniweave-tenant-id": "t_1",
      },
    });
    expect(authed.status).toBe(200);
  });
});
