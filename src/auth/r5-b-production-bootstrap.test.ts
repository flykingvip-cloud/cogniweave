import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import { InMemoryMetadataStore } from "../storage/in-memory.js";
import { ProductionBootstrapError } from "../errors.js";
import { PrincipalUnavailableError } from "../errors.js";
import { createDenyByDefaultPrincipalProvider } from "./principal.js";
import { createMemoryDelegationAuthorizationStore } from "./delegation.js";
import { createDenyByDefaultBindingQuery } from "./canonical-scope.js";
import { getSealedProcessTrustMode, isProductionProcess } from "./process-trust.js";
import {
  bootstrapProductionTrustedRuntime,
  getEngineProductionAssemblyAudit,
  getProductionAssemblyAudit,
  listFailedProductionBootstrapAudits,
  runWithSimulatedProductionProcess,
  submitProductionAssemblyAudit,
  type ProductionBootstrapResult,
} from "./production-bootstrap.js";
import { createTrustedRuntime, createImplicitLocalRuntime, isVerifiableTrustedRuntime } from "./trusted-runtime.js";
import { InMemoryCogniWeaveEngine } from "../runtime/in-memory-engine.js";
import { createCogniWeaveRuntime } from "../runtime/bootstrap.js";
import { createAdapterBundle } from "../adapters/factory.js";
import { CogniWeaveRestService } from "../rest/service.js";
import { routeCogniWeaveHttpRequest } from "../rest/node-server.js";
import { runOptimizationJob } from "../optimization/index.js";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const tsxBin = join(packageRoot, "node_modules", ".bin", "tsx");

const SCOPE = {
  workspaceId: "ws_1",
  projectId: "proj_1",
  agentId: "agent_main",
  visibility: "private" as const,
};
const SUBJECT = { tenantId: "t_1", ownerType: "user" as const, ownerId: "u_1" };
const PRINCIPAL = {
  tenantId: "t_1",
  userId: "u_1",
  allowedWorkspaceIds: ["ws_1"],
  subject: SUBJECT,
};
const TOKEN = "valid_tok";

const simulatedFixture = {
  authorityId: "authority_test_r5b",
  engineEnvironment: "service" as const,
  principalBindings: [{ token: TOKEN, principal: PRINCIPAL }],
  authoritativeScopes: [{ tenantId: "t_1", subject: SUBJECT, scope: SCOPE }],
};

const serviceConfig = {
  environment: "service" as const,
  metadataBackend: "memory",
  graphBackend: "memory",
  evidenceBackend: "memory",
  vectorBackend: "memory",
};

function expectFailedClosed(error: unknown, reason: string): ProductionBootstrapError {
  expect(error).toBeInstanceOf(ProductionBootstrapError);
  const err = error as ProductionBootstrapError;
  expect(err.reason).toBe(reason);
  expect(err.audit.verificationResult).toBe("failed");
  expect(err.audit.failureReason).toBe(reason);
  expect(submitProductionAssemblyAudit(err.audit)).toBe(false);
  expect(getProductionAssemblyAudit(err.audit)).toBeUndefined();
  expect(getProductionAssemblyAudit({ assemblyId: err.audit.assemblyId, verificationResult: "passed" })).toBeUndefined();
  return err;
}

function assertNoServiceEscape(result: ProductionBootstrapResult): void {
  const forbidden = [
    "metadataStore",
    "graphStore",
    "vectorStore",
    "principalProvider",
    "bindingQuery",
    "delegationStore",
    "trustedRuntime",
    "assembly",
    "stores",
    "bundle",
  ];
  for (const key of forbidden) {
    expect(key in result).toBe(false);
    expect((result as unknown as Record<string, unknown>)[key]).toBeUndefined();
  }
  const engine = result.engine as unknown as Record<string, unknown>;
  for (const key of ["metadataStore", "graphStore", "vectorStore", "trustedRuntime", "principalProvider", "bindingQuery", "delegationStore"]) {
    expect(engine[key]).toBeUndefined();
    expect(key in engine).toBe(false);
  }
}

function runChild(env: Record<string, string | undefined>, source: string): { status: number | null; stdout: string; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), "cw-r5b-child-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ type: "module" }), "utf8");
  const file = join(dir, "entry.mts");
  writeFileSync(file, source, "utf8");
  const childEnv = { ...process.env };
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) {
      delete childEnv[key];
    } else {
      childEnv[key] = value;
    }
  }
  const result = spawnSync(tsxBin, [file], {
    cwd: packageRoot,
    encoding: "utf8",
    env: childEnv,
  });
  return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

describe("CW-09-02-R5-B production bootstrap trust boundary", () => {
  it("seals the host test process as non-production and unmixable", () => {
    expect(getSealedProcessTrustMode()).toBe("non_production");
    expect(isProductionProcess()).toBe(false);
  });

  it("1. refuses an ordinary caller creating a production Trusted Runtime and fail-closes", async () => {
    const runtime = createTrustedRuntime({
      environment: "service",
      principalProvider: createDenyByDefaultPrincipalProvider([{ token: TOKEN, principal: PRINCIPAL }]),
    });
    expect(isVerifiableTrustedRuntime(runtime)).toBe(true);
    expect(runtime.environment).toBe("service");
    expect(getProductionAssemblyAudit(runtime)).toBeUndefined();
    const engine = new InMemoryCogniWeaveEngine(serviceConfig, { runtime });
    expect(getEngineProductionAssemblyAudit(engine)).toBeUndefined();

    let caught: unknown;
    try {
      await bootstrapProductionTrustedRuntime();
    } catch (error) {
      caught = error;
    }
    expectFailedClosed(caught, "process_not_production");
    expect(getEngineProductionAssemblyAudit(engine)).toBeUndefined();
    expect(submitProductionAssemblyAudit({ verificationResult: "passed", trustClass: "production" })).toBe(false);
  });

  it("2. ignores a forged production environment identifier after the process snapshot is sealed", async () => {
    const previousMode = process.env.COGNIWEAVE_RUNTIME_MODE;
    const previousAuthority = process.env.COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID;
    const previousEngine = process.env.COGNIWEAVE_ENGINE_ENVIRONMENT;
    process.env.COGNIWEAVE_RUNTIME_MODE = "production";
    process.env.COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID = "forged_authority";
    process.env.COGNIWEAVE_ENGINE_ENVIRONMENT = "service";
    try {
      expect(getSealedProcessTrustMode()).toBe("non_production");
      let caught: unknown;
      try {
        await bootstrapProductionTrustedRuntime();
      } catch (error) {
        caught = error;
      }
      expectFailedClosed(caught, "process_not_production");
      const runtime = createTrustedRuntime({ environment: "cloud" });
      expect(getProductionAssemblyAudit(runtime)).toBeUndefined();
    } finally {
      if (previousMode === undefined) delete process.env.COGNIWEAVE_RUNTIME_MODE;
      else process.env.COGNIWEAVE_RUNTIME_MODE = previousMode;
      if (previousAuthority === undefined) delete process.env.COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID;
      else process.env.COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID = previousAuthority;
      if (previousEngine === undefined) delete process.env.COGNIWEAVE_ENGINE_ENVIRONMENT;
      else process.env.COGNIWEAVE_ENGINE_ENVIRONMENT = previousEngine;
    }
  });

  it("2b. a child process mixing VITEST and production mode fail-closes", () => {
    const result = runChild(
      {
        VITEST: "true",
        COGNIWEAVE_RUNTIME_MODE: "production",
        COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID: "mixed_authority",
        COGNIWEAVE_ENGINE_ENVIRONMENT: "service",
      },
      `
        import { bootstrapProductionTrustedRuntime } from ${JSON.stringify(resolve(packageRoot, "src/auth/production-bootstrap.ts"))};
        import { createTrustedRuntime } from ${JSON.stringify(resolve(packageRoot, "src/auth/trusted-runtime.ts"))};
        const failures = [];
        try {
          await bootstrapProductionTrustedRuntime();
          failures.push("bootstrap_succeeded");
        } catch (error) {
          failures.push((error && error.reason) || error.name || "error");
        }
        try {
          createTrustedRuntime({ environment: "service" });
          failures.push("createTrustedRuntime_succeeded");
        } catch (error) {
          failures.push((error && error.reason) || error.name || "error");
        }
        console.log(JSON.stringify({ failures }));
      `,
    );
    expect(result.status, result.stderr + result.stdout).toBe(0);
    const payload = JSON.parse(result.stdout.trim().split("\n").at(-1) ?? "{}") as { failures: string[] };
    expect(payload.failures).toContain("mixed_test_and_production_configuration");
    expect(payload.failures).not.toContain("bootstrap_succeeded");
    expect(payload.failures).not.toContain("createTrustedRuntime_succeeded");
  });

  it("3-5. refuses caller-injected principal, binding query, and delegation store", async () => {
    const forgedProvider = createDenyByDefaultPrincipalProvider([{ token: TOKEN, principal: PRINCIPAL }]);
    const forgedQuery = createDenyByDefaultBindingQuery([]);
    const forgedDelegation = createMemoryDelegationAuthorizationStore([]);
    for (const input of [
      { principalProvider: forgedProvider },
      { bindingQuery: forgedQuery },
      { delegationStore: forgedDelegation },
      { environment: "service", principalProvider: forgedProvider, bindingQuery: forgedQuery, delegationStore: forgedDelegation },
    ]) {
      let caught: unknown;
      try {
        await (bootstrapProductionTrustedRuntime as unknown as (input: unknown) => Promise<unknown>)(input);
      } catch (error) {
        caught = error;
      }
      expectFailedClosed(caught, "caller_injection_rejected");
    }

    await runWithSimulatedProductionProcess(simulatedFixture, async () => {
      let caught: unknown;
      try {
        await (bootstrapProductionTrustedRuntime as unknown as (input: unknown) => Promise<unknown>)({
          principalProvider: forgedProvider,
          bindingQuery: forgedQuery,
          delegationStore: forgedDelegation,
        });
      } catch (error) {
        caught = error;
      }
      expectFailedClosed(caught, "caller_injection_rejected");
      expect(listFailedProductionBootstrapAudits().some((audit) => audit.failureReason === "caller_injection_rejected")).toBe(true);
      // A failed injection must not leave a usable production assembly.
      try {
        createTrustedRuntime({
          environment: "service",
          principalProvider: forgedProvider,
          bindingQuery: forgedQuery,
          delegationStore: forgedDelegation,
        });
        throw new Error("createTrustedRuntime unexpectedly succeeded in simulated production");
      } catch (error) {
        expectFailedClosed(error, "public_api_not_production_authority");
      }
    });
  });

  it("6. real production startup fail-closes when required services are missing", () => {
    const result = runChild(
      {
        VITEST: undefined,
        COGNIWEAVE_TEST_HARNESS: undefined,
        COGNIWEAVE_RUNTIME_MODE: "production",
        COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID: "real_authority",
        COGNIWEAVE_ENGINE_ENVIRONMENT: "service",
        COGNIWEAVE_METADATA_BACKEND: "memory",
      },
      `
        import { bootstrapProductionTrustedRuntime } from ${JSON.stringify(resolve(packageRoot, "src/auth/production-bootstrap.ts"))};
        try {
          const created = await bootstrapProductionTrustedRuntime();
          console.log(JSON.stringify({ ok: true, assemblyId: created.audit.assemblyId }));
        } catch (error) {
          console.log(JSON.stringify({
            ok: false,
            reason: error?.reason ?? null,
            verificationResult: error?.audit?.verificationResult ?? null,
            failureReason: error?.audit?.failureReason ?? null,
          }));
        }
      `,
    );
    expect(result.status, result.stderr + result.stdout).toBe(0);
    const payload = JSON.parse(result.stdout.trim().split("\n").at(-1) ?? "{}") as Record<string, unknown>;
    expect(payload.ok).toBe(false);
    expect(payload.verificationResult).toBe("failed");
    expect(["required_service_missing", "untrusted_service_implementation", "missing_bootstrap_authority"]).toContain(
      payload.reason,
    );
  });

  it("7. rejects an untrusted Canonical Store replacement and does not mutate production data", async () => {
    const retained = new InMemoryMetadataStore();
    await runWithSimulatedProductionProcess(simulatedFixture, async () => {
      const created = await bootstrapProductionTrustedRuntime();
      let constructCaught: unknown;
      try {
        new InMemoryCogniWeaveEngine(serviceConfig, {
          metadataStore: retained,
          runtime: created.runtime,
        });
      } catch (error) {
        constructCaught = error;
      }
      expectFailedClosed(constructCaught, "engine_construction_rejected");

      let bundleCaught: unknown;
      try {
        createAdapterBundle(serviceConfig);
      } catch (error) {
        bundleCaught = error;
      }
      expectFailedClosed(bundleCaught, "production_factory_denied");

      await retained.saveAtom({
        id: "atm_untrusted",
        atomType: "strategy",
        scope: SCOPE,
        claim: { type: "procedural", statement: "planted via untrusted store" },
        trigger: { conditions: [], contextTags: [] },
        applicability: { include: [], exclude: [] },
        provenance: { sourceEventIds: [], evidenceRefs: [] },
        versioning: { version: 1 },
        state: { status: "active", conflictsWith: [] },
        metrics: { confidence: 1, reuseCount: 0 },
        dedupKey: "planted",
      } as never);
      const atoms = await created.engine.queryAtoms({
        scope: SCOPE,
        caller: SUBJECT,
        authorization: { bearerToken: TOKEN },
      });
      const ids = atoms.map((hit) => hit.atom.id);
      expect(ids).not.toContain("atm_untrusted");
    });
  });

  it("8. does not hand back store or trusted-service references that can bypass Engine authorization", async () => {
    const priorStore = new InMemoryMetadataStore();
    await runWithSimulatedProductionProcess(simulatedFixture, async () => {
      const created = await bootstrapProductionTrustedRuntime();
      assertNoServiceEscape(created);
      expect(Object.isFrozen(created.audit)).toBe(true);
      expect(created.audit.verificationResult).toBe("passed");
      expect(created.audit.bootstrapAuthorityId).toBe("authority_test_r5b");
      expect(created.audit.canonicalStoreBindingQueryAssociation).toBe("bound_same_assembly");

      await priorStore.saveAtom({
        id: "atm_prior",
        atomType: "strategy",
        scope: SCOPE,
        claim: { type: "procedural", statement: "retained pre-bootstrap store" },
        trigger: { conditions: [], contextTags: [] },
        applicability: { include: [], exclude: [] },
        provenance: { sourceEventIds: [], evidenceRefs: [] },
        versioning: { version: 1 },
        state: { status: "active", conflictsWith: [] },
        metrics: { confidence: 1, reuseCount: 0 },
        dedupKey: "prior",
      } as never);

      let unauthDenied = false;
      try {
        await created.engine.writeBack({
          rawInput: "Current throughput is dropping and the external API is slow. Should we add synchronous retries?",
          scope: SCOPE,
          sourceType: "chat",
          sourceSessionId: "sess_unauth",
        });
      } catch (error) {
        unauthDenied = error instanceof PrincipalUnavailableError;
      }
      expect(unauthDenied).toBe(true);

      const authorized = await created.engine.writeBack({
        rawInput: "Current throughput is dropping and the external API is slow. Should we add synchronous retries?",
        scope: SCOPE,
        sourceType: "chat",
        sourceSessionId: "sess_auth",
        authorization: { bearerToken: TOKEN },
      });
      expect(authorized.status).toBe("COMPLETED");

      const priorAtoms = await priorStore.listAtoms?.() ?? [];
      expect(priorAtoms.some((atom: { id: string }) => atom.id === "atm_prior")).toBe(true);
      const leakedJournal = priorAtoms.some((atom: { id?: string; journalId?: string }) => atom.id === authorized.journalId);
      expect(leakedJournal).toBe(false);
    });
  });

  it("9. REST, Engine Direct, and Optimization cannot unpack the assembly and still honor authorization", async () => {
    await runWithSimulatedProductionProcess(simulatedFixture, async () => {
      const created = await bootstrapProductionTrustedRuntime();
      const engine = created.engine as unknown as Record<string, unknown>;
      const extractAttempts = [
        engine.trustedRuntime,
        engine.principalProvider,
        engine.bindingQuery,
        engine.delegationStore,
        engine.metadataStore,
        engine["#trustedRuntime"],
        created.runtime && (created.runtime as unknown as Record<string, unknown>).principalProvider,
        created.audit && (created.audit as unknown as Record<string, unknown>).principalProvider,
      ];
      expect(extractAttempts.every((value) => value === undefined)).toBe(true);

      const unauth = await routeCogniWeaveHttpRequest(created.service, {
        method: "GET",
        url: "/v1/metrics",
        headers: {},
      });
      expect(unauth.status).toBe(401);

      const authed = await routeCogniWeaveHttpRequest(created.service, {
        method: "GET",
        url: "/v1/metrics",
        headers: { authorization: `Bearer ${TOKEN}`, "x-cogniweave-tenant-id": "t_1" },
      });
      expect(authed.status).toBe(200);

      const write = await created.engine.writeBack({
        rawInput: "Current throughput is dropping and the external API is slow. Should we add synchronous retries?",
        scope: SCOPE,
        sourceType: "chat",
        sourceSessionId: "sess_r5b_9",
        authorization: { bearerToken: TOKEN },
      });
      expect(write.status).toBe("COMPLETED");

      const journal = await routeCogniWeaveHttpRequest(created.service, {
        method: "GET",
        url: `/v1/journals/${write.journalId}`,
        headers: {
          authorization: `Bearer ${TOKEN}`,
          "x-cogniweave-tenant-id": "t_1",
          "x-cogniweave-workspace-id": SCOPE.workspaceId,
          "x-cogniweave-project-id": SCOPE.projectId,
          "x-cogniweave-agent-id": SCOPE.agentId,
          "x-cogniweave-visibility": SCOPE.visibility,
        },
      });
      expect(journal.status).toBe(200);

      const atomA = {
        id: "atm_opt_a",
        atomType: "strategy",
        scope: SCOPE,
        claim: { type: "procedural", statement: "Always verify forward-only ancestry before production cutover." },
        trigger: { conditions: ["production_cutover"], contextTags: ["release"] },
        applicability: { include: ["prod"], exclude: [] },
        provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_1"] },
        versioning: { version: 1 },
        state: { status: "active", conflictsWith: [] },
        metrics: { confidence: 0.85, reuseCount: 3 },
        dedupKey: "k_opt",
      };
      const atomB = { ...atomA, id: "atm_opt_b", provenance: { sourceEventIds: ["evt_2"], evidenceRefs: ["evd_2"] } };
      const job = await runOptimizationJob({
        tenantId: "t_1",
        subjectId: "u_1",
        scope: SCOPE,
        optimizationType: "consolidation",
        atoms: [atomA, atomB] as never,
        executionContext: {
          actorUserId: "u_1",
          tenantId: "t_1",
          scope: SCOPE,
          caller: SUBJECT,
          dataPlaneId: created.audit.canonicalDataPlaneId ?? "missing_data_plane",
        },
        runtime: created.runtime,
        authorization: { bearerToken: TOKEN },
        metadataStore: new InMemoryMetadataStore(),
      } as never);
      expect(job.status === "completed" || job.authorization?.decision === "allow").toBe(true);

      let optDenied = false;
      try {
        await runOptimizationJob({
          tenantId: "t_1",
          subjectId: "u_1",
          scope: SCOPE,
          optimizationType: "consolidation",
          atoms: [atomA, atomB] as never,
          executionContext: {
            actorUserId: "u_1",
            tenantId: "t_1",
            scope: SCOPE,
            caller: SUBJECT,
            dataPlaneId: created.audit.canonicalDataPlaneId ?? "missing_data_plane",
          },
          runtime: created.runtime,
          metadataStore: new InMemoryMetadataStore(),
        } as never);
      } catch (error) {
        optDenied = error instanceof PrincipalUnavailableError;
      }
      expect(optDenied).toBe(true);
    });
  });

  it("10. reflection, prototype, Proxy, and serialization cannot extract trusted services", async () => {
    await runWithSimulatedProductionProcess(simulatedFixture, async () => {
      const created = await bootstrapProductionTrustedRuntime();
      const surfaces: object[] = [created, created.engine, created.runtime, created.audit, created.service];
      const leaked: string[] = [];
      for (const surface of surfaces) {
        const names = [
          ...Object.keys(surface),
          ...Object.getOwnPropertyNames(surface),
          ...Reflect.ownKeys(surface).map((key) => String(key)),
          ...Object.getOwnPropertyNames(Object.getPrototypeOf(surface) ?? {}),
        ];
        for (const name of names) {
          if (
            /^(metadataStore|graphStore|vectorStore|principalProvider|bindingQuery|delegationStore|trustedRuntime|#trustedRuntime)$/.test(
              name,
            )
          ) {
            leaked.push(name);
          }
        }
        const inspected = inspect(surface, { showHidden: true, depth: 2 });
        if (surface !== created.audit) {
          const looksLikeLiveService =
            /resolvePrincipal\s*[:(]/.test(inspected) ||
            /listLiveBindings\s*[:(]/.test(inspected) ||
            /getActiveDelegation\s*[:(]/.test(inspected) ||
            /#metadataStore/.test(inspected);
          if (looksLikeLiveService) {
            leaked.push("inspect");
          }
        }
        try {
          const cloned = structuredClone(surface) as Record<string, unknown>;
          expect(cloned.principalProvider).toBeUndefined();
          expect(cloned.bindingQuery).toBeUndefined();
          expect(cloned.delegationStore).toBeUndefined();
          expect(cloned.metadataStore).toBeUndefined();
        } catch {
          // Non-cloneable surfaces must not yield trusted services either.
        }
        const proxy = new Proxy(surface, {
          get(target, prop, receiver) {
            return Reflect.get(target, prop, receiver);
          },
        }) as Record<string | symbol, unknown>;
        expect(proxy.metadataStore).toBeUndefined();
        expect(proxy.principalProvider).toBeUndefined();
        expect(proxy.bindingQuery).toBeUndefined();
        expect(JSON.stringify(created.audit)).not.toMatch(/password|api[_-]?key|token|connectionString/i);
      }
      expect(leaked).toEqual([]);
      expect(submitProductionAssemblyAudit(JSON.parse(JSON.stringify(created.audit)))).toBe(false);
    });
  });

  it("11. refuses repeated create, replace, or re-bind of a production assembly", async () => {
    await runWithSimulatedProductionProcess(simulatedFixture, async () => {
      const first = await bootstrapProductionTrustedRuntime();
      const firstAudit = first.audit.assemblyId;
      let secondCaught: unknown;
      try {
        await bootstrapProductionTrustedRuntime();
      } catch (error) {
        secondCaught = error;
      }
      expectFailedClosed(secondCaught, "assembly_already_sealed");
      expect(getEngineProductionAssemblyAudit(first.engine)?.assemblyId).toBe(firstAudit);
      expect(getProductionAssemblyAudit(first.runtime)?.assemblyId).toBe(firstAudit);
      const stillWorks = await routeCogniWeaveHttpRequest(first.service, {
        method: "GET",
        url: "/v1/metrics",
        headers: { authorization: `Bearer ${TOKEN}`, "x-cogniweave-tenant-id": "t_1" },
      });
      expect(stillWorks.status).toBe(200);
    });
  });

  it("12. refuses mixed production and test configuration", async () => {
    await runWithSimulatedProductionProcess(simulatedFixture, async () => {
      let implicitCaught: unknown;
      try {
        createImplicitLocalRuntime();
      } catch (error) {
        implicitCaught = error;
      }
      expectFailedClosed(implicitCaught, "public_api_not_production_authority");

      let createCaught: unknown;
      try {
        createTrustedRuntime({ environment: "local", requireAuth: false, allowLocalInjection: true, injectedPrincipal: PRINCIPAL });
      } catch (error) {
        createCaught = error;
      }
      expectFailedClosed(createCaught, "public_api_not_production_authority");

      let runtimeCaught: unknown;
      try {
        createCogniWeaveRuntime(serviceConfig);
      } catch (error) {
        runtimeCaught = error;
      }
      expectFailedClosed(runtimeCaught, "public_api_not_production_authority");
    });
  });

  it("records a complete redacted audit on a successful simulated production bootstrap", async () => {
    await runWithSimulatedProductionProcess(simulatedFixture, async () => {
      const created = await bootstrapProductionTrustedRuntime();
      const audit = created.audit;
      expect(audit.assemblyId.startsWith("prod_")).toBe(true);
      expect(audit.trustClass).toBe("simulated_production");
      expect(audit.runtimeEnvironment).toBe("service");
      expect(audit.processTrustMode).toBe("production");
      expect(audit.bootstrapAuthorityId).toBe("authority_test_r5b");
      expect(audit.createdAt).toMatch(/^\d{4}-/);
      expect(audit.verificationResult).toBe("passed");
      expect(audit.failureReason).toBeUndefined();
      expect(audit.services.principalProvider?.verified).toBe(true);
      expect(audit.services.bindingQuery?.verified).toBe(true);
      expect(audit.services.delegationStore?.verified).toBe(true);
      expect(audit.services.metadataStore?.verified).toBe(true);
      expect(audit.canonicalStoreBindingQueryAssociation).toBe("bound_same_assembly");
      const serialized = JSON.stringify(audit);
      expect(serialized).not.toMatch(/password|api[_-]?key|secret|access[_-]?token|connectionString|postgres:\/\//i);
      expect(getEngineProductionAssemblyAudit(created.engine)).toEqual(audit);
      expect(submitProductionAssemblyAudit(audit)).toBe(false);
    });
  });
});
