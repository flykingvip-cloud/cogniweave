import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { InMemoryMetadataStore } from "../storage/in-memory.js";
import { ProductionBootstrapError } from "../errors.js";
import { createDenyByDefaultPrincipalProvider } from "./principal.js";
import { createMemoryDelegationAuthorizationStore } from "./delegation.js";
import { createDenyByDefaultBindingQuery } from "./canonical-scope.js";
import {
  getProcessTrustSnapshot,
  getSealedProcessTrustMode,
  isProductionProcess,
  isProductionTrustBoundaryActive,
} from "./process-trust.js";
import { createTrustedRuntime, createImplicitLocalRuntime } from "./trusted-runtime.js";
import { InMemoryCogniWeaveEngine } from "../runtime/in-memory-engine.js";
import { createCogniWeaveRuntime } from "../runtime/bootstrap.js";
import { createAdapterBundle } from "../adapters/factory.js";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const tsxBin = join(packageRoot, "node_modules", ".bin", "tsx");

const processTrustPath = JSON.stringify(resolve(packageRoot, "src/auth/process-trust.ts"));
const productionBootstrapPath = JSON.stringify(resolve(packageRoot, "src/auth/production-bootstrap.ts"));
const trustedRuntimePath = JSON.stringify(resolve(packageRoot, "src/auth/trusted-runtime.ts"));
const enginePath = JSON.stringify(resolve(packageRoot, "src/runtime/in-memory-engine.ts"));
const runtimeBootstrapPath = JSON.stringify(resolve(packageRoot, "src/runtime/bootstrap.ts"));
const factoryPath = JSON.stringify(resolve(packageRoot, "src/adapters/factory.ts"));
const indexPath = JSON.stringify(resolve(packageRoot, "src/index.ts"));

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

const serviceConfig = {
  environment: "service" as const,
  metadataBackend: "memory",
  graphBackend: "memory",
  evidenceBackend: "memory",
  vectorBackend: "memory",
};

type ChildResult = { status: number | null; stdout: string; stderr: string };

function runChild(env: Record<string, string | undefined>, source: string): ChildResult {
  const dir = mkdtempSync(join(tmpdir(), "cw-r5b-r1-child-"));
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

function lastJson(result: ChildResult): Record<string, unknown> {
  expect(result.status, result.stderr + result.stdout).toBe(0);
  const line = result.stdout.trim().split("\n").at(-1) ?? "{}";
  return JSON.parse(line) as Record<string, unknown>;
}

const productionChildEnv = {
  VITEST: undefined,
  COGNIWEAVE_TEST_HARNESS: undefined,
  COGNIWEAVE_RUNTIME_MODE: "production",
  COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID: "authority_r5b_r1",
  COGNIWEAVE_ENGINE_ENVIRONMENT: "service",
  COGNIWEAVE_METADATA_BACKEND: "memory",
};

const nonProductionChildEnv = {
  VITEST: undefined,
  COGNIWEAVE_TEST_HARNESS: undefined,
  COGNIWEAVE_RUNTIME_MODE: undefined,
  COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID: undefined,
  COGNIWEAVE_ENGINE_ENVIRONMENT: undefined,
};

describe("CW-09-02-R5-B-R1 process trust snapshot is not decided by first SDK API call", () => {
  it("host test process remains ordinary non-production and unestablished", () => {
    const snapshot = getProcessTrustSnapshot();
    expect(snapshot.mode).toBe("non_production");
    expect(snapshot.productionTrustEstablished).toBe(false);
    expect(snapshot.establishment).toBe("unestablished");
    expect(snapshot.mixedConfiguration).toBe(false);
    expect(isProductionProcess()).toBe(false);
    expect(isProductionTrustBoundaryActive()).toBe(false);
    expect(getSealedProcessTrustMode()).toBe("non_production");
  });

  it("A. after SDK import, before first trust API, mutating env cannot downgrade a production request", () => {
    const initialEnv = { ...productionChildEnv };
    const result = runChild(
      initialEnv,
      `
        const report = {
          scenario: "A",
          initialEnv: {
            COGNIWEAVE_RUNTIME_MODE: "production",
            COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID: "authority_r5b_r1",
            COGNIWEAVE_ENGINE_ENVIRONMENT: "service",
            VITEST: null,
            COGNIWEAVE_TEST_HARNESS: null,
          },
          importOrder: ["src/auth/process-trust.ts", "src/auth/trusted-runtime.ts", "src/auth/production-bootstrap.ts"],
          mutationTiming: "after SDK import, before first trust API call",
          firstTrustApiTiming: "after env mutation",
          expected: "frozen production request preserved; createTrustedRuntime refused; bootstrap is not process_not_production",
        };
        const processTrust = await import(${processTrustPath});
        const trustedRuntime = await import(${trustedRuntimePath});
        const productionBootstrap = await import(${productionBootstrapPath});
        process.env.COGNIWEAVE_RUNTIME_MODE = "non_production";
        process.env.COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID = "forged_after_import";
        process.env.COGNIWEAVE_ENGINE_ENVIRONMENT = "local";
        const snapshot = processTrust.getProcessTrustSnapshot();
        const firstRead = {
          productionRequested: snapshot.productionRequested,
          mode: snapshot.mode,
          productionTrustEstablished: snapshot.productionTrustEstablished,
          isProductionProcess: processTrust.isProductionProcess(),
          boundaryActive: processTrust.isProductionTrustBoundaryActive(),
          authorityId: snapshot.authorityId,
          engineEnvironment: snapshot.engineEnvironment,
        };
        let createTrustedRuntime = "not_called";
        try {
          trustedRuntime.createTrustedRuntime({ environment: "service" });
          createTrustedRuntime = "succeeded";
        } catch (error) {
          createTrustedRuntime = error?.reason ?? error?.name ?? "error";
        }
        let bootstrap = { ok: false, reason: null };
        try {
          await productionBootstrap.bootstrapProductionTrustedRuntime();
          bootstrap = { ok: true, reason: null };
        } catch (error) {
          bootstrap = { ok: false, reason: error?.reason ?? null };
        }
        console.log(JSON.stringify({
          ...report,
          firstRead,
          createTrustedRuntime,
          bootstrap,
          expectedRefusal: "public_api_not_production_authority for createTrustedRuntime; bootstrap must not be process_not_production",
        }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("A");
    expect(payload.firstRead).toMatchObject({
      productionRequested: true,
      mode: "non_production",
      productionTrustEstablished: false,
      isProductionProcess: false,
      boundaryActive: true,
      authorityId: "authority_r5b_r1",
      engineEnvironment: "service",
    });
    expect(payload.createTrustedRuntime).toBe("public_api_not_production_authority");
    expect(payload.bootstrap).toMatchObject({ ok: false });
    expect((payload.bootstrap as { reason: string }).reason).not.toBe("process_not_production");
    expect(["required_service_missing", "untrusted_service_implementation", "missing_bootstrap_authority"]).toContain(
      (payload.bootstrap as { reason: string }).reason,
    );
  });

  it("B. after SDK import, before first trust API, deleting COGNIWEAVE_RUNTIME_MODE cannot downgrade a production request", () => {
    const result = runChild(
      productionChildEnv,
      `
        const report = {
          scenario: "B",
          initialEnv: {
            COGNIWEAVE_RUNTIME_MODE: "production",
            COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID: "authority_r5b_r1",
            COGNIWEAVE_ENGINE_ENVIRONMENT: "service",
          },
          importOrder: ["src/auth/process-trust.ts", "src/auth/trusted-runtime.ts", "src/auth/production-bootstrap.ts"],
          mutationTiming: "after SDK import, before first trust API call, delete COGNIWEAVE_RUNTIME_MODE",
          firstTrustApiTiming: "after env deletion",
          expected: "frozen production request preserved; createTrustedRuntime refused; bootstrap is not process_not_production",
        };
        const processTrust = await import(${processTrustPath});
        const trustedRuntime = await import(${trustedRuntimePath});
        const productionBootstrap = await import(${productionBootstrapPath});
        delete process.env.COGNIWEAVE_RUNTIME_MODE;
        delete process.env.COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID;
        const snapshot = processTrust.getProcessTrustSnapshot();
        let createTrustedRuntime = "not_called";
        try {
          trustedRuntime.createTrustedRuntime({ environment: "local" });
          createTrustedRuntime = "succeeded";
        } catch (error) {
          createTrustedRuntime = error?.reason ?? error?.name ?? "error";
        }
        let bootstrap = { ok: false, reason: null };
        try {
          await productionBootstrap.bootstrapProductionTrustedRuntime();
          bootstrap = { ok: true, reason: null };
        } catch (error) {
          bootstrap = { ok: false, reason: error?.reason ?? null };
        }
        const afterBootstrap = {
          mode: processTrust.getSealedProcessTrustMode(),
          isProductionProcess: processTrust.isProductionProcess(),
          productionRequested: processTrust.getProcessTrustSnapshot().productionRequested,
          productionTrustEstablished: processTrust.getProcessTrustSnapshot().productionTrustEstablished,
        };
        console.log(JSON.stringify({
          ...report,
          firstRead: {
            productionRequested: snapshot.productionRequested,
            mode: snapshot.mode,
            liveEnvMode: process.env.COGNIWEAVE_RUNTIME_MODE ?? null,
          },
          createTrustedRuntime,
          bootstrap,
          afterBootstrap,
        }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("B");
    expect(payload.firstRead).toMatchObject({
      productionRequested: true,
      mode: "non_production",
      liveEnvMode: null,
    });
    expect(payload.createTrustedRuntime).toBe("public_api_not_production_authority");
    expect((payload.bootstrap as { ok: boolean }).ok).toBe(false);
    expect((payload.bootstrap as { reason: string }).reason).not.toBe("process_not_production");
    expect(payload.afterBootstrap).toMatchObject({
      mode: "production",
      isProductionProcess: true,
      productionRequested: true,
      productionTrustEstablished: true,
    });
  });

  it("C. after official trusted start establishes production identity, later env mutation does not change production state", () => {
    const result = runChild(
      productionChildEnv,
      `
        const report = {
          scenario: "C",
          initialEnv: {
            COGNIWEAVE_RUNTIME_MODE: "production",
            COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID: "authority_r5b_r1",
            COGNIWEAVE_ENGINE_ENVIRONMENT: "service",
          },
          importOrder: ["src/auth/production-bootstrap.ts", "src/auth/process-trust.ts", "src/auth/trusted-runtime.ts"],
          mutationTiming: "after bootstrapProductionTrustedRuntime() has applied official production identity",
          firstTrustApiTiming: "bootstrapProductionTrustedRuntime is the first trust API, during trusted start",
          expected: "production identity remains after later env deletion; createTrustedRuntime refused",
        };
        const productionBootstrap = await import(${productionBootstrapPath});
        const processTrust = await import(${processTrustPath});
        const trustedRuntime = await import(${trustedRuntimePath});
        let bootstrap = { ok: false, reason: null, establishedBeforeCatch: null };
        try {
          await productionBootstrap.bootstrapProductionTrustedRuntime();
          bootstrap = { ok: true, reason: null, establishedBeforeCatch: processTrust.isProductionProcess() };
        } catch (error) {
          bootstrap = {
            ok: false,
            reason: error?.reason ?? null,
            establishedBeforeCatch: processTrust.isProductionProcess(),
          };
        }
        const established = {
          mode: processTrust.getSealedProcessTrustMode(),
          isProductionProcess: processTrust.isProductionProcess(),
          productionTrustEstablished: processTrust.getProcessTrustSnapshot().productionTrustEstablished,
        };
        delete process.env.COGNIWEAVE_RUNTIME_MODE;
        process.env.COGNIWEAVE_RUNTIME_MODE = "non_production";
        delete process.env.COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID;
        const afterMutation = {
          mode: processTrust.getSealedProcessTrustMode(),
          isProductionProcess: processTrust.isProductionProcess(),
          productionRequested: processTrust.getProcessTrustSnapshot().productionRequested,
          productionTrustEstablished: processTrust.getProcessTrustSnapshot().productionTrustEstablished,
          authorityId: processTrust.getProcessTrustSnapshot().authorityId,
          liveEnvMode: process.env.COGNIWEAVE_RUNTIME_MODE,
        };
        let createTrustedRuntime = "not_called";
        try {
          trustedRuntime.createTrustedRuntime({ environment: "service" });
          createTrustedRuntime = "succeeded";
        } catch (error) {
          createTrustedRuntime = error?.reason ?? error?.name ?? "error";
        }
        console.log(JSON.stringify({ ...report, bootstrap, established, afterMutation, createTrustedRuntime }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("C");
    expect(payload.bootstrap).toMatchObject({ ok: false, establishedBeforeCatch: true });
    expect((payload.bootstrap as { reason: string }).reason).not.toBe("process_not_production");
    expect(payload.established).toMatchObject({
      mode: "production",
      isProductionProcess: true,
      productionTrustEstablished: true,
    });
    expect(payload.afterMutation).toMatchObject({
      mode: "production",
      isProductionProcess: true,
      productionRequested: true,
      productionTrustEstablished: true,
      authorityId: "authority_r5b_r1",
      liveEnvMode: "non_production",
    });
    expect(payload.createTrustedRuntime).toBe("public_api_not_production_authority");
  });

  it("D. ordinary public APIs cannot first-read establish, reset, or change process trust", () => {
    const result = runChild(
      productionChildEnv,
      `
        const report = {
          scenario: "D",
          initialEnv: { COGNIWEAVE_RUNTIME_MODE: "production" },
          importOrder: ["src/index.ts public SDK root"],
          mutationTiming: "none before first public API; after first reads, env is mutated to test reset",
          firstTrustApiTiming: "public isProductionProcess / getSealedProcessTrustMode / createTrustedRuntime after import",
          expected: "public reads do not establish production; no public setter; createTrustedRuntime refused; env mutation after reads cannot reset identity",
        };
        const sdk = await import(${indexPath});
        const publicKeys = Object.keys(sdk).sort();
        const forbidden = [
          "applyOfficialProductionTrustEstablishment",
          "markOfficialProductionTrustFailedClosed",
          "installSimulatedProcessTrustForTests",
          "runWithSimulatedProductionProcess",
          "setProcessTrustSnapshot",
          "resetProcessTrust",
          "establishProductionProcessTrust",
        ].filter((key) => publicKeys.includes(key));
        const firstRead = {
          isProductionProcess: sdk.isProductionProcess(),
          getSealedProcessTrustMode: sdk.getSealedProcessTrustMode(),
        };
        let createTrustedRuntime = "not_called";
        try {
          sdk.createTrustedRuntime({ environment: "service" });
          createTrustedRuntime = "succeeded";
        } catch (error) {
          createTrustedRuntime = error?.reason ?? error?.name ?? "error";
        }
        process.env.COGNIWEAVE_RUNTIME_MODE = "non_production";
        const afterMutation = {
          isProductionProcess: sdk.isProductionProcess(),
          getSealedProcessTrustMode: sdk.getSealedProcessTrustMode(),
        };
        let createTrustedRuntimeAfterMutation = "not_called";
        try {
          sdk.createTrustedRuntime({ environment: "local" });
          createTrustedRuntimeAfterMutation = "succeeded";
        } catch (error) {
          createTrustedRuntimeAfterMutation = error?.reason ?? error?.name ?? "error";
        }
        let bootstrap = { ok: false, reason: null };
        try {
          await sdk.bootstrapProductionTrustedRuntime();
          bootstrap = { ok: true, reason: null };
        } catch (error) {
          bootstrap = { ok: false, reason: error?.reason ?? null };
        }
        const afterBootstrap = {
          isProductionProcess: sdk.isProductionProcess(),
          getSealedProcessTrustMode: sdk.getSealedProcessTrustMode(),
        };
        console.log(JSON.stringify({
          ...report,
          forbidden,
          firstRead,
          createTrustedRuntime,
          afterMutation,
          createTrustedRuntimeAfterMutation,
          bootstrap,
          afterBootstrap,
        }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("D");
    expect(payload.forbidden).toEqual([]);
    expect(payload.firstRead).toMatchObject({
      isProductionProcess: false,
      getSealedProcessTrustMode: "non_production",
    });
    expect(payload.createTrustedRuntime).toBe("public_api_not_production_authority");
    expect(payload.afterMutation).toMatchObject({
      isProductionProcess: false,
      getSealedProcessTrustMode: "non_production",
    });
    expect(payload.createTrustedRuntimeAfterMutation).toBe("public_api_not_production_authority");
    expect((payload.bootstrap as { ok: boolean }).ok).toBe(false);
    expect((payload.bootstrap as { reason: string }).reason).not.toBe("process_not_production");
    expect(payload.afterBootstrap).toMatchObject({
      isProductionProcess: true,
      getSealedProcessTrustMode: "production",
    });
  });

  it("E. non-production mode cannot enter a production authorization path via createTrustedRuntime, Engine, or custom stores", () => {
    const result = runChild(
      nonProductionChildEnv,
      `
        const report = {
          scenario: "E",
          initialEnv: { COGNIWEAVE_RUNTIME_MODE: null, VITEST: null },
          importOrder: ["process-trust", "trusted-runtime", "in-memory-engine", "runtime/bootstrap", "factory", "production-bootstrap"],
          mutationTiming: "none; process starts as ordinary non-production",
          firstTrustApiTiming: "createTrustedRuntime and Engine construction, then bootstrapProductionTrustedRuntime",
          expected: "non-production assemblies have no production audit; official bootstrap fail-closes with process_not_production; later env production claim is ignored",
        };
        const processTrust = await import(${processTrustPath});
        const trustedRuntime = await import(${trustedRuntimePath});
        const engineMod = await import(${enginePath});
        const runtimeBootstrap = await import(${runtimeBootstrapPath});
        const factory = await import(${factoryPath});
        const productionBootstrap = await import(${productionBootstrapPath});
        const snapshot = processTrust.getProcessTrustSnapshot();
        const runtime = trustedRuntime.createTrustedRuntime({
          environment: "service",
          requireAuth: true,
        });
        const bundle = factory.createAdapterBundle({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        });
        const engine = new engineMod.InMemoryCogniWeaveEngine({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }, {
          metadataStore: bundle.metadataStore,
          graphStore: bundle.graphStore,
          vectorStore: bundle.vectorStore,
          runtime,
        });
        const createdRuntime = runtimeBootstrap.createCogniWeaveRuntime({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }, { runtime });
        const audits = {
          runtime: productionBootstrap.getProductionAssemblyAudit(runtime) ?? null,
          engine: productionBootstrap.getEngineProductionAssemblyAudit(engine) ?? null,
          createdRuntime: productionBootstrap.getProductionAssemblyAudit(createdRuntime.engine) ?? null,
        };
        process.env.COGNIWEAVE_RUNTIME_MODE = "production";
        process.env.COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID = "forged";
        process.env.COGNIWEAVE_ENGINE_ENVIRONMENT = "service";
        let bootstrap = { ok: false, reason: null };
        try {
          await productionBootstrap.bootstrapProductionTrustedRuntime();
          bootstrap = { ok: true, reason: null };
        } catch (error) {
          bootstrap = { ok: false, reason: error?.reason ?? null };
        }
        const afterForgedEnv = {
          mode: processTrust.getSealedProcessTrustMode(),
          isProductionProcess: processTrust.isProductionProcess(),
          productionRequested: processTrust.getProcessTrustSnapshot().productionRequested,
        };
        console.log(JSON.stringify({
          ...report,
          firstSnapshot: {
            mode: snapshot.mode,
            productionRequested: snapshot.productionRequested,
            productionTrustEstablished: snapshot.productionTrustEstablished,
          },
          audits,
          bootstrap,
          afterForgedEnv,
        }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("E");
    expect(payload.firstSnapshot).toMatchObject({
      mode: "non_production",
      productionRequested: false,
      productionTrustEstablished: false,
    });
    expect(payload.audits).toMatchObject({ runtime: null, engine: null, createdRuntime: null });
    expect(payload.bootstrap).toMatchObject({ ok: false, reason: "process_not_production" });
    expect(payload.afterForgedEnv).toMatchObject({
      mode: "non_production",
      isProductionProcess: false,
      productionRequested: false,
    });
  });

  it("E-host. host non-production process cannot self-declare production via injected services", () => {
    const runtime = createTrustedRuntime({
      environment: "service",
      principalProvider: createDenyByDefaultPrincipalProvider([{ token: TOKEN, principal: PRINCIPAL }]),
      bindingQuery: createDenyByDefaultBindingQuery([]),
      delegationStore: createMemoryDelegationAuthorizationStore([]),
    });
    const store = new InMemoryMetadataStore();
    const engine = new InMemoryCogniWeaveEngine(serviceConfig, {
      metadataStore: store,
      runtime,
    });
    const implicit = createImplicitLocalRuntime();
    expect(implicit.environment).toBe("local");
    expect(engine.config.environment).toBe("service");
    expect(isProductionProcess()).toBe(false);
    expect(() =>
      createAdapterBundle(serviceConfig),
    ).not.toThrow();
    expect(() => createCogniWeaveRuntime(serviceConfig, { runtime })).not.toThrow(ProductionBootstrapError);
  });

  it("F. in a production-requested process, bypassing official bootstrap to construct Runtime or Engine is refused", () => {
    const result = runChild(
      productionChildEnv,
      `
        const report = {
          scenario: "F",
          initialEnv: { COGNIWEAVE_RUNTIME_MODE: "production" },
          importOrder: ["process-trust", "trusted-runtime", "in-memory-engine", "runtime/bootstrap", "factory"],
          mutationTiming: "none before bypass attempts",
          firstTrustApiTiming: "direct createTrustedRuntime / Engine / createCogniWeaveRuntime / createAdapterBundle, without bootstrapProductionTrustedRuntime",
          expected: "all public construction paths refused; no store bundle or engine returned",
        };
        const processTrust = await import(${processTrustPath});
        const trustedRuntime = await import(${trustedRuntimePath});
        const engineMod = await import(${enginePath});
        const runtimeBootstrap = await import(${runtimeBootstrapPath});
        const factory = await import(${factoryPath});
        const attempts = {};
        const tryCall = (name, fn) => {
          try {
            const value = fn();
            attempts[name] = { ok: true, type: typeof value, reason: null };
          } catch (error) {
            attempts[name] = { ok: false, type: null, reason: error?.reason ?? error?.name ?? "error" };
          }
        };
        tryCall("createTrustedRuntime", () => trustedRuntime.createTrustedRuntime({ environment: "service" }));
        tryCall("createImplicitLocalRuntime", () => trustedRuntime.createImplicitLocalRuntime());
        tryCall("InMemoryCogniWeaveEngine", () => new engineMod.InMemoryCogniWeaveEngine({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }));
        tryCall("createCogniWeaveRuntime", () => runtimeBootstrap.createCogniWeaveRuntime({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }));
        tryCall("createAdapterBundle", () => factory.createAdapterBundle({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }));
        tryCall("createProductionEngine", () => engineMod.createProductionEngine({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }, {}));
        tryCall("createOfficialProductionAdapterBundle", () => factory.createOfficialProductionAdapterBundle({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }));
        const beforeBootstrap = {
          isProductionProcess: processTrust.isProductionProcess(),
          productionRequested: processTrust.getProcessTrustSnapshot().productionRequested,
          boundaryActive: processTrust.isProductionTrustBoundaryActive(),
        };
        console.log(JSON.stringify({ ...report, beforeBootstrap, attempts }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("F");
    expect(payload.beforeBootstrap).toMatchObject({
      isProductionProcess: false,
      productionRequested: true,
      boundaryActive: true,
    });
    const attempts = payload.attempts as Record<string, { ok: boolean; reason: string | null }>;
    expect(attempts.createTrustedRuntime).toMatchObject({ ok: false, reason: "public_api_not_production_authority" });
    expect(attempts.createImplicitLocalRuntime).toMatchObject({ ok: false, reason: "public_api_not_production_authority" });
    expect(attempts.InMemoryCogniWeaveEngine).toMatchObject({ ok: false, reason: "engine_construction_rejected" });
    expect(attempts.createCogniWeaveRuntime).toMatchObject({ ok: false, reason: "public_api_not_production_authority" });
    expect(attempts.createAdapterBundle).toMatchObject({ ok: false, reason: "production_factory_denied" });
    expect(attempts.createProductionEngine.ok).toBe(false);
    expect(attempts.createOfficialProductionAdapterBundle.ok).toBe(false);
  });
});
