import { createAdapterBundle } from "../adapters/factory.js";
import { getProcessTrustSnapshot, isProductionTrustBoundaryActive } from "../auth/process-trust.js";
import { resolveEngineTrustedRuntime, type TrustedRuntime } from "../auth/trusted-runtime.js";
import { ProductionBootstrapError } from "../errors.js";
import type { EngineConfig } from "../models.js";
import {
  createCogniWeaveHttpServer,
  type CogniWeaveHttpServerOptions,
} from "../rest/node-server.js";
import { CogniWeaveRestService } from "../rest/service.js";
import { InMemoryCogniWeaveEngine } from "./in-memory-engine.js";

export interface CogniWeaveRuntime {
  config: EngineConfig;
  engine: InMemoryCogniWeaveEngine;
  service: CogniWeaveRestService;
  server: ReturnType<typeof createCogniWeaveHttpServer>;
}

export interface CreateCogniWeaveRuntimeOptions {
  /** Sealed runtime from createTrustedRuntime(). Required for service/cloud auth. */
  runtime?: TrustedRuntime;
  http?: CogniWeaveHttpServerOptions;
}

export function createCogniWeaveRuntime(
  config: EngineConfig,
  options?: CreateCogniWeaveRuntimeOptions,
): CogniWeaveRuntime {
  if (isProductionTrustBoundaryActive()) {
    const trust = getProcessTrustSnapshot();
    throw new ProductionBootstrapError(
      "createCogniWeaveRuntime() is not production authorization proof; use bootstrapProductionTrustedRuntime()",
      "public_api_not_production_authority",
      Object.freeze({
        assemblyId: "unissued",
        trustClass: "none",
        runtimeEnvironment: trust.engineEnvironment,
        processTrustMode: trust.mode,
        bootstrapAuthorityId: trust.authorityId,
        createdAt: new Date().toISOString(),
        verificationResult: "failed",
        failureReason: "public_api_not_production_authority",
        services: {},
        canonicalStoreBindingQueryAssociation: "missing",
      }),
    );
  }
  const bundle = createAdapterBundle(config);
  const engine = new InMemoryCogniWeaveEngine(config, {
    metadataStore: bundle.metadataStore,
    graphStore: bundle.graphStore,
    vectorStore: bundle.vectorStore,
    runtime: options?.runtime,
  });
  const service = new CogniWeaveRestService(engine);
  const server = createCogniWeaveHttpServer(service, {
    ...options?.http,
    runtime: options?.runtime ?? options?.http?.runtime ?? resolveEngineTrustedRuntime(engine),
  });

  return {
    config,
    engine,
    service,
    server,
  };
}
