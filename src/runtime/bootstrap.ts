import { createAdapterBundle } from "../adapters/factory.js";
import { resolveEngineTrustedRuntime, type TrustedRuntime } from "../auth/trusted-runtime.js";
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
