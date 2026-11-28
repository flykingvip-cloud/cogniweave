/**
 * CW-09-02-R5-B: official production Trusted Runtime bootstrap.
 *
 * Ordinary callers cannot assemble a production runtime. This module is the
 * only official process-start path that can establish production identity from
 * the frozen environment claim, creates trusted services internally,
 * runs the assembly guard, seals a write-once production assembly, and returns
 * a handle plus a redacted audit record. Store and trusted-service references
 * are not returned to the caller.
 */

import { createOfficialProductionAdapterBundle } from "../adapters/factory.js";
import { createPgSqlClient } from "../adapters/postgres-client.js";
import { ProductionBootstrapError, type ProductionBootstrapFailureReason } from "../errors.js";
import { createMemoryPartitionKeyV1 } from "../keys.js";
import type { EngineConfig, EngineEnvironment, Scope } from "../models.js";
import { createMemorySubjectBinding } from "../subject/binding.js";
import { CogniWeaveRestService } from "../rest/service.js";
import { createCogniWeaveHttpServer } from "../rest/node-server.js";
import { InMemoryCogniWeaveEngine, createProductionEngine } from "../runtime/in-memory-engine.js";
import type { MetadataStore } from "../storage/types.js";
import { createAuthoritativeBindingQueryFromMetadataStore, type AuthoritativeBindingQuery } from "./canonical-scope.js";
import {
  revalidateDelegationRecord,
  type ActiveDelegationQuery,
  type DelegationAuthorizationStore,
} from "./delegation.js";
import { isUsableTrustedPrincipal, type TrustedPrincipal, type TrustedPrincipalProvider } from "./principal.js";
import {
  applyOfficialProductionTrustEstablishment,
  assertNoSecretMaterial,
  getProcessTrustSnapshot,
  getSealedProcessSecrets,
  getSealedProcessTrustMode,
  getSimulatedAuthoritativeScopes,
  getSimulatedPrincipalBindings,
  installSimulatedProcessTrustForTests,
  isProductionProcess,
  isSimulatedProductionProcess,
  markOfficialProductionTrustFailedClosed,
  registerSimulatedProductionCleanup,
  type SimulatedProductionTrustFixture,
} from "./process-trust.js";
import {
  clearSimulatedProductionRuntimeSlot,
  createSealedProductionRuntime,
  issueProductionRuntimePermit,
  resolveEngineTrustedRuntime,
  resolveTrustedRuntimeAssembly,
  type TrustedRuntime,
} from "./trusted-runtime.js";

export type ProductionAssemblyTrustClass = "production" | "simulated_production";

export type ProductionServiceVerification = {
  readonly implementationType: string;
  readonly verified: boolean;
  readonly source: "official_production_bootstrap";
};

export type ProductionAssemblyAuditRecord = {
  readonly assemblyId: string;
  readonly trustClass: ProductionAssemblyTrustClass | "none";
  readonly runtimeEnvironment: "service" | "cloud" | null;
  readonly processTrustMode: "production" | "non_production";
  readonly bootstrapAuthorityId: string | null;
  readonly createdAt: string;
  readonly verificationResult: "passed" | "failed";
  readonly failureReason?: ProductionBootstrapFailureReason;
  readonly services: {
    readonly principalProvider?: ProductionServiceVerification;
    readonly bindingQuery?: ProductionServiceVerification;
    readonly delegationStore?: ProductionServiceVerification;
    readonly metadataStore?: ProductionServiceVerification;
  };
  readonly canonicalStoreBindingQueryAssociation: "bound_same_assembly" | "missing" | "mismatch";
  readonly canonicalDataPlaneId?: string;
};

export type ProductionBootstrapResult = {
  readonly runtime: TrustedRuntime;
  readonly engine: InMemoryCogniWeaveEngine;
  readonly service: CogniWeaveRestService;
  readonly server: ReturnType<typeof createCogniWeaveHttpServer>;
  readonly audit: ProductionAssemblyAuditRecord;
};

const blessedPrincipalProviders = new WeakSet<object>();
const blessedBindingQueries = new WeakSet<object>();
const blessedDelegationStores = new WeakSet<object>();
const blessedMetadataStores = new WeakSet<object>();
const bindingQueryStores = new WeakMap<object, object>();
const productionAuditByHandle = new WeakMap<object, ProductionAssemblyAuditRecord>();
const productionAuditByEngine = new WeakMap<object, ProductionAssemblyAuditRecord>();
let failedBootstrapAudits: ProductionAssemblyAuditRecord[] = [];

registerSimulatedProductionCleanup(() => {
  clearSimulatedProductionRuntimeSlot();
  failedBootstrapAudits = [];
});

function freezeAudit(audit: ProductionAssemblyAuditRecord): ProductionAssemblyAuditRecord {
  assertNoSecretMaterial(audit, "audit");
  return Object.freeze({
    ...audit,
    services: Object.freeze({ ...audit.services }),
  });
}

function baseAudit(
  extras: Partial<ProductionAssemblyAuditRecord> & {
    verificationResult: "passed" | "failed";
  },
): ProductionAssemblyAuditRecord {
  const trust = getProcessTrustSnapshot();
  return freezeAudit({
    assemblyId: extras.assemblyId ?? "unissued",
    trustClass: extras.trustClass ?? (trust.simulated ? "simulated_production" : trust.mode === "production" ? "production" : "none"),
    runtimeEnvironment: extras.runtimeEnvironment ?? trust.engineEnvironment,
    processTrustMode: trust.mode,
    bootstrapAuthorityId: trust.authorityId,
    createdAt: extras.createdAt ?? new Date().toISOString(),
    verificationResult: extras.verificationResult,
    ...(extras.failureReason ? { failureReason: extras.failureReason } : {}),
    services: extras.services ?? {},
    canonicalStoreBindingQueryAssociation: extras.canonicalStoreBindingQueryAssociation ?? "missing",
  });
}

function fail(
  reason: ProductionBootstrapFailureReason,
  message: string,
  extras: Partial<ProductionAssemblyAuditRecord> = {},
): never {
  if (reason !== "process_not_production" && reason !== "caller_injection_rejected") {
    markOfficialProductionTrustFailedClosed();
  }
  const audit = baseAudit({ ...extras, verificationResult: "failed", failureReason: reason });
  failedBootstrapAudits.push(audit);
  throw new ProductionBootstrapError(message, reason, audit);
}

function rejectCallerInput(args: IArguments): void {
  if (args.length > 0) {
    fail(
      "caller_injection_rejected",
      "bootstrapProductionTrustedRuntime() accepts no caller arguments; production assembly is created only from the sealed process-start trust boundary",
    );
  }
}

class SimulatedProductionPrincipalProvider implements TrustedPrincipalProvider {
  readonly implementationType = "simulated_production_principal_provider";
  readonly #byToken: ReadonlyMap<string, TrustedPrincipal>;

  constructor(bindings: NonNullable<SimulatedProductionTrustFixture["principalBindings"]>) {
    const entries: Array<[string, TrustedPrincipal]> = [];
    for (const binding of bindings) {
      if (!binding.token.trim() || !isUsableTrustedPrincipal(binding.principal as TrustedPrincipal)) {
        continue;
      }
      entries.push([binding.token, binding.principal as TrustedPrincipal]);
    }
    this.#byToken = new Map(entries);
  }

  async resolvePrincipal(input: { bearerToken?: string; environment: EngineEnvironment }) {
    const token = input.bearerToken?.trim() ?? "";
    if (!token) return null;
    return this.#byToken.get(token) ?? null;
  }
}

class SimulatedProductionDelegationStore implements DelegationAuthorizationStore {
  readonly implementationType = "simulated_production_delegation_store";
  readonly #inner: DelegationAuthorizationStore;

  constructor(inner: DelegationAuthorizationStore) {
    this.#inner = inner;
  }

  async getActiveDelegation(query: ActiveDelegationQuery) {
    const record = await this.#inner.getActiveDelegation(query);
    return revalidateDelegationRecord(record, query) === null ? record : null;
  }
}

async function assertDelegationStoreValidatesRecords(store: DelegationAuthorizationStore): Promise<void> {
  const probe: ActiveDelegationQuery = {
    tenantId: "probe_tenant_does_not_exist",
    actorUserId: "probe_actor_does_not_exist",
    subject: { tenantId: "probe_tenant_does_not_exist", ownerType: "user", ownerId: "probe_subject" },
    scope: {
      workspaceId: "probe_workspace",
      projectId: "probe_project",
      agentId: "probe_agent",
      visibility: "private",
    },
    now: new Date().toISOString(),
  };
  const result = await store.getActiveDelegation(probe);
  if (result !== null) {
    fail(
      "untrusted_service_implementation",
      "Delegation Store failed production validation: a probe query must not return an authorization record",
    );
  }
}

function createSimulatedPrincipalProvider(): TrustedPrincipalProvider {
  const bindings = getSimulatedPrincipalBindings() ?? [];
  const provider = new SimulatedProductionPrincipalProvider(bindings);
  blessedPrincipalProviders.add(provider);
  return provider;
}

function createSimulatedDelegationStore(): DelegationAuthorizationStore {
  const store = new SimulatedProductionDelegationStore({
    async getActiveDelegation() {
      return null;
    },
  });
  blessedDelegationStores.add(store);
  return store;
}

function createProductionBindingQuery(store: MetadataStore): AuthoritativeBindingQuery {
  const query = createAuthoritativeBindingQueryFromMetadataStore(store);
  if (!query) {
    fail(
      "required_service_missing",
      "Canonical Store cannot provide an Authoritative Binding Query",
    );
  }
  blessedBindingQueries.add(query);
  bindingQueryStores.set(query, store);
  return query;
}


async function seedSimulatedAuthoritativeBindings(store: MetadataStore): Promise<void> {
  const scopes = getSimulatedAuthoritativeScopes() ?? [];
  if (scopes.length === 0 || typeof store.saveMemorySubjectBinding !== "function") {
    return;
  }
  const dataPlaneId =
    typeof store.ensureDataPlaneId === "function" ? await store.ensureDataPlaneId() : "simulated_data_plane";
  for (const entry of scopes) {
    const scope = entry.scope as Scope;
    const binding = createMemorySubjectBinding({
      partition: createMemoryPartitionKeyV1(dataPlaneId, scope),
      scope,
      subject: entry.subject,
    });
    await store.saveMemorySubjectBinding(binding);
  }
}

function createOfficialProductionStores(config: EngineConfig) {
  if (getProcessTrustSnapshot().mode !== "production") {
    fail("process_not_production", "Production stores can only be created in a production process");
  }
  const bundle = createOfficialProductionAdapterBundle(config);
  blessedMetadataStores.add(bundle.metadataStore);
  return bundle;
}

async function resolveProductionEngineConfig(): Promise<EngineConfig> {
  const trust = getProcessTrustSnapshot();
  if (trust.engineEnvironment !== "service" && trust.engineEnvironment !== "cloud") {
    fail(
      "invalid_engine_environment",
      "Production bootstrap requires sealed COGNIWEAVE_ENGINE_ENVIRONMENT of service or cloud",
    );
  }
  const metadataBackend = trust.metadataBackend ?? (trust.simulated ? "memory" : null);
  const graphBackend = trust.graphBackend ?? (trust.simulated ? "memory" : "memory");
  const evidenceBackend = trust.evidenceBackend ?? (trust.simulated ? "memory" : "memory");
  const vectorBackend = trust.vectorBackend ?? (trust.simulated ? "memory" : "memory");
  if (!metadataBackend) {
    fail("required_service_missing", "Production bootstrap requires a sealed metadata backend");
  }
  if (!trust.simulated && (metadataBackend === "memory" || metadataBackend === "placeholder")) {
    fail(
      "untrusted_service_implementation",
      "Real production bootstrap does not accept a memory or placeholder Canonical Store",
    );
  }
  if (trust.simulated && metadataBackend !== "memory") {
    fail(
      "mixed_test_and_production_configuration",
      "Simulated production bootstrap only creates in-process memory stores; durable backends cannot be mixed into the test seal",
    );
  }

  const config: EngineConfig = {
    environment: trust.engineEnvironment,
    metadataBackend,
    graphBackend,
    evidenceBackend,
    vectorBackend,
  };

  if (!trust.simulated && metadataBackend === "postgres") {
    const postgresUrl = getSealedProcessSecrets().postgresUrl;
    if (!postgresUrl) {
      fail(
        "required_service_missing",
        "Production Postgres Canonical Store is configured but no sealed process connection was provided",
      );
    }
    config.postgres = {
      client: await createPgSqlClient({ connectionString: postgresUrl }),
    };
  }

  return config;
}

function publicEngineConfig(config: EngineConfig): EngineConfig {
  return {
    environment: config.environment,
    metadataBackend: config.metadataBackend,
    graphBackend: config.graphBackend,
    evidenceBackend: config.evidenceBackend,
    vectorBackend: config.vectorBackend,
  };
}

function createRealProductionPrincipalProvider(): TrustedPrincipalProvider {
  fail(
    "required_service_missing",
    "Real production bootstrap requires an official OpenBot Trusted Principal Provider, which is not configured",
  );
}

function createRealProductionDelegationStore(): DelegationAuthorizationStore {
  fail(
    "required_service_missing",
    "Real production bootstrap requires an official durable Delegation Store, which is not configured",
  );
}

async function runAssemblyGuard(input: {
  principalProvider: TrustedPrincipalProvider;
  bindingQuery: AuthoritativeBindingQuery;
  delegationStore: DelegationAuthorizationStore;
  metadataStore: MetadataStore;
}): Promise<{
  principalProvider: ProductionServiceVerification;
  bindingQuery: ProductionServiceVerification;
  delegationStore: ProductionServiceVerification;
  metadataStore: ProductionServiceVerification;
  association: "bound_same_assembly";
}> {
  if (!blessedPrincipalProviders.has(input.principalProvider)) {
    fail(
      "untrusted_service_implementation",
      "Trusted Principal Provider is not an official production bootstrap implementation",
    );
  }
  if (!blessedBindingQueries.has(input.bindingQuery)) {
    fail(
      "untrusted_service_implementation",
      "Authoritative Binding Query is not an official production bootstrap implementation",
    );
  }
  if (!blessedDelegationStores.has(input.delegationStore)) {
    fail(
      "untrusted_service_implementation",
      "Delegation Store is not an official production bootstrap implementation",
    );
  }
  if (!blessedMetadataStores.has(input.metadataStore)) {
    fail(
      "untrusted_store_replacement",
      "Canonical Store is not the store created by the official production bootstrap",
    );
  }
  if (bindingQueryStores.get(input.bindingQuery) !== input.metadataStore) {
    fail(
      "canonical_store_binding_query_mismatch",
      "Authoritative Binding Query is not bound to the Canonical Store of the same production assembly",
      { canonicalStoreBindingQueryAssociation: "mismatch" },
    );
  }
  await assertDelegationStoreValidatesRecords(input.delegationStore);

  const principalType =
    "implementationType" in input.principalProvider &&
    typeof (input.principalProvider as { implementationType?: unknown }).implementationType === "string"
      ? (input.principalProvider as { implementationType: string }).implementationType
      : "unknown";
  const delegationType =
    "implementationType" in input.delegationStore &&
    typeof (input.delegationStore as { implementationType?: unknown }).implementationType === "string"
      ? (input.delegationStore as { implementationType: string }).implementationType
      : "unknown";
  const metadataType = input.metadataStore.constructor?.name || "MetadataStore";

  return {
    principalProvider: {
      implementationType: principalType,
      verified: true,
      source: "official_production_bootstrap",
    },
    bindingQuery: {
      implementationType: "authoritative_binding_query_from_canonical_store",
      verified: true,
      source: "official_production_bootstrap",
    },
    delegationStore: {
      implementationType: delegationType,
      verified: true,
      source: "official_production_bootstrap",
    },
    metadataStore: {
      implementationType: metadataType,
      verified: true,
      source: "official_production_bootstrap",
    },
    association: "bound_same_assembly",
  };
}

/**
 * Official production bootstrap. Accepts no caller arguments.
 * Process-start trust, not request parameters, selects the environment and
 * implementations. Missing or unverifiable required services fail closed.
 */
export async function bootstrapProductionTrustedRuntime(
  ...forbidden: unknown[]
): Promise<ProductionBootstrapResult> {
  rejectCallerInput(arguments);
  void forbidden;
  const established = applyOfficialProductionTrustEstablishment();
  if (!established.ok) {
    fail(
      established.reason,
      established.reason === "mixed_test_and_production_configuration"
        ? "Process trust snapshot mixes test harness markers with production mode"
        : "Ordinary callers cannot create a production Trusted Runtime; official bootstrap requires a sealed production process-start boundary",
    );
  }
  const trust = getProcessTrustSnapshot();
  if (trust.mixedConfiguration) {
    fail(
      "mixed_test_and_production_configuration",
      "Process trust snapshot mixes test harness markers with production mode",
    );
  }
  if (trust.mode !== "production" || !trust.productionTrustEstablished) {
    fail(
      "process_not_production",
      "Ordinary callers cannot create a production Trusted Runtime; official bootstrap requires a sealed production process-start boundary",
    );
  }
  if (!trust.authorityId) {
    fail("missing_bootstrap_authority", "Production bootstrap requires a sealed bootstrap authority identifier");
  }
  if (trust.engineEnvironment !== "service" && trust.engineEnvironment !== "cloud") {
    fail(
      "invalid_engine_environment",
      "Production bootstrap requires sealed engine environment service or cloud",
    );
  }

  const privateConfig = await resolveProductionEngineConfig();
  const stores = createOfficialProductionStores(privateConfig);
  await seedSimulatedAuthoritativeBindings(stores.metadataStore);
  const bindingQuery = createProductionBindingQuery(stores.metadataStore);
  const principalProvider = trust.simulated
    ? createSimulatedPrincipalProvider()
    : createRealProductionPrincipalProvider();
  const delegationStore = trust.simulated
    ? createSimulatedDelegationStore()
    : createRealProductionDelegationStore();

  const guardResult = await runAssemblyGuard({
    principalProvider,
    bindingQuery,
    delegationStore,
    metadataStore: stores.metadataStore,
  });

  const permit = issueProductionRuntimePermit();
  const runtime = createSealedProductionRuntime(permit, {
    environment: trust.engineEnvironment,
    principalProvider,
    bindingQuery,
    delegationStore,
    ensureDataPlaneId:
      typeof stores.metadataStore.ensureDataPlaneId === "function"
        ? () => stores.metadataStore.ensureDataPlaneId!()
        : typeof stores.metadataStore.getDataPlaneId === "function"
          ? async () => {
              const id = await stores.metadataStore.getDataPlaneId!();
              if (!id) {
                throw new Error("Canonical Store did not return a data plane id");
              }
              return id;
            }
          : undefined,
  });
  const assembly = resolveTrustedRuntimeAssembly(runtime);
  const canonicalDataPlaneId =
    typeof stores.metadataStore.getDataPlaneId === "function"
      ? await stores.metadataStore.getDataPlaneId()
      : undefined;
  const engine = createProductionEngine(publicEngineConfig(privateConfig), {
    metadataStore: stores.metadataStore,
    graphStore: stores.graphStore,
    vectorStore: stores.vectorStore,
    runtime,
  });
  const audit = freezeAudit({
    assemblyId: assembly.assemblyId,
    trustClass: trust.simulated ? "simulated_production" : "production",
    runtimeEnvironment: trust.engineEnvironment,
    processTrustMode: "production",
    bootstrapAuthorityId: trust.authorityId,
    createdAt: new Date().toISOString(),
    verificationResult: "passed",
    services: {
      principalProvider: guardResult.principalProvider,
      bindingQuery: guardResult.bindingQuery,
      delegationStore: guardResult.delegationStore,
      metadataStore: guardResult.metadataStore,
    },
    canonicalStoreBindingQueryAssociation: guardResult.association,
    ...(canonicalDataPlaneId ? { canonicalDataPlaneId } : {}),
  });
  productionAuditByHandle.set(runtime, audit);
  productionAuditByEngine.set(engine, audit);
  const service = new CogniWeaveRestService(engine);
  const server = createCogniWeaveHttpServer(service, { runtime });
  return Object.freeze({
    runtime,
    engine,
    service,
    server,
    audit,
  });
}

/**
 * Returns the redacted production assembly audit for a verifiable production
 * runtime handle. A caller-supplied look-alike record is not accepted and
 * this lookup is not a substitute for runtime authorization.
 */
export function getProductionAssemblyAudit(runtime: unknown): ProductionAssemblyAuditRecord | undefined {
  if (!runtime || typeof runtime !== "object") {
    return undefined;
  }
  return productionAuditByHandle.get(runtime);
}

/**
 * Returns the redacted production assembly audit for an Engine constructed by
 * the official production bootstrap. Ordinary objects and test engines yield
 * undefined. The audit cannot be submitted to bind or replace an assembly.
 */
export function getEngineProductionAssemblyAudit(engine: unknown): ProductionAssemblyAuditRecord | undefined {
  if (!engine || typeof engine !== "object") {
    return undefined;
  }
  const bound = productionAuditByEngine.get(engine);
  if (bound) {
    return bound;
  }
  const handle = resolveEngineTrustedRuntime(engine);
  return handle ? productionAuditByHandle.get(handle) : undefined;
}

/**
 * Submitting an audit record never proves assembly trust. This function exists
 * so tests can lock that contract; it always returns false and never binds.
 */
export function submitProductionAssemblyAudit(_record: unknown): false {
  return false;
}

export function listFailedProductionBootstrapAudits(): readonly ProductionAssemblyAuditRecord[] {
  return [...failedBootstrapAudits];
}

/**
 * Test-only. Installs a simulated production process-start snapshot, runs the
 * callback, then invalidates simulated assemblies and restores the previous
 * snapshot. Not a public SDK export. Refuses real production processes.
 */
export async function runWithSimulatedProductionProcess<T>(
  fixture: SimulatedProductionTrustFixture,
  fn: () => T | Promise<T>,
): Promise<T> {
  const restore = installSimulatedProcessTrustForTests(fixture);
  try {
    return await fn();
  } finally {
    restore();
  }
}

export { getSealedProcessTrustMode, isProductionProcess, isSimulatedProductionProcess };
