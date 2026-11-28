import { randomUUID } from "node:crypto";
import {
  ProductionBootstrapError,
  SecurityOverrideRejectedError,
  UntrustedRuntimeError,
} from "../errors.js";
import type { EngineEnvironment } from "../models.js";
import type { AuthoritativeBindingQuery } from "./canonical-scope.js";
import type { DelegationAuthorizationStore } from "./delegation.js";
import { isUsableTrustedPrincipal, type TrustedPrincipal, type TrustedPrincipalProvider } from "./principal.js";
import { getProcessTrustSnapshot } from "./process-trust.js";

/**
 * CW-09-02-R5: unforgeable runtime capability.
 *
 * Trust is established only by `createTrustedRuntime()`, which stores the
 * sealed assembly in a module-private WeakMap. A same-shaped ordinary object
 * constructed by a business caller cannot resolve to that assembly.
 *
 * TypeScript interfaces, type assertions, and field names are not trust.
 */
const sealedAssemblies = new WeakMap<object, SealedTrustedRuntimeAssembly>();
const engineRuntimeHandles = new WeakMap<object, TrustedRuntime>();

export type TrustedRuntime = {
  readonly environment: EngineEnvironment;
  readonly requireAuth: boolean;
};

export type TrustedRuntimeTrustClass = "non_production" | "production" | "simulated_production";

export type SealedTrustedRuntimeAssembly = {
  readonly environment: EngineEnvironment;
  readonly requireAuth: boolean;
  readonly allowLocalInjection: boolean;
  readonly trustClass: TrustedRuntimeTrustClass;
  readonly assemblyId: string;
  readonly injectedPrincipal?: TrustedPrincipal;
  readonly principalProvider?: TrustedPrincipalProvider;
  readonly bindingQuery?: AuthoritativeBindingQuery;
  readonly delegationStore?: DelegationAuthorizationStore;
  readonly ensureDataPlaneId?: () => Promise<string>;
};

export type CreateTrustedRuntimeInput = {
  environment: EngineEnvironment;
  /**
   * Honored only when environment is `"local"`. service/cloud always require auth.
   * This is bootstrap configuration, not a request field.
   */
  requireAuth?: boolean;
  /**
   * Local bootstrap only. When true, `injectedPrincipal` may be used as the
   * local test identity. Never honored for service/cloud.
   */
  allowLocalInjection?: boolean;
  /** Local bootstrap only, and only when `allowLocalInjection` is true. */
  injectedPrincipal?: TrustedPrincipal;
  principalProvider?: TrustedPrincipalProvider;
  bindingQuery?: AuthoritativeBindingQuery;
  delegationStore?: DelegationAuthorizationStore;
  ensureDataPlaneId?: () => Promise<string>;
};

/**
 * Fields that must never be honored from a business request object.
 * Presence on a production request is a rejected security override.
 */
export const REQUEST_SECURITY_OVERRIDE_KEYS = [
  "environment",
  "requireAuth",
  "principal",
  "principalProvider",
  "bindingQuery",
  "delegationStore",
  "trustedServices",
  "allowInjectedPrincipal",
  "injectedPrincipal",
] as const;

export type RequestSecurityOverrideKey = (typeof REQUEST_SECURITY_OVERRIDE_KEYS)[number];

export function isProductionLikeEnvironment(environment: EngineEnvironment | undefined): boolean {
  return environment !== "local";
}

export function findCallerSecurityOverrides(value: unknown): RequestSecurityOverrideKey[] {
  if (!value || typeof value !== "object") {
    return [];
  }
  const record = value as Record<string, unknown>;
  return REQUEST_SECURITY_OVERRIDE_KEYS.filter((key) => Object.prototype.hasOwnProperty.call(record, key));
}

function publicRuntimeDeniedAudit(reason: "mixed_test_and_production_configuration" | "public_api_not_production_authority" | "assembly_already_sealed" | "process_not_production") {
  const trust = getProcessTrustSnapshot();
  return Object.freeze({
    assemblyId: "unissued",
    trustClass: "none",
    runtimeEnvironment: trust.engineEnvironment,
    processTrustMode: trust.mode,
    bootstrapAuthorityId: trust.authorityId,
    createdAt: new Date().toISOString(),
    verificationResult: "failed",
    failureReason: reason,
    services: {},
    canonicalStoreBindingQueryAssociation: "missing",
  });
}

function assertPublicRuntimeCreationAllowed(): void {
  const trust = getProcessTrustSnapshot();
  if (trust.mixedConfiguration) {
    throw new ProductionBootstrapError(
      "Process trust snapshot mixes test harness markers with production mode; public createTrustedRuntime() is refused",
      "mixed_test_and_production_configuration",
      publicRuntimeDeniedAudit("mixed_test_and_production_configuration"),
    );
  }
  if (trust.mode === "production") {
    throw new ProductionBootstrapError(
      "createTrustedRuntime() is not production authorization proof and cannot create or replace a production Trusted Runtime",
      "public_api_not_production_authority",
      publicRuntimeDeniedAudit("public_api_not_production_authority"),
    );
  }
}

export function createTrustedRuntime(input: CreateTrustedRuntimeInput): TrustedRuntime {
  assertPublicRuntimeCreationAllowed();
  const environment = input.environment;
  if (environment !== "local" && environment !== "service" && environment !== "cloud") {
    throw new UntrustedRuntimeError(`Invalid trusted runtime environment: ${String(environment)}`, {
      decision: "deny",
      reason: "untrusted_runtime",
    });
  }
  const production = isProductionLikeEnvironment(environment);
  const requireAuth = production ? true : input.requireAuth === true;
  const allowLocalInjection = production ? false : input.allowLocalInjection === true;
  const injectedPrincipal =
    allowLocalInjection && isUsableTrustedPrincipal(input.injectedPrincipal)
      ? input.injectedPrincipal
      : undefined;

  const handle: TrustedRuntime = Object.freeze({
    environment,
    requireAuth,
  });

  const assembly: SealedTrustedRuntimeAssembly = Object.freeze({
    environment,
    requireAuth,
    allowLocalInjection,
    trustClass: "non_production",
    assemblyId: `nonprod_${randomUUID()}`,
    ...(injectedPrincipal ? { injectedPrincipal } : {}),
    ...(input.principalProvider ? { principalProvider: input.principalProvider } : {}),
    ...(input.bindingQuery ? { bindingQuery: input.bindingQuery } : {}),
    ...(input.delegationStore ? { delegationStore: input.delegationStore } : {}),
    ...(input.ensureDataPlaneId ? { ensureDataPlaneId: input.ensureDataPlaneId } : {}),
  });
  sealedAssemblies.set(handle, assembly);
  return handle;
}

/**
 * Implicit local runtime for engines constructed with `environment: "local"`
 * and no explicit handle. Not production evidence. requireAuth is off.
 */
export function createImplicitLocalRuntime(): TrustedRuntime {
  return createTrustedRuntime({ environment: "local", requireAuth: false });
}

export function isVerifiableTrustedRuntime(value: unknown): value is TrustedRuntime {
  return typeof value === "object" && value !== null && sealedAssemblies.has(value);
}

/**
 * Same-bundle internal helper. Associates an Engine instance with its sealed
 * runtime handle. Not a public SDK export and not replaceable later.
 */
export function bindEngineTrustedRuntime(engine: object, runtime: TrustedRuntime): void {
  if (!isVerifiableTrustedRuntime(runtime)) {
    throw new UntrustedRuntimeError(
      "Engine runtime binding requires a verifiable TrustedRuntime from createTrustedRuntime()",
      { decision: "deny", reason: "untrusted_runtime" },
    );
  }
  const existing = engineRuntimeHandles.get(engine);
  if (existing && existing !== runtime) {
    throw new UntrustedRuntimeError(
      "Engine trusted runtime is already sealed and cannot be replaced",
      { decision: "deny", reason: "untrusted_runtime" },
    );
  }
  engineRuntimeHandles.set(engine, runtime);
}

/**
 * Same-bundle internal helper. Returns the Engine-held handle, or undefined.
 * Not a public SDK export. Ordinary instance property access cannot substitute
 * for this lookup.
 */
export function resolveEngineTrustedRuntime(engine: unknown): TrustedRuntime | undefined {
  if (!engine || typeof engine !== "object") {
    return undefined;
  }
  return engineRuntimeHandles.get(engine);
}

export function resolveTrustedRuntimeAssembly(runtime: unknown): SealedTrustedRuntimeAssembly {
  if (!runtime || typeof runtime !== "object") {
    throw new UntrustedRuntimeError(
      "Trusted runtime assembly is required; an ordinary object is not a runtime capability",
      { decision: "deny", reason: "untrusted_runtime" },
    );
  }
  const assembly = sealedAssemblies.get(runtime);
  if (!assembly) {
    throw new UntrustedRuntimeError(
      "Unverifiable runtime assembly; a same-shaped object cannot impersonate createTrustedRuntime()",
      { decision: "deny", reason: "untrusted_runtime" },
    );
  }
  return assembly;
}

export type TrustedExecutionRequestAuthorization = {
  bearerToken?: string;
};

export function assertNoProductionSecurityOverrides(input: {
  environment: EngineEnvironment;
  bags: readonly unknown[];
}): void {
  if (!isProductionLikeEnvironment(input.environment)) {
    return;
  }
  const keys = input.bags.flatMap((bag) => findCallerSecurityOverrides(bag));
  if (keys.length === 0) {
    return;
  }
  throw new SecurityOverrideRejectedError(
    `Production execution rejects caller security overrides: ${[...new Set(keys)].join(", ")}`,
    { decision: "deny", reason: "security_override_rejected", keys: [...new Set(keys)] },
  );
}

const productionIssuancePermits = new WeakSet<object>();
let productionRuntimeSlot: TrustedRuntime | undefined;
const issuedProductionHandles = new Set<object>();

/**
 * Same-bundle helper used only by the official production bootstrap after the
 * assembly guard has passed. Not a public SDK export.
 */
export function issueProductionRuntimePermit(): object {
  const trust = getProcessTrustSnapshot();
  if (trust.mixedConfiguration) {
    throw new ProductionBootstrapError(
      "Process trust snapshot mixes test harness markers with production mode",
      "mixed_test_and_production_configuration",
      publicRuntimeDeniedAudit("mixed_test_and_production_configuration"),
    );
  }
  if (trust.mode !== "production") {
    throw new ProductionBootstrapError(
      "Production runtime issuance requires a sealed production process trust snapshot",
      "process_not_production",
      publicRuntimeDeniedAudit("public_api_not_production_authority"),
    );
  }
  const permit = Object.freeze({ brand: "cw-production-runtime-permit" });
  productionIssuancePermits.add(permit);
  return permit;
}

export type ProductionRuntimeAssemblyInput = {
  environment: "service" | "cloud";
  principalProvider: TrustedPrincipalProvider;
  bindingQuery: AuthoritativeBindingQuery;
  delegationStore: DelegationAuthorizationStore;
  ensureDataPlaneId?: () => Promise<string>;
};

/**
 * Same-bundle helper. Creates a sealed production or simulated-production
 * assembly. Requires a single-use permit from issueProductionRuntimePermit().
 * Not a public SDK export. Write-once per process slot.
 */
export function createSealedProductionRuntime(
  permit: object,
  input: ProductionRuntimeAssemblyInput,
): TrustedRuntime {
  if (!productionIssuancePermits.has(permit)) {
    throw new ProductionBootstrapError(
      "Production runtime creation requires a permit issued by the official production bootstrap",
      "public_api_not_production_authority",
      publicRuntimeDeniedAudit("public_api_not_production_authority"),
    );
  }
  productionIssuancePermits.delete(permit);
  const trust = getProcessTrustSnapshot();
  if (trust.mode !== "production" || trust.mixedConfiguration) {
    throw new ProductionBootstrapError(
      "Production runtime creation is refused outside a sealed production process",
      trust.mixedConfiguration ? "mixed_test_and_production_configuration" : "process_not_production",
      publicRuntimeDeniedAudit(
        trust.mixedConfiguration
          ? "mixed_test_and_production_configuration"
          : "public_api_not_production_authority",
      ),
    );
  }
  if (productionRuntimeSlot) {
    throw new ProductionBootstrapError(
      "A production Trusted Runtime assembly is already sealed and cannot be replaced or re-bound",
      "assembly_already_sealed",
      publicRuntimeDeniedAudit("assembly_already_sealed"),
    );
  }
  const handle: TrustedRuntime = Object.freeze({
    environment: input.environment,
    requireAuth: true,
  });
  const assembly: SealedTrustedRuntimeAssembly = Object.freeze({
    environment: input.environment,
    requireAuth: true,
    allowLocalInjection: false,
    trustClass: trust.simulated ? "simulated_production" : "production",
    assemblyId: `prod_${randomUUID()}`,
    principalProvider: input.principalProvider,
    bindingQuery: input.bindingQuery,
    delegationStore: input.delegationStore,
    ...(input.ensureDataPlaneId ? { ensureDataPlaneId: input.ensureDataPlaneId } : {}),
  });
  sealedAssemblies.set(handle, assembly);
  issuedProductionHandles.add(handle);
  productionRuntimeSlot = handle;
  return handle;
}

export function getSealedProductionRuntimeSlot(): TrustedRuntime | undefined {
  return productionRuntimeSlot;
}

/**
 * Same-bundle test cleanup. Invalidates simulated production handles only.
 * Refuses to clear a real production slot.
 */
export function clearSimulatedProductionRuntimeSlot(): void {
  const trust = getProcessTrustSnapshot();
  if (trust.mode === "production" && !trust.simulated) {
    throw new ProductionBootstrapError(
      "A real production runtime slot cannot be cleared",
      "public_api_not_production_authority",
      publicRuntimeDeniedAudit("public_api_not_production_authority"),
    );
  }
  for (const handle of issuedProductionHandles) {
    sealedAssemblies.delete(handle);
  }
  issuedProductionHandles.clear();
  productionRuntimeSlot = undefined;
}

export function isProductionTrustClass(
  trustClass: TrustedRuntimeTrustClass | undefined,
): boolean {
  return trustClass === "production" || trustClass === "simulated_production";
}
