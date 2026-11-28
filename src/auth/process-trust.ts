import type { MemorySubject, ScopeVisibility } from "../models.js";
/**
 * CW-09-02-R5-B-R1: process-start trust claim and official production identity.
 *
 * A Node.js library cannot run before ordinary application code prepares
 * `process.env` or chooses when to import the SDK. Environment variables are
 * therefore not an unforgeable production-identity root.
 *
 * What this module can guarantee:
 * - At SDK module evaluation (before any ordinary public SDK API returns),
 *   a frozen process-environment *claim* is captured. Later `process.env`
 *   mutations, including those that happen after import but before the first
 *   trust API call, cannot change that claim and cannot downgrade a
 *   production request into ordinary non-production.
 * - Ordinary public SDK APIs never establish, reset, or replace production
 *   identity. Their first call does not decide whether the process is
 *   production or non-production.
 * - Production identity (`mode === "production"`) is established only by the
 *   official, zero-argument process-start assembly path
 *   (`bootstrapProductionTrustedRuntime()`), which applies the frozen claim
 *   and then runs the assembly guard. A public setter, ordinary config
 *   object, mutable global, or caller-injectable callback cannot do this.
 * - If official production establishment fails after identity is applied,
 *   the process stays on the production boundary and fail-closes. It does
 *   not degrade to ordinary non-production and then accept caller-injected
 *   authorization services.
 *
 * `createTrustedRuntime()` is not production authorization proof.
 */

export const PROCESS_TRUST_MODE_ENV = "COGNIWEAVE_RUNTIME_MODE";
export const PROCESS_TRUST_AUTHORITY_ENV = "COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID";
export const PROCESS_TRUST_ENGINE_ENVIRONMENT_ENV = "COGNIWEAVE_ENGINE_ENVIRONMENT";
export const PROCESS_TRUST_METADATA_BACKEND_ENV = "COGNIWEAVE_METADATA_BACKEND";
export const PROCESS_TRUST_GRAPH_BACKEND_ENV = "COGNIWEAVE_GRAPH_BACKEND";
export const PROCESS_TRUST_VECTOR_BACKEND_ENV = "COGNIWEAVE_VECTOR_BACKEND";
export const PROCESS_TRUST_EVIDENCE_BACKEND_ENV = "COGNIWEAVE_EVIDENCE_BACKEND";
export const PROCESS_TRUST_TEST_HARNESS_ENV = "COGNIWEAVE_TEST_HARNESS";

const SECRET_ENV_KEYS = [
  "COGNIWEAVE_POSTGRES_URL",
  "OPENBOT_COGNIWEAVE_POSTGRES_URL",
  "DATABASE_URL",
  "COGNIWEAVE_OPENBOT_TOKEN",
  "COGNIWEAVE_OPENBOT_API_KEY",
  "COGNIWEAVE_OPENBOT_ACCESS_TOKEN",
  "OPENBOT_API_KEY",
  "OPENBOT_ACCESS_TOKEN",
] as const;

export type ProcessTrustMode = "production" | "non_production";

/**
 * Distinct process configuration state.
 * Mixed/invalid is never implicitly ordinary non-production.
 * `"production"` means official production identity has been established,
 * not merely that an environment variable requested it.
 */
export type ProcessConfigurationState = "production" | "non_production" | "mixed_or_invalid";

export type ProcessTrustEstablishment = "unestablished" | "established" | "failed_closed";

export type ProcessTrustSnapshot = {
  readonly mode: ProcessTrustMode;
  readonly configurationState: ProcessConfigurationState;
  /** Frozen at SDK module evaluation. Not an unforgeable production identity root. */
  readonly productionRequested: boolean;
  /** True only after the official process-start assembly path establishes production trust. */
  readonly productionTrustEstablished: boolean;
  readonly establishment: ProcessTrustEstablishment;
  readonly simulated: boolean;
  readonly mixedConfiguration: boolean;
  readonly authorityId: string | null;
  readonly engineEnvironment: "service" | "cloud" | null;
  readonly metadataBackend: string | null;
  readonly graphBackend: string | null;
  readonly vectorBackend: string | null;
  readonly evidenceBackend: string | null;
  readonly testHarnessPresent: boolean;
  readonly sealedAt: string;
};

export type SimulatedProductionTrustFixture = {
  readonly authorityId: string;
  readonly engineEnvironment?: "service" | "cloud";
  readonly metadataBackend?: "memory";
  readonly graphBackend?: "memory";
  readonly vectorBackend?: "memory";
  readonly evidenceBackend?: "memory";
  readonly principalBindings?: ReadonlyArray<{
    token: string;
    principal: {
      tenantId: string;
      userId: string;
      subject: { tenantId: string; ownerType: MemorySubject["ownerType"]; ownerId: string };
      roles?: string[];
      allowedWorkspaceIds?: string[];
      agentId?: string;
      tokenId?: string;
    };
  }>;
  readonly authoritativeScopes?: ReadonlyArray<{
    tenantId: string;
    subject: { tenantId: string; ownerType: MemorySubject["ownerType"]; ownerId: string };
    scope: {
      workspaceId: string;
      projectId: string;
      agentId: string;
      visibility: ScopeVisibility;
    };
  }>;
};

type SealedSecrets = {
  readonly postgresUrl?: string;
};

type InternalSnapshot = ProcessTrustSnapshot & {
  readonly principalBindings?: SimulatedProductionTrustFixture["principalBindings"];
  readonly authoritativeScopes?: SimulatedProductionTrustFixture["authoritativeScopes"];
};

type FrozenEnvironmentClaim = {
  readonly productionRequested: boolean;
  readonly mixedConfiguration: boolean;
  readonly authorityId: string | null;
  readonly engineEnvironment: "service" | "cloud" | null;
  readonly metadataBackend: string | null;
  readonly graphBackend: string | null;
  readonly vectorBackend: string | null;
  readonly evidenceBackend: string | null;
  readonly testHarnessPresent: boolean;
  readonly sealedAt: string;
  readonly secrets: SealedSecrets;
};

function trimEnv(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function isTestHarnessPresent(env: NodeJS.ProcessEnv): boolean {
  return env.VITEST === "true" || trimEnv(env[PROCESS_TRUST_TEST_HARNESS_ENV]) === "1";
}

function readEngineEnvironment(value: string | undefined): "service" | "cloud" | null {
  if (value === "service" || value === "cloud") {
    return value;
  }
  return null;
}

function captureEnvironmentClaim(env: NodeJS.ProcessEnv): FrozenEnvironmentClaim {
  const testHarnessPresent = isTestHarnessPresent(env);
  const productionRequested = trimEnv(env[PROCESS_TRUST_MODE_ENV]) === "production";
  const mixedConfiguration = productionRequested && testHarnessPresent;
  const authorityId = trimEnv(env[PROCESS_TRUST_AUTHORITY_ENV]) ?? null;
  const postgresUrl =
    trimEnv(env.COGNIWEAVE_POSTGRES_URL) ??
    trimEnv(env.OPENBOT_COGNIWEAVE_POSTGRES_URL) ??
    trimEnv(env.DATABASE_URL);
  return Object.freeze({
    productionRequested,
    mixedConfiguration,
    authorityId,
    engineEnvironment: readEngineEnvironment(env[PROCESS_TRUST_ENGINE_ENVIRONMENT_ENV]),
    metadataBackend: trimEnv(env[PROCESS_TRUST_METADATA_BACKEND_ENV]) ?? null,
    graphBackend: trimEnv(env[PROCESS_TRUST_GRAPH_BACKEND_ENV]) ?? null,
    vectorBackend: trimEnv(env[PROCESS_TRUST_VECTOR_BACKEND_ENV]) ?? null,
    evidenceBackend: trimEnv(env[PROCESS_TRUST_EVIDENCE_BACKEND_ENV]) ?? null,
    testHarnessPresent,
    sealedAt: new Date().toISOString(),
    secrets: Object.freeze({
      ...(postgresUrl ? { postgresUrl } : {}),
    }),
  });
}

function configurationStateOf(input: {
  mixedConfiguration: boolean;
  productionTrustEstablished: boolean;
  establishment: ProcessTrustEstablishment;
}): ProcessConfigurationState {
  if (input.mixedConfiguration || input.establishment === "failed_closed") {
    return "mixed_or_invalid";
  }
  if (input.productionTrustEstablished) {
    return "production";
  }
  return "non_production";
}

function snapshotFromClaim(
  claim: FrozenEnvironmentClaim,
  extras: {
    mode: ProcessTrustMode;
    productionTrustEstablished: boolean;
    establishment: ProcessTrustEstablishment;
    simulated: boolean;
    principalBindings?: SimulatedProductionTrustFixture["principalBindings"];
    authoritativeScopes?: SimulatedProductionTrustFixture["authoritativeScopes"];
  },
): InternalSnapshot {
  return Object.freeze({
    mode: extras.mode,
    configurationState: configurationStateOf({
      mixedConfiguration: claim.mixedConfiguration,
      productionTrustEstablished: extras.productionTrustEstablished,
      establishment: extras.establishment,
    }),
    productionRequested: claim.productionRequested,
    productionTrustEstablished: extras.productionTrustEstablished,
    establishment: extras.establishment,
    simulated: extras.simulated,
    mixedConfiguration: claim.mixedConfiguration,
    authorityId: claim.authorityId,
    engineEnvironment: claim.engineEnvironment,
    metadataBackend: claim.metadataBackend,
    graphBackend: claim.graphBackend,
    vectorBackend: claim.vectorBackend,
    evidenceBackend: claim.evidenceBackend,
    testHarnessPresent: claim.testHarnessPresent,
    sealedAt: claim.sealedAt,
    ...(extras.principalBindings ? { principalBindings: extras.principalBindings } : {}),
    ...(extras.authoritativeScopes ? { authoritativeScopes: extras.authoritativeScopes } : {}),
  });
}

/**
 * Frozen at this module's evaluation, which happens before any ordinary
 * public SDK API that depends on process trust can return. This is a claim,
 * not production identity. Ordinary application code may still have mutated
 * `process.env` before importing the SDK; that is why environment variables
 * are not treated as an unforgeable production-identity root.
 */
const frozenEnvironmentClaim: FrozenEnvironmentClaim = captureEnvironmentClaim(process.env);
let sealedSecrets: SealedSecrets = frozenEnvironmentClaim.secrets;
let snapshot: InternalSnapshot = snapshotFromClaim(frozenEnvironmentClaim, {
  mode: "non_production",
  productionTrustEstablished: false,
  establishment: "unestablished",
  simulated: false,
});
const simulatedCleanupHooks: Array<() => void> = [];

/**
 * Returns the process trust snapshot.
 * The environment claim was frozen at module evaluation. This function never
 * re-reads `process.env` and never establishes production identity.
 */
export function getProcessTrustSnapshot(): ProcessTrustSnapshot {
  return snapshot;
}

/**
 * True only after official production identity has been established.
 * A frozen environment claim that requested production is not enough.
 */
export function isProductionProcess(): boolean {
  return snapshot.mode === "production" && snapshot.productionTrustEstablished;
}

/**
 * True when ordinary public APIs must not act as a non-production caller
 * because production was requested at module evaluation or official
 * production identity has been established.
 *
 * Mixed/invalid configuration is a distinct rejection state and is not
 * implied by this helper.
 */
export function isProductionTrustBoundaryActive(): boolean {
  return (
    snapshot.productionTrustEstablished ||
    snapshot.mode === "production" ||
    (snapshot.productionRequested && !snapshot.mixedConfiguration)
  );
}

/**
 * Distinct mixed/invalid configuration state. Must not be treated as
 * ordinary non-production.
 */
export function isMixedOrInvalidProcessConfiguration(): boolean {
  return snapshot.mixedConfiguration || snapshot.configurationState === "mixed_or_invalid";
}

export function isSimulatedProductionProcess(): boolean {
  return snapshot.mode === "production" && snapshot.simulated;
}

export function getSealedProcessTrustMode(): ProcessTrustMode {
  return snapshot.mode;
}

/** Same-bundle only. Never include the result in audit records or logs. */
export function getSealedProcessSecrets(): SealedSecrets {
  return sealedSecrets;
}

/** Same-bundle only. Simulated principal bindings never come from request input. */
export function getSimulatedPrincipalBindings(): SimulatedProductionTrustFixture["principalBindings"] {
  return snapshot.principalBindings;
}

export function getSimulatedAuthoritativeScopes(): SimulatedProductionTrustFixture["authoritativeScopes"] {
  return snapshot.authoritativeScopes;
}

export function registerSimulatedProductionCleanup(hook: () => void): void {
  simulatedCleanupHooks.push(hook);
}

export type OfficialProductionTrustEstablishmentResult =
  | { readonly ok: true; readonly snapshot: ProcessTrustSnapshot }
  | {
      readonly ok: false;
      readonly reason: "mixed_test_and_production_configuration" | "process_not_production";
    };

/**
 * Same-bundle helper used only by the official production bootstrap.
 * This is the only path that can establish production identity from the
 * frozen environment claim. Not a public SDK export. Not a setter for
 * ordinary callers. Does not re-read `process.env`.
 */
export function applyOfficialProductionTrustEstablishment(): OfficialProductionTrustEstablishmentResult {
  if (snapshot.mixedConfiguration) {
    if (snapshot.establishment === "unestablished") {
      snapshot = Object.freeze({
        ...snapshot,
        establishment: "failed_closed",
        configurationState: "mixed_or_invalid",
      });
    }
    return { ok: false, reason: "mixed_test_and_production_configuration" };
  }
  if (snapshot.mode === "production" && snapshot.productionTrustEstablished) {
    return { ok: true, snapshot };
  }
  if (!snapshot.productionRequested && !snapshot.simulated) {
    return { ok: false, reason: "process_not_production" };
  }
  snapshot = Object.freeze({
    ...snapshot,
    mode: "production",
    productionTrustEstablished: true,
    establishment: "established",
    configurationState: "production",
  });
  return { ok: true, snapshot };
}

/**
 * Same-bundle helper. After official production identity has been applied,
 * a later assembly failure must not degrade the process to ordinary
 * non-production. Not a public SDK export.
 */
export function markOfficialProductionTrustFailedClosed(): void {
  if (snapshot.mode === "production" || snapshot.productionRequested) {
    snapshot = Object.freeze({
      ...snapshot,
      mode: snapshot.mode === "production" ? "production" : snapshot.mode,
      productionTrustEstablished: snapshot.productionTrustEstablished || snapshot.mode === "production",
      establishment: snapshot.productionTrustEstablished || snapshot.mode === "production" ? "established" : "failed_closed",
      configurationState:
        snapshot.mode === "production" || snapshot.productionTrustEstablished ? "production" : "mixed_or_invalid",
    });
  }
}

/**
 * Test-only. Installs a simulated production snapshot.
 * Refuses if the sealed snapshot is real production, if no test harness was
 * present at first seal, or if test and production markers were mixed.
 * Not a public SDK export.
 */
export function installSimulatedProcessTrustForTests(fixture: SimulatedProductionTrustFixture): () => void {
  const current = getProcessTrustSnapshot();
  if (current.mixedConfiguration) {
    throw new Error("Cannot install a simulated production snapshot over mixed test/production process configuration");
  }
  if (current.mode === "production" && !current.simulated) {
    throw new Error("Cannot install a simulated production snapshot over a sealed real production process");
  }
  if (!current.testHarnessPresent) {
    throw new Error("Simulated production process trust requires a test harness present at first seal");
  }
  const authorityId = fixture.authorityId.trim();
  if (!authorityId) {
    throw new Error("Simulated production bootstrap authority id is required");
  }
  const previousSnapshot = snapshot;
  const previousSecrets = sealedSecrets;
  snapshot = Object.freeze({
    mode: "production",
    configurationState: "production",
    productionRequested: true,
    productionTrustEstablished: true,
    establishment: "established",
    simulated: true,
    mixedConfiguration: false,
    authorityId,
    engineEnvironment: fixture.engineEnvironment ?? "service",
    metadataBackend: fixture.metadataBackend ?? "memory",
    graphBackend: fixture.graphBackend ?? "memory",
    vectorBackend: fixture.vectorBackend ?? "memory",
    evidenceBackend: fixture.evidenceBackend ?? "memory",
    testHarnessPresent: true,
    sealedAt: new Date().toISOString(),
    ...(fixture.principalBindings ? { principalBindings: fixture.principalBindings } : {}),
    ...(fixture.authoritativeScopes ? { authoritativeScopes: fixture.authoritativeScopes } : {}),
  });
  sealedSecrets = Object.freeze({});
  return () => {
    for (const hook of [...simulatedCleanupHooks].reverse()) {
      hook();
    }
    snapshot = previousSnapshot;
    sealedSecrets = previousSecrets;
  };
}

/**
 * Secret environment key names that must never appear in audit output.
 * Values are not returned.
 */
export function secretProcessEnvKeyNames(): readonly string[] {
  return SECRET_ENV_KEYS;
}

export function assertNoSecretMaterial(value: unknown, path = "value"): void {
  if (!value || typeof value !== "object") {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoSecretMaterial(entry, `${path}[${index}]`));
    return;
  }
  const record = value as Record<string, unknown>;
  for (const [key, entry] of Object.entries(record)) {
    const lowered = key.toLowerCase();
    if (
      lowered.includes("password") ||
      lowered.includes("secret") ||
      lowered.includes("api_key") ||
      lowered.includes("apikey") ||
      lowered.includes("access_token") ||
      lowered.includes("accesstoken") ||
      lowered.includes("connectionstring") ||
      lowered.includes("connection_string") ||
      SECRET_ENV_KEYS.includes(key as (typeof SECRET_ENV_KEYS)[number])
    ) {
      throw new Error(`Secret material must not appear in audit output at ${path}.${key}`);
    }
    if (typeof entry === "string") {
      const looksLikeUrlWithCredential = /:\/\/[^/\s]+:[^@/\s]+@/.test(entry);
      if (looksLikeUrlWithCredential) {
        throw new Error(`Secret material must not appear in audit output at ${path}.${key}`);
      }
    }
    assertNoSecretMaterial(entry, `${path}.${key}`);
  }
}
