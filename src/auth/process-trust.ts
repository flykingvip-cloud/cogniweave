import type { MemorySubject, Scope, ScopeVisibility } from "../models.js";
/**
 * CW-09-02-R5-B: process-start trust snapshot.
 *
 * Production bootstrap identity is determined only by a sealed process-start
 * boundary. Request parameters, ordinary config objects, caller-declared
 * fields, and later mutations of process.env cannot change this snapshot.
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

export type ProcessTrustSnapshot = {
  readonly mode: ProcessTrustMode;
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

let snapshot: InternalSnapshot | undefined;
let sealedSecrets: SealedSecrets | undefined;
const simulatedCleanupHooks: Array<() => void> = [];

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

function readFromEnv(env: NodeJS.ProcessEnv): { snapshot: InternalSnapshot; secrets: SealedSecrets } {
  const testHarnessPresent = isTestHarnessPresent(env);
  const wantsProduction = trimEnv(env[PROCESS_TRUST_MODE_ENV]) === "production";
  const mixedConfiguration = wantsProduction && testHarnessPresent;
  const authorityId = trimEnv(env[PROCESS_TRUST_AUTHORITY_ENV]) ?? null;
  const snapshot: InternalSnapshot = Object.freeze({
    mode: wantsProduction && !mixedConfiguration ? "production" : "non_production",
    simulated: false,
    mixedConfiguration,
    authorityId,
    engineEnvironment: readEngineEnvironment(env[PROCESS_TRUST_ENGINE_ENVIRONMENT_ENV]),
    metadataBackend: trimEnv(env[PROCESS_TRUST_METADATA_BACKEND_ENV]) ?? null,
    graphBackend: trimEnv(env[PROCESS_TRUST_GRAPH_BACKEND_ENV]) ?? null,
    vectorBackend: trimEnv(env[PROCESS_TRUST_VECTOR_BACKEND_ENV]) ?? null,
    evidenceBackend: trimEnv(env[PROCESS_TRUST_EVIDENCE_BACKEND_ENV]) ?? null,
    testHarnessPresent,
    sealedAt: new Date().toISOString(),
  });
  const postgresUrl =
    trimEnv(env.COGNIWEAVE_POSTGRES_URL) ??
    trimEnv(env.OPENBOT_COGNIWEAVE_POSTGRES_URL) ??
    trimEnv(env.DATABASE_URL);
  const secrets: SealedSecrets = Object.freeze({
    ...(postgresUrl ? { postgresUrl } : {}),
  });
  return { snapshot, secrets };
}

/**
 * Returns the sealed process-start trust snapshot.
 * The first call freezes the snapshot; later process.env mutations are ignored.
 */
export function getProcessTrustSnapshot(): ProcessTrustSnapshot {
  if (!snapshot) {
    const read = readFromEnv(process.env);
    snapshot = read.snapshot;
    sealedSecrets = read.secrets;
  }
  return snapshot;
}

export function isProductionProcess(): boolean {
  return getProcessTrustSnapshot().mode === "production";
}

export function isSimulatedProductionProcess(): boolean {
  const current = getProcessTrustSnapshot();
  return current.mode === "production" && current.simulated;
}

export function getSealedProcessTrustMode(): ProcessTrustMode {
  return getProcessTrustSnapshot().mode;
}

/** Same-bundle only. Never include the result in audit records or logs. */
export function getSealedProcessSecrets(): SealedSecrets {
  getProcessTrustSnapshot();
  return sealedSecrets ?? Object.freeze({});
}

/** Same-bundle only. Simulated principal bindings never come from request input. */
export function getSimulatedPrincipalBindings(): SimulatedProductionTrustFixture["principalBindings"] {
  const current = snapshot ?? getProcessTrustSnapshot();
  return (current as InternalSnapshot).principalBindings;
}

export function getSimulatedAuthoritativeScopes(): SimulatedProductionTrustFixture["authoritativeScopes"] {
  const current = snapshot ?? getProcessTrustSnapshot();
  return (current as InternalSnapshot).authoritativeScopes;
}

export function registerSimulatedProductionCleanup(hook: () => void): void {
  simulatedCleanupHooks.push(hook);
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
