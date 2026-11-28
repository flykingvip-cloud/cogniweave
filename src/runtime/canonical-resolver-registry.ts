/**
 * Package-internal Canonical resolver registration.
 *
 * Not part of the public SDK surface. The public package export allowlist must
 * not expose this module. Registration is write-once so a caller who holds an
 * Engine instance cannot replace the resolver used by REST authorization.
 */
import { UntrustedRuntimeError } from "../errors.js";
import type { CanonicalResourceScopeResolver } from "../auth/canonical-scope.js";

const engineCanonicalAuthorizationResolvers = new WeakMap<object, CanonicalResourceScopeResolver>();

export function getEngineCanonicalAuthorizationResolver(
  engine: object,
): CanonicalResourceScopeResolver | undefined {
  return engineCanonicalAuthorizationResolvers.get(engine);
}

export function registerEngineCanonicalAuthorizationResolver(
  engine: object,
  resolver: CanonicalResourceScopeResolver,
): void {
  if (engineCanonicalAuthorizationResolvers.has(engine)) {
    throw new UntrustedRuntimeError(
      "Canonical authorization resolver is already sealed and cannot be replaced",
      { decision: "deny", reason: "untrusted_runtime" },
    );
  }
  engineCanonicalAuthorizationResolvers.set(engine, resolver);
}
