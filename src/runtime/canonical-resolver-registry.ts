/**
 * Package-internal Canonical resolver registration.
 *
 * This module is not part of the public SDK surface and must not be published
 * as a standalone JavaScript file. The SDK build inlines it into the public
 * entry bundles so packaged consumers cannot load a named getter or register
 * hook by package specifier or filesystem path.
 *
 * Registration is write-once so a caller who holds an Engine instance cannot
 * replace the resolver used by REST authorization.
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
