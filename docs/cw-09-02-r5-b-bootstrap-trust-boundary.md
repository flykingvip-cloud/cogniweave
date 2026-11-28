# CW-09-02-R5-B Bootstrap Trust Boundary

Implementation evidence, not acceptance. This document describes the production
Trusted Runtime startup trust boundary.

## Roles

| Role | Meaning |
|---|---|
| Production Bootstrap Authority | The authority id captured in the frozen process-environment claim (`COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID`) and applied only by official production establishment. Not a caller-declared field, and not production identity by itself. |
| Trusted Runtime Assembly | The module-private sealed assembly bound to a public handle. Production assemblies have `trustClass` `production` or `simulated_production`. |
| Trusted Principal Provider | Created inside official production bootstrap. Never accepted as a caller-injected object in production. |
| Authoritative Binding Query | Created from the bootstrap's own Canonical Store and bound to that store. |
| Delegation Store | Official production (or simulated-production) store that can validate authorization records. |
| Canonical Metadata Store | Created inside official production bootstrap and held only as an Engine `#private` field. |
| Engine Runtime | Constructed only by `createProductionEngine()` in a production process. |
| Ordinary Application Caller | Any in-process caller of the public SDK, including `createTrustedRuntime()`. |

## Process-start claim and official production identity

A Node.js library cannot run before ordinary application code prepares
`process.env` or chooses when to import the SDK. Environment variables,
including `COGNIWEAVE_RUNTIME_MODE`, are therefore **not** an unforgeable
production-identity root. `NODE_ENV=production` is also not a CogniWeave
production trust root.

What the SDK does guarantee:

1. At SDK module evaluation — before any ordinary public SDK API returns — a
   frozen process-environment *claim* captures:
   - `COGNIWEAVE_RUNTIME_MODE` — the exact value `production` is a production
     *request*, not production identity
   - `COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID` — required for official production startup
   - `COGNIWEAVE_ENGINE_ENVIRONMENT` — must be `service` or `cloud`
   - backend selectors and a secret bag (for example a Postgres URL) that is
     never audited
2. Later mutations of `process.env`, including mutations after import and
   before the first trust API call, cannot change the frozen claim and cannot
   downgrade a production request into ordinary non-production.
3. The first call to any ordinary public SDK API does not decide whether the
   process is production or non-production, and cannot establish, reset, or
   replace production identity.
4. Production identity (`mode === "production"`, `productionTrustEstablished`)
   is established only by the official, zero-argument process-start assembly
   path `bootstrapProductionTrustedRuntime()`. There is no public setter,
   ordinary config object, mutable global, or caller-injectable callback that
   can do this.
5. If official production establishment fails after identity is applied, the
   process stays on the production boundary and fail-closes. It does not
   degrade to ordinary non-production and then accept caller-injected
   authorization services.

A process that mixes a production request with a test harness marker
(`VITEST=true` or `COGNIWEAVE_TEST_HARNESS=1`) at module evaluation is
`mixedConfiguration` / `configurationState: "mixed_or_invalid"`. That is a
distinct rejection state, not ordinary non-production, and fail-closes
runtime creation paths.

## Official production path

`bootstrapProductionTrustedRuntime()` accepts no arguments. It:

1. Applies official production identity from the frozen environment claim
   (this is the only path that can do so), then requires an authority id and a
   service/cloud engine environment.
2. Creates stores and trusted services internally.
3. Runs the Production Assembly Guard (blessed implementations, same-assembly
   Canonical Store / Binding Query association, Delegation Store probe, no
   caller-controlled switch that turns authorization off).
4. Issues a single-use production permit and seals a write-once runtime.
5. Constructs the Engine through an internal gate. The public constructor is
   refused in a production process.
6. Returns `{ runtime, engine, service, server, audit }` with no store or
   trusted-service references.

Real production currently fail-closes if an official OpenBot Principal Provider
or durable Delegation Store is not configured. That is intentional; those
integrations remain independently unverified. Simulated production, used only
by a test-only hook that refuses a real production snapshot, creates in-process
memory implementations so the guard, audit, and anti-escape tests can run.

## Assembly audit

A successful or failed production start records:

- Assembly ID or `unissued` for a failed start
- Runtime environment and process trust mode
- Bootstrap authority id
- Implementation type and verification status of principal provider, binding
  query, delegation store, and metadata store
- Canonical Store / Binding Query association
- Creation time, verification result, and failure reason

The audit never includes passwords, API keys, access tokens, or connection
strings. `getEngineProductionAssemblyAudit(engine)` returns the bound record.
`submitProductionAssemblyAudit()` always returns false and never binds or
replaces an assembly. The audit is not a substitute for runtime authorization.

## Residual risks

A caller who already holds a *different* store instance still holds that
instance. Production APIs do not hand back the live production instances, and
public factory/constructor injection into the live Engine is refused. A second
process or a raw database login outside this SDK is outside this boundary.
