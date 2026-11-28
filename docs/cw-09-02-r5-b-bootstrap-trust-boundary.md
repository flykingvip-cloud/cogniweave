# CW-09-02-R5-B Bootstrap Trust Boundary

Implementation evidence, not acceptance. This document describes the production
Trusted Runtime startup trust boundary.

## Roles

| Role | Meaning |
|---|---|
| Production Bootstrap Authority | The sealed process-start identity (`COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID` captured at first snapshot). Not a caller-declared field. |
| Trusted Runtime Assembly | The module-private sealed assembly bound to a public handle. Production assemblies have `trustClass` `production` or `simulated_production`. |
| Trusted Principal Provider | Created inside official production bootstrap. Never accepted as a caller-injected object in production. |
| Authoritative Binding Query | Created from the bootstrap's own Canonical Store and bound to that store. |
| Delegation Store | Official production (or simulated-production) store that can validate authorization records. |
| Canonical Metadata Store | Created inside official production bootstrap and held only as an Engine `#private` field. |
| Engine Runtime | Constructed only by `createProductionEngine()` in a production process. |
| Ordinary Application Caller | Any in-process caller of the public SDK, including `createTrustedRuntime()`. |

## Process-start seal

The first read of the process trust snapshot freezes:

- `COGNIWEAVE_RUNTIME_MODE` — only the exact value `production` enables production mode
- `COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID` — required for production startup
- `COGNIWEAVE_ENGINE_ENVIRONMENT` — must be `service` or `cloud`
- backend selectors and a secret bag (for example a Postgres URL) that is never audited

`NODE_ENV=production` is not a CogniWeave production trust root. Later mutations
of `process.env` are ignored. A process that mixes production mode with a test
harness marker (`VITEST=true` or `COGNIWEAVE_TEST_HARNESS=1`) at first seal is
`mixedConfiguration` and fail-closes every runtime creation path.

## Official production path

`bootstrapProductionTrustedRuntime()` accepts no arguments. It:

1. Requires a sealed production snapshot, an authority id, and a service/cloud
   engine environment.
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
