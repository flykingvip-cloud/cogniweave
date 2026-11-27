# CW-09-02-R5 Trusted Runtime Boundary

Implementation evidence, not acceptance. This document describes the runtime
bootstrap and public authorization entry points after R5.

## Runtime bootstrap and call chain

1. The integration layer (OpenBot or a test bootstrap) calls
   `createTrustedRuntime()` with an explicit `environment` and the production
   Principal Provider, Authoritative Binding Query, and Delegation Store.
2. `createTrustedRuntime()` freezes a public handle (`environment`,
   `requireAuth`) and stores the sealed assembly in a module-private WeakMap.
   A same-shaped ordinary object cannot resolve that assembly.
3. `createCogniWeaveRuntime()` / `new InMemoryCogniWeaveEngine()` receive the
   handle. service/cloud always force `requireAuth: true`. local may only be
   selected at bootstrap; a job or HTTP request cannot downgrade it.
4. Authorization functions (`authorizeTrustedExecution`,
   `authorizeEngineDirectInvocation`, REST routing) call
   `resolveTrustedRuntimeAssembly(handle)` and snapshot environment,
   requireAuth, and services once. Request objects may carry a bearer token
   and business data only.
5. `metadataStore` remains a data-plane store. It is never auto-promoted to a
   Binding Query on a production request path. A local or production bootstrap
   may pass an already-built Binding Query into `createTrustedRuntime()`.

## Public identity and authorization entry points

### Optimization service

- `runOptimizationJob({ runtime, authorization?: { bearerToken }, ...job })`
- `authorizeTrustedExecution({ runtime, authorization?: { bearerToken }, request })`

### REST

- `createCogniWeaveHttpServer` / `routeCogniWeaveHttpRequest`
- Identity and Binding Query come from the engine-held `TrustedRuntime`.
- Declared-scope routes use `authorizeDeclaredScope()`.
- Resource-id routes use `authorizeCanonicalResource()` (`read` / `manage` / `revoke`).
- `/v1/memory-resources/:id/revoke` uses `revoke` mode and returns a uniform 404
  for unauthorized or invisible resources.

### Engine / SDK direct

See `ENGINE_DIRECT_AUTH_ENTRYPOINTS` in `src/auth/engine-invocation.ts`.
Notable methods: `rebuildFromTruth`, `repairIndexes`, `recoverFromCanonical`,
`compactJournals`, `writeBack`, `ingest`, `queryAtoms`, resource traces, and
source lifecycle operations. Missing security context or authoritative stores
fail closed in service/cloud.

`ensureMemorySubjectBinding()` is not a production binding-provision API. It
fails closed in service/cloud so a caller cannot self-create a live binding.
Local unauthenticated engines may still use it as a test helper.

`resolveCanonicalResourceScopeForAuthorization()` is an internal lookup used
by authorization gates. The public `resolveCanonicalResourceScope()` is
itself authorized in service/cloud.

## Non-goals still unverified

- Real PostgreSQL multi-instance Binding Store behavior
- Real OpenBot Principal Provider integration
- Merge to `main`, production migration, or traffic cutover
