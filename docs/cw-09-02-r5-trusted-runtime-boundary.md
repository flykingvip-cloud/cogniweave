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
   handle. The Engine stores it as an ECMAScript `#private` field and in a
   module-private WeakMap; it is not a public instance property. service/cloud
   always force `requireAuth: true`. local may only be selected at bootstrap;
   a job or HTTP request cannot downgrade it.
4. Authorization functions (`authorizeTrustedExecution`,
   `authorizeEngineDirectInvocation`, REST routing) call the same-bundle
   internal `resolveTrustedRuntimeAssembly(handle)` and snapshot environment,
   requireAuth, and services once. That unpack helper is not a public SDK
   root export. Request objects may carry a bearer token and business data
   only.
5. `metadataStore` remains a data-plane store. It is never auto-promoted to a
   Binding Query on a production request path. A local or production bootstrap
   may pass an already-built Binding Query into `createTrustedRuntime()`.

## Public identity and authorization entry points

### Optimization service

- `runOptimizationJob({ runtime, authorization?: { bearerToken }, ...job })`
- `authorizeTrustedExecution({ runtime, authorization?: { bearerToken }, request })`

### REST

- `createCogniWeaveHttpServer` / `routeCogniWeaveHttpRequest`
- Identity and Binding Query come from the engine-held `TrustedRuntime`,
  obtained through a same-bundle internal handle lookup, not a public
  Engine property or SDK-root unpack helper.
- Declared-scope routes use `authorizeDeclaredScope()`.
- Resource-id routes use `authorizeCanonicalResource()` (`read` / `manage` / `revoke`).
- `/v1/memory-resources/:id/revoke` uses `revoke` mode and returns a uniform 404
  for unauthorized or invisible resources.

### Engine / SDK direct

See `ENGINE_DIRECT_AUTH_ENTRYPOINTS` in `src/auth/engine-invocation.ts` for the
remaining public Engine I/O surface. Notable methods: `rebuildFromTruth`,
`repairIndexes`, `recoverFromCanonical`, `compactJournals`, `writeBack`,
`ingest`, `queryAtoms` / `queryAtomsHybrid` / `searchEvidence`, resource
traces, and source lifecycle operations. Missing security context or
authoritative stores fail closed in service/cloud.

The inventory is not itself proof of coverage; each public method must call
the unified gate before Canonical or Derived I/O. Scoped batch methods
(`upsertAtoms`, `compactJournals`, `recoverFromCanonical`, source lifecycle)
must not apply one Scope grant to another Scope's data or receipt IDs.

`ensureMemorySubjectBinding()` is not a production binding-provision API. It
fails closed in service/cloud so a caller cannot self-create a live binding.
Local unauthenticated engines may still use it as a test helper.

Ungated Canonical ownership lookup is engine-internal (not on
`CogniWeaveEngine` or the instance public surface). The public
`resolveCanonicalResourceScope()` is itself authorized in service/cloud.
`getSourceBindingStatus` and `isSourcePathRetrievable` are no longer public
Engine methods. `isEvidenceRetrievable` is a private helper used after
authorization inside `searchEvidence`.
`rebuildFromTruth` / `repairDerivedIndexes` in `src/journal/repair.ts` are
engine-internal and are not exported from the package root.

## Non-goals still unverified

- Real PostgreSQL multi-instance Binding Store behavior
- Real OpenBot Principal Provider integration
- Merge to `main`, production migration, or traffic cutover
