import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const tsxBin = join(packageRoot, "node_modules", ".bin", "tsx");

const factoryPath = JSON.stringify(resolve(packageRoot, "src/adapters/factory.ts"));
const postgresStorePath = JSON.stringify(resolve(packageRoot, "src/adapters/postgres-metadata.ts"));
const postgresClientPath = JSON.stringify(resolve(packageRoot, "src/adapters/postgres-client.ts"));
const sqliteStorePath = JSON.stringify(resolve(packageRoot, "src/adapters/local-metadata.ts"));
const pgvectorPath = JSON.stringify(resolve(packageRoot, "src/adapters/pgvector-vector.ts"));
const neo4jPath = JSON.stringify(resolve(packageRoot, "src/adapters/neo4j-graph.ts"));
const inMemoryPath = JSON.stringify(resolve(packageRoot, "src/storage/in-memory.ts"));
const migrationPath = JSON.stringify(resolve(packageRoot, "src/migration/local-to-postgres.ts"));
const cliPath = JSON.stringify(resolve(packageRoot, "src/cli.ts"));
const processTrustPath = JSON.stringify(resolve(packageRoot, "src/auth/process-trust.ts"));

type ChildResult = { status: number | null; stdout: string; stderr: string };

function runChild(env: Record<string, string | undefined>, source: string): ChildResult {
  const dir = mkdtempSync(join(tmpdir(), "cw-r5b-r2-child-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ type: "module" }), "utf8");
  const file = join(dir, "entry.mts");
  writeFileSync(file, source, "utf8");
  const childEnv = { ...process.env };
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) {
      delete childEnv[key];
    } else {
      childEnv[key] = value;
    }
  }
  const result = spawnSync(tsxBin, [file], {
    cwd: packageRoot,
    encoding: "utf8",
    env: childEnv,
  });
  return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function lastJson(result: ChildResult): Record<string, unknown> {
  expect(result.status, result.stderr + result.stdout).toBe(0);
  const line = result.stdout.trim().split("\n").at(-1) ?? "{}";
  return JSON.parse(line) as Record<string, unknown>;
}

const mixedEnv = {
  VITEST: "true",
  COGNIWEAVE_TEST_HARNESS: "1",
  COGNIWEAVE_RUNTIME_MODE: "production",
  COGNIWEAVE_BOOTSTRAP_AUTHORITY_ID: "authority_r5b_r2",
  COGNIWEAVE_ENGINE_ENVIRONMENT: "service",
  COGNIWEAVE_METADATA_BACKEND: "memory",
};

const memoryConfig = `{
  environment: "service",
  metadataBackend: "memory",
  graphBackend: "memory",
  evidenceBackend: "memory",
  vectorBackend: "memory",
}`;

describe("CW-09-02-R5-B-R2 mixed/invalid process configuration fail-closes all public store and CLI entries", () => {
  it("A. createAdapterBundle refuses mixed configuration and does not return or construct a Store bundle", () => {
    const storePath = join(mkdtempSync(join(tmpdir(), "cw-r5b-r2-a-")), "should-not-be-created.sqlite");
    const result = runChild(
      mixedEnv,
      `
        const report = {
          scenario: "A",
          initialEnv: { COGNIWEAVE_RUNTIME_MODE: "production", VITEST: "true", COGNIWEAVE_TEST_HARNESS: "1" },
          importOrder: ["process-trust", "adapters/factory"],
          mutationTiming: "none; mixed flags present at process start and module evaluation",
          firstTrustApiTiming: "createAdapterBundle is the first public store API",
          expected: "mixed_test_and_production_configuration; no bundle returned; local sqlite file not created",
        };
        const processTrust = await import(${processTrustPath});
        const factory = await import(${factoryPath});
        const snapshot = processTrust.getProcessTrustSnapshot();
        let memoryAttempt = { ok: false, reason: null, message: null, hasBundle: false };
        try {
          const bundle = factory.createAdapterBundle(${memoryConfig});
          memoryAttempt = { ok: true, reason: null, message: null, hasBundle: Boolean(bundle && bundle.metadataStore) };
        } catch (error) {
          memoryAttempt = {
            ok: false,
            reason: error?.reason ?? null,
            message: error?.message ?? String(error),
            hasBundle: false,
          };
        }
        const localPath = ${JSON.stringify(storePath)};
        let localAttempt = { ok: false, reason: null, fileExistsAfter: false };
        try {
          factory.createAdapterBundle({
            environment: "local",
            metadataBackend: "local",
            metadataStorePath: localPath,
            graphBackend: "memory",
            evidenceBackend: "memory",
            vectorBackend: "memory",
          });
          localAttempt = { ok: true, reason: null, fileExistsAfter: false };
        } catch (error) {
          const fs = await import("node:fs");
          localAttempt = {
            ok: false,
            reason: error?.reason ?? null,
            fileExistsAfter: fs.existsSync(localPath),
          };
        }
        console.log(JSON.stringify({
          ...report,
          configurationState: snapshot.configurationState,
          mixedConfiguration: snapshot.mixedConfiguration,
          memoryAttempt,
          localAttempt,
        }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("A");
    expect(payload.configurationState).toBe("mixed_or_invalid");
    expect(payload.mixedConfiguration).toBe(true);
    expect(payload.memoryAttempt).toMatchObject({
      ok: false,
      reason: "mixed_test_and_production_configuration",
      hasBundle: false,
    });
    expect(String((payload.memoryAttempt as { message: string }).message)).toMatch(/runtime configuration conflict/i);
    expect(payload.localAttempt).toMatchObject({
      ok: false,
      reason: "mixed_test_and_production_configuration",
      fileExistsAfter: false,
    });
    expect(existsSync(storePath)).toBe(false);
  });

  it("B. public PostgreSQL Store Factory refuses before any client connect or query", () => {
    const result = runChild(
      mixedEnv,
      `
        const report = {
          scenario: "B",
          initialEnv: { COGNIWEAVE_RUNTIME_MODE: "production", VITEST: "true" },
          importOrder: ["postgres-metadata"],
          mutationTiming: "none",
          firstTrustApiTiming: "new PostgresMetadataStore with an instrumented client",
          expected: "refused before client.query / connect; sideEffects remain 0",
        };
        const sideEffects = [];
        const client = {
          query: async () => {
            sideEffects.push("query");
            return { rows: [], rowCount: 0 };
          },
          connect: async () => {
            sideEffects.push("connect");
            return { query: async () => ({ rows: [], rowCount: 0 }), release() { sideEffects.push("release"); } };
          },
        };
        const { PostgresMetadataStore } = await import(${postgresStorePath});
        let attempt = { ok: false, reason: null };
        try {
          new PostgresMetadataStore({
            backend: "postgres",
            environment: "service",
            client,
            schema: "should_not_be_used",
          });
          attempt = { ok: true, reason: null };
        } catch (error) {
          attempt = { ok: false, reason: error?.reason ?? null };
        }
        console.log(JSON.stringify({ ...report, attempt, sideEffects }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("B");
    expect(payload.attempt).toMatchObject({ ok: false, reason: "mixed_test_and_production_configuration" });
    expect(payload.sideEffects).toEqual([]);
  });

  it("C. public SQLite Store Factory refuses before the database file is created or opened", () => {
    const storePath = join(mkdtempSync(join(tmpdir(), "cw-r5b-r2-c-")), "should-not-be-created.sqlite");
    const result = runChild(
      mixedEnv,
      `
        const report = {
          scenario: "C",
          initialEnv: { COGNIWEAVE_RUNTIME_MODE: "production", VITEST: "true" },
          importOrder: ["local-metadata"],
          mutationTiming: "none",
          firstTrustApiTiming: "new LocalMetadataStore",
          expected: "refused; sqlite file not created",
        };
        const fs = await import("node:fs");
        const storePath = ${JSON.stringify(storePath)};
        const { LocalMetadataStore } = await import(${sqliteStorePath});
        let attempt = { ok: false, reason: null, fileExistsAfter: false };
        try {
          new LocalMetadataStore({ backend: "local", environment: "local", path: storePath });
          attempt = { ok: true, reason: null, fileExistsAfter: fs.existsSync(storePath) };
        } catch (error) {
          attempt = { ok: false, reason: error?.reason ?? null, fileExistsAfter: fs.existsSync(storePath) };
        }
        console.log(JSON.stringify({ ...report, attempt }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("C");
    expect(payload.attempt).toMatchObject({
      ok: false,
      reason: "mixed_test_and_production_configuration",
      fileExistsAfter: false,
    });
    expect(existsSync(storePath)).toBe(false);
  });

  it("D. SQL Client Factory refuses before connection string validation or pg import", () => {
    const result = runChild(
      mixedEnv,
      `
        const report = {
          scenario: "D",
          initialEnv: { COGNIWEAVE_RUNTIME_MODE: "production", VITEST: "true" },
          importOrder: ["postgres-client"],
          mutationTiming: "none",
          firstTrustApiTiming: "createPgSqlClient with an empty connection string, then a dummy URL",
          expected: "mixed refusal, not a connectionString or pg import error",
        };
        const { createPgSqlClient } = await import(${postgresClientPath});
        const attempts = {};
        for (const [name, options] of [
          ["empty", { connectionString: "" }],
          ["dummy", { connectionString: "postgres://probe:probe@127.0.0.1:1/should_not_connect" }],
        ]) {
          try {
            await createPgSqlClient(options);
            attempts[name] = { ok: true, reason: null, message: null };
          } catch (error) {
            attempts[name] = {
              ok: false,
              reason: error?.reason ?? null,
              message: error?.message ?? String(error),
            };
          }
        }
        console.log(JSON.stringify({ ...report, attempts }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("D");
    const attempts = payload.attempts as Record<string, { ok: boolean; reason: string; message: string }>;
    expect(attempts.empty).toMatchObject({ ok: false, reason: "mixed_test_and_production_configuration" });
    expect(attempts.empty.message).toMatch(/runtime configuration conflict/i);
    expect(attempts.empty.message).not.toMatch(/non-empty connectionString|could not import pg/);
    expect(attempts.dummy).toMatchObject({ ok: false, reason: "mixed_test_and_production_configuration" });
    expect(attempts.dummy.message).not.toMatch(/could not import pg|ECONNREFUSED/);
  });

  it("E. CLI bootstrap-schema refuses and does not execute schema operations", () => {
    const storePath = join(mkdtempSync(join(tmpdir(), "cw-r5b-r2-e-")), "schema-should-not-exist.sqlite");
    const result = runChild(
      mixedEnv,
      `
        const report = {
          scenario: "E",
          initialEnv: { COGNIWEAVE_RUNTIME_MODE: "production", VITEST: "true" },
          importOrder: ["cli"],
          mutationTiming: "none",
          firstTrustApiTiming: "runCogniWeaveCli bootstrap-schema",
          expected: "exit 1; configuration conflict; sqlite file not created",
        };
        const fs = await import("node:fs");
        const storePath = ${JSON.stringify(storePath)};
        const { runCogniWeaveCli } = await import(${cliPath});
        const io = { logs: [], errors: [] };
        const exitCode = await runCogniWeaveCli(
          ["bootstrap-schema", "--metadata-backend", "local", "--metadata-store-path", storePath, "--graph-backend", "memory", "--vector-backend", "memory"],
          {
            log: (message) => io.logs.push(String(message)),
            error: (message) => io.errors.push(String(message)),
          },
        );
        console.log(JSON.stringify({
          ...report,
          exitCode,
          errors: io.errors,
          logs: io.logs,
          fileExistsAfter: fs.existsSync(storePath),
        }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("E");
    expect(payload.exitCode).toBe(1);
    expect(payload.fileExistsAfter).toBe(false);
    expect(existsSync(storePath)).toBe(false);
    const errors = payload.errors as string[];
    expect(errors.join("\n")).toMatch(/runtime configuration conflict/i);
    expect(errors.join("\n")).not.toMatch(/Dry run ok|bootstrap complete|schema bootstrapped/i);
  });

  it("F. CLI recover refuses and does not execute recovery or mutate the store file", () => {
    const dir = mkdtempSync(join(tmpdir(), "cw-r5b-r2-f-"));
    const storePath = join(dir, "existing.sqlite");
    const marker = "PREEXISTING_STORE_BYTES_MUST_NOT_CHANGE\n";
    writeFileSync(storePath, marker, "utf8");
    const beforeHash = createHash("sha256").update(readFileSync(storePath)).digest("hex");
    const result = runChild(
      mixedEnv,
      `
        const report = {
          scenario: "F",
          initialEnv: { COGNIWEAVE_RUNTIME_MODE: "production", VITEST: "true" },
          importOrder: ["cli"],
          mutationTiming: "none",
          firstTrustApiTiming: "runCogniWeaveCli recover against a preexisting store file",
          expected: "exit 1; file bytes unchanged; no recovery",
        };
        const fs = await import("node:fs");
        const crypto = await import("node:crypto");
        const storePath = ${JSON.stringify(storePath)};
        const before = crypto.createHash("sha256").update(fs.readFileSync(storePath)).digest("hex");
        const { runCogniWeaveCli } = await import(${cliPath});
        const io = { errors: [], logs: [] };
        const exitCode = await runCogniWeaveCli(
          ["recover", "--metadata-backend", "local", "--metadata-store-path", storePath, "--graph-backend", "memory", "--vector-backend", "memory"],
          {
            log: (message) => io.logs.push(String(message)),
            error: (message) => io.errors.push(String(message)),
          },
        );
        const afterBytes = fs.readFileSync(storePath);
        const after = crypto.createHash("sha256").update(afterBytes).digest("hex");
        console.log(JSON.stringify({
          ...report,
          exitCode,
          errors: io.errors,
          logs: io.logs,
          before,
          after,
          unchanged: before === after,
          textUnchanged: afterBytes.toString("utf8") === ${JSON.stringify(marker)},
        }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("F");
    expect(payload.exitCode).toBe(1);
    expect(payload.unchanged).toBe(true);
    expect(payload.textUnchanged).toBe(true);
    expect(payload.after).toBe(beforeHash);
    expect((payload.errors as string[]).join("\n")).toMatch(/runtime configuration conflict/i);
    expect((payload.logs as string[]).join("\n")).not.toMatch(/recovered journalsRebuilt=/);
    expect(readFileSync(storePath, "utf8")).toBe(marker);
  });

  it("G. CLI compact refuses and does not mutate the journal file", () => {
    const dir = mkdtempSync(join(tmpdir(), "cw-r5b-r2-g-"));
    const storePath = join(dir, "journal.sqlite");
    const marker = "JOURNAL_BYTES_MUST_NOT_BE_COMPACTED\n";
    writeFileSync(storePath, marker, "utf8");
    const beforeHash = createHash("sha256").update(readFileSync(storePath)).digest("hex");
    const result = runChild(
      mixedEnv,
      `
        const report = {
          scenario: "G",
          initialEnv: { COGNIWEAVE_RUNTIME_MODE: "production", VITEST: "true" },
          importOrder: ["cli"],
          mutationTiming: "none",
          firstTrustApiTiming: "runCogniWeaveCli compact against a preexisting store file",
          expected: "exit 1; journal file unchanged",
        };
        const fs = await import("node:fs");
        const crypto = await import("node:crypto");
        const storePath = ${JSON.stringify(storePath)};
        const before = crypto.createHash("sha256").update(fs.readFileSync(storePath)).digest("hex");
        const { runCogniWeaveCli } = await import(${cliPath});
        const io = { errors: [], logs: [] };
        const exitCode = await runCogniWeaveCli(
          ["compact", "--metadata-backend", "local", "--metadata-store-path", storePath, "--graph-backend", "memory", "--vector-backend", "memory"],
          {
            log: (message) => io.logs.push(String(message)),
            error: (message) => io.errors.push(String(message)),
          },
        );
        const after = crypto.createHash("sha256").update(fs.readFileSync(storePath)).digest("hex");
        console.log(JSON.stringify({
          ...report,
          exitCode,
          errors: io.errors,
          logs: io.logs,
          before,
          after,
          unchanged: before === after,
        }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("G");
    expect(payload.exitCode).toBe(1);
    expect(payload.unchanged).toBe(true);
    expect(payload.after).toBe(beforeHash);
    expect((payload.errors as string[]).join("\n")).toMatch(/runtime configuration conflict/i);
    expect((payload.logs as string[]).join("\n")).not.toMatch(/deleted=/);
    expect(readFileSync(storePath, "utf8")).toBe(marker);
  });

  it("H. public subpaths and other factories cannot bypass the unified mixed-configuration check", () => {
    const storePath = join(mkdtempSync(join(tmpdir(), "cw-r5b-r2-h-")), "bypass.sqlite");
    const result = runChild(
      mixedEnv,
      `
        const report = {
          scenario: "H",
          initialEnv: { COGNIWEAVE_RUNTIME_MODE: "production", VITEST: "true" },
          importOrder: ["openLocalMetadataStoreReadonly", "migrateLocalCanonicalToPostgres", "PgVectorStore", "Neo4jGraphStore", "InMemoryMetadataStore", "bootstrapAdapterBundle"],
          mutationTiming: "none",
          firstTrustApiTiming: "direct public subpath factory and constructor calls",
          expected: "every entry refuses with mixed_test_and_production_configuration; no sqlite file; no client side effects",
        };
        const fs = await import("node:fs");
        const storePath = ${JSON.stringify(storePath)};
        const sideEffects = [];
        const attempts = {};
        const record = async (name, fn) => {
          try {
            const value = await fn();
            attempts[name] = { ok: true, reason: null, valueType: value && typeof value };
          } catch (error) {
            attempts[name] = { ok: false, reason: error?.reason ?? error?.name ?? "error" };
          }
        };
        const local = await import(${sqliteStorePath});
        const migration = await import(${migrationPath});
        const pgvector = await import(${pgvectorPath});
        const neo4j = await import(${neo4jPath});
        const memory = await import(${inMemoryPath});
        const cli = await import(${cliPath});
        const factory = await import(${factoryPath});
        await record("openLocalMetadataStoreReadonly", () => local.openLocalMetadataStoreReadonly({
          backend: "local",
          environment: "local",
          path: storePath,
        }));
        await record("migrateLocalCanonicalToPostgres", () => migration.migrateLocalCanonicalToPostgres({
          sourceStorePath: storePath,
          client: { query: async () => { sideEffects.push("migrate-query"); return { rows: [], rowCount: 0 }; } },
        }));
        await record("PgVectorStore", () => new pgvector.PgVectorStore({
          backend: "pgvector",
          environment: "service",
          client: { query: async () => { sideEffects.push("pgvector-query"); return { rows: [], rowCount: 0 }; } },
        }));
        await record("Neo4jGraphStore", () => new neo4j.Neo4jGraphStore({
          backend: "neo4j",
          environment: "service",
          client: { run: async () => { sideEffects.push("neo4j-run"); return { records: [] }; } },
        }));
        await record("InMemoryMetadataStore", () => new memory.InMemoryMetadataStore());
        await record("InMemoryGraphStore", () => new memory.InMemoryGraphStore());
        await record("InMemoryVectorStore", () => new memory.InMemoryVectorStore());
        await record("bootstrapAdapterBundle", () => cli.bootstrapAdapterBundle({
          metadataStore: {},
          graphStore: {},
          vectorStore: {},
          resolutions: [],
        }));
        await record("createOfficialProductionAdapterBundle", () => factory.createOfficialProductionAdapterBundle(${memoryConfig}));
        console.log(JSON.stringify({
          ...report,
          attempts,
          sideEffects,
          fileExistsAfter: fs.existsSync(storePath),
        }));
      `,
    );
    const payload = lastJson(result);
    expect(payload.scenario).toBe("H");
    expect(payload.fileExistsAfter).toBe(false);
    expect(payload.sideEffects).toEqual([]);
    const attempts = payload.attempts as Record<string, { ok: boolean; reason: string }>;
    for (const name of [
      "openLocalMetadataStoreReadonly",
      "migrateLocalCanonicalToPostgres",
      "PgVectorStore",
      "Neo4jGraphStore",
      "InMemoryMetadataStore",
      "InMemoryGraphStore",
      "InMemoryVectorStore",
      "bootstrapAdapterBundle",
      "createOfficialProductionAdapterBundle",
    ]) {
      expect(attempts[name], name).toMatchObject({
        ok: false,
        reason: "mixed_test_and_production_configuration",
      });
    }
    expect(existsSync(storePath)).toBe(false);
  });
});
