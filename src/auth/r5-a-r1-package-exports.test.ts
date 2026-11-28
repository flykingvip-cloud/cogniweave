import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const typescriptBin = join(packageRoot, "node_modules", "typescript", "bin", "tsc");

const FORBIDDEN_SPECIFIERS = [
  "@cogniweave/sdk/journal/repair",
  "@cogniweave/sdk/journal/repair.js",
  "@cogniweave/sdk/runtime/in-memory-engine",
  "@cogniweave/sdk/runtime/canonical-resolver-registry",
  "@cogniweave/sdk/auth/trusted-runtime",
  "@cogniweave/sdk/src/journal/repair",
  "@cogniweave/sdk/dist/journal/repair",
];

const ALLOWED_SPECIFIERS = ["@cogniweave/sdk", "@cogniweave/sdk/models", "@cogniweave/sdk/contracts"];

const PUBLISHED_DIST_FILES = [
  "dist/cli.js",
  "dist/contracts.d.ts",
  "dist/contracts.js",
  "dist/index.d.ts",
  "dist/index.js",
  "dist/models.d.ts",
  "dist/models.js",
];

const FORBIDDEN_FS_RELATIVE_PATHS = [
  "dist/journal/repair.js",
  "dist/journal/repair.ts",
  "dist/journal/repair.mjs",
  "dist/journal/repair.cjs",
  "dist/journal/repair.d.ts",
  "src/journal/repair.ts",
  "src/journal/repair.js",
  "journal/repair.js",
  "journal/repair.ts",
  "dist/runtime/canonical-resolver-registry.js",
  "dist/runtime/canonical-resolver-registry.ts",
  "dist/runtime/canonical-resolver-registry.mjs",
  "dist/runtime/canonical-resolver-registry.cjs",
  "dist/runtime/canonical-resolver-registry.d.ts",
  "src/runtime/canonical-resolver-registry.ts",
  "src/runtime/canonical-resolver-registry.js",
  "runtime/canonical-resolver-registry.js",
];

const FORBIDDEN_PACKED_PATH_PATTERNS = [
  /(^|\/)src\//,
  /journal\/repair/,
  /canonical-resolver-registry/,
  /dist\/journal\//,
  /dist\/runtime\//,
];

type CommandResult = {
  status: number | null;
  stdout: string;
  stderr: string;
};

function run(command: string, args: string[], cwd: string, env?: NodeJS.ProcessEnv): CommandResult {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    env: env ?? process.env,
  });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function runNode(code: string, cwd: string): CommandResult {
  return run("node", ["--input-type=module", "-e", code], cwd);
}

function resolveExportError(result: CommandResult): boolean {
  const text = `${result.stdout}\n${result.stderr}`;
  return (
    result.status !== 0 &&
    (text.includes("ERR_PACKAGE_PATH_NOT_EXPORTED") || text.includes("Package path") || text.includes("not exported"))
  );
}

function resolveMissingModuleError(result: CommandResult): boolean {
  const text = `${result.stdout}\n${result.stderr}`;
  return (
    result.status !== 0 &&
    (text.includes("ERR_MODULE_NOT_FOUND") ||
      text.includes("Cannot find module") ||
      text.includes("MODULE_NOT_FOUND") ||
      text.includes("ENOENT"))
  );
}

function publishedLayoutIsBundled(): boolean {
  const index = join(packageRoot, "dist", "index.js");
  if (!existsSync(index)) {
    return false;
  }
  if (existsSync(join(packageRoot, "dist", "journal", "repair.js"))) {
    return false;
  }
  if (existsSync(join(packageRoot, "dist", "runtime", "canonical-resolver-registry.js"))) {
    return false;
  }
  const source = readFileSync(index, "utf8");
  return !source.includes("./journal/repair") && !source.includes("./canonical-resolver-registry");
}

function listFilesRecursive(root: string): string[] {
  const results: string[] = [];
  const walk = (current: string): void => {
    for (const entry of readdirSync(current)) {
      const full = join(current, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else {
        results.push(full);
      }
    }
  };
  walk(root);
  return results;
}

describe("CW-09-02-R5-A-R1 built package export surface", () => {
  let tempRoot = "";
  let installDir = "";
  let installedPkgRoot = "";
  let exportMap: Record<string, unknown> = {};
  let tarballName = "";
  let packedFiles: string[] = [];

  beforeAll(() => {
    execFileSync("pnpm", ["build"], {
      cwd: packageRoot,
      stdio: "pipe",
    });
    if (!publishedLayoutIsBundled()) {
      throw new Error("pnpm build did not produce the bundled public SDK layout");
    }
    tempRoot = mkdtempSync(join(tmpdir(), "cogniweave-r5-a-r1-"));
    const packDir = join(tempRoot, "pack");
    installDir = join(tempRoot, "install");
    const npmCacheDir = join(tempRoot, "npm-cache");
    mkdirSync(packDir, { recursive: true });
    mkdirSync(installDir, { recursive: true });
    mkdirSync(npmCacheDir, { recursive: true });
    const env = { ...process.env, npm_config_cache: npmCacheDir };

    const pack = run("npm", ["pack", "--ignore-scripts", "--pack-destination", packDir], packageRoot, env);
    if (pack.status !== 0) {
      throw new Error(`npm pack failed:\n${pack.stdout}\n${pack.stderr}`);
    }
    tarballName =
      pack.stdout
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
        .at(-1) ?? "";
    if (!tarballName) {
      throw new Error(`npm pack did not report a tarball:\n${pack.stdout}\n${pack.stderr}`);
    }
    const tarballPath = join(packDir, tarballName);
    const listed = run("tar", ["-tzf", tarballPath], packDir);
    if (listed.status !== 0) {
      throw new Error(`tar -tzf failed:\n${listed.stdout}\n${listed.stderr}`);
    }
    packedFiles = listed.stdout
      .split("\n")
      .map((line) => line.trim().replace(/^package\//, ""))
      .filter(Boolean)
      .sort();
    const init = run("npm", ["init", "-y"], installDir, env);
    if (init.status !== 0) {
      throw new Error(`npm init failed:\n${init.stdout}\n${init.stderr}`);
    }
    const install = run("npm", ["install", tarballPath], installDir, env);
    if (install.status !== 0) {
      throw new Error(`npm install failed:\n${install.stdout}\n${install.stderr}`);
    }
    installedPkgRoot = join(installDir, "node_modules", "@cogniweave", "sdk");
    const installedPkg = JSON.parse(readFileSync(join(installedPkgRoot, "package.json"), "utf8")) as {
      exports?: Record<string, unknown>;
    };
    exportMap = installedPkg.exports ?? {};
  }, 180_000);

  afterAll(() => {
    if (tempRoot) {
      rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it("publishes an explicit export allowlist without a wildcard subpath", () => {
    expect(tarballName).toMatch(/cogniweave-sdk-0\.1\.0\.tgz/);
    expect(Object.keys(exportMap).sort()).toEqual([".", "./cli-entry", "./contracts", "./models"]);
    expect(exportMap).not.toHaveProperty("./*");
    expect(JSON.stringify(exportMap)).not.toContain("*");
  });

  it("omits src and standalone internal mutation or resolver modules from the packed layout", () => {
    const distFiles = packedFiles.filter((file) => file.startsWith("dist/")).sort();
    expect(distFiles).toEqual(PUBLISHED_DIST_FILES);
    for (const file of packedFiles) {
      for (const pattern of FORBIDDEN_PACKED_PATH_PATTERNS) {
        expect(file, `packed path ${file}`).not.toMatch(pattern);
      }
    }
    const installedFiles = listFilesRecursive(installedPkgRoot).map((file) =>
      relative(installedPkgRoot, file).replaceAll("\\", "/"),
    );
    for (const file of installedFiles) {
      for (const pattern of FORBIDDEN_PACKED_PATH_PATTERNS) {
        expect(file, `installed path ${file}`).not.toMatch(pattern);
      }
    }
    for (const relativePath of FORBIDDEN_FS_RELATIVE_PATHS) {
      expect(existsSync(join(installedPkgRoot, relativePath)), relativePath).toBe(false);
    }
  });

  it("resolves root and documented subpath imports from the packed package", () => {
    const result = runNode(
      `
        const sdk = await import("@cogniweave/sdk");
        const models = await import("@cogniweave/sdk/models");
        const contracts = await import("@cogniweave/sdk/contracts");
        if (typeof sdk.InMemoryCogniWeaveEngine !== "function") {
          throw new Error("missing InMemoryCogniWeaveEngine");
        }
        if (typeof sdk.createCogniWeaveRuntime !== "function") {
          throw new Error("missing createCogniWeaveRuntime");
        }
        if ("rebuildFromTruth" in sdk || "repairDerivedIndexes" in sdk) {
          throw new Error("repair helpers leaked on the package root");
        }
        if (
          "getEngineCanonicalAuthorizationResolver" in sdk ||
          "registerEngineCanonicalAuthorizationResolver" in sdk
        ) {
          throw new Error("resolver hooks leaked on the package root");
        }
        if (
          "resolveTrustedRuntimeAssembly" in sdk ||
          "bindEngineTrustedRuntime" in sdk ||
          "resolveEngineTrustedRuntime" in sdk ||
          "SealedTrustedRuntimeAssembly" in sdk
        ) {
          throw new Error("trusted runtime unpack helpers leaked on the package root");
        }
        if (typeof models !== "object" || models === null) {
          throw new Error("models subpath import failed");
        }
        if (typeof contracts !== "object" || contracts === null) {
          throw new Error("contracts subpath import failed");
        }
        console.log(JSON.stringify({
          ok: true,
          rootExportsSample: ["InMemoryCogniWeaveEngine", "createCogniWeaveRuntime"].filter((name) => name in sdk),
        }));
      `,
      installDir,
    );
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout.trim())).toMatchObject({ ok: true });
    for (const specifier of ALLOWED_SPECIFIERS) {
      const probe = runNode(`await import(${JSON.stringify(specifier)}); console.log("ok");`, installDir);
      expect(probe.status, specifier).toBe(0);
    }
  });

  it("rejects forbidden deep imports of repair helpers, resolver hooks, and other internals", () => {
    const failures: Record<string, string> = {};
    for (const specifier of FORBIDDEN_SPECIFIERS) {
      const result = runNode(`await import(${JSON.stringify(specifier)});`, installDir);
      expect(resolveExportError(result), `${specifier} stdout=${result.stdout} stderr=${result.stderr}`).toBe(
        true,
      );
      failures[specifier] = `${result.stderr}\n${result.stdout}`;
    }
    expect(Object.keys(failures)).toEqual(FORBIDDEN_SPECIFIERS);
  });

  it("fails TypeScript resolution for forbidden deep imports against the packed types", () => {
    // Resolve through the packed install's node_modules so tsc sees the published export map.
    writeFileSync(
      join(installDir, "tsconfig.forbidden.json"),
      JSON.stringify({
        compilerOptions: {
          module: "NodeNext",
          moduleResolution: "NodeNext",
          noEmit: true,
          strict: true,
          skipLibCheck: true,
          types: [],
        },
        files: ["forbidden.ts"],
      }),
    );
    writeFileSync(
      join(installDir, "forbidden.ts"),
      [
        'import { rebuildFromTruth } from "@cogniweave/sdk/journal/repair";',
        'import { registerEngineCanonicalAuthorizationResolver } from "@cogniweave/sdk/runtime/canonical-resolver-registry";',
        'import { resolveTrustedRuntimeAssembly, bindEngineTrustedRuntime, resolveEngineTrustedRuntime } from "@cogniweave/sdk";',
        "export const leaked = [rebuildFromTruth, registerEngineCanonicalAuthorizationResolver, resolveTrustedRuntimeAssembly, bindEngineTrustedRuntime, resolveEngineTrustedRuntime];",
        "",
      ].join("\n"),
    );
    writeFileSync(
      join(installDir, "tsconfig.allowed.json"),
      JSON.stringify({
        compilerOptions: {
          module: "NodeNext",
          moduleResolution: "NodeNext",
          noEmit: true,
          strict: true,
          skipLibCheck: true,
          types: [],
        },
        files: ["allowed.ts"],
      }),
    );
    writeFileSync(
      join(installDir, "allowed.ts"),
      [
        'import { InMemoryCogniWeaveEngine } from "@cogniweave/sdk";',
        'import type { Scope } from "@cogniweave/sdk/models";',
        'import type { CogniWeaveEngine } from "@cogniweave/sdk/contracts";',
        "export const Engine: typeof InMemoryCogniWeaveEngine = InMemoryCogniWeaveEngine;",
        "export type S = Scope;",
        "export type E = CogniWeaveEngine;",
        "",
      ].join("\n"),
    );

    const forbidden = run(typescriptBin, ["-p", "tsconfig.forbidden.json"], installDir);
    expect(forbidden.status).not.toBe(0);
    expect(`${forbidden.stdout}\n${forbidden.stderr}`).toMatch(
      /journal\/repair|not exported|Cannot find module|has no exported member/i,
    );

    const allowed = run(typescriptBin, ["-p", "tsconfig.allowed.json"], installDir);
    expect(allowed.stderr + allowed.stdout, `allowed types failed:\n${allowed.stdout}\n${allowed.stderr}`).toBe("");
    expect(allowed.status).toBe(0);
  });

  it("cannot load repair helpers or the resolver registry by filesystem path from the packed install", () => {
    const failures: Record<string, string> = {};
    for (const relativePath of FORBIDDEN_FS_RELATIVE_PATHS) {
      const absolute = join(installedPkgRoot, relativePath);
      expect(existsSync(absolute), relativePath).toBe(false);
      const href = pathToFileURL(absolute).href;
      const esm = runNode(`await import(${JSON.stringify(href)});`, installDir);
      expect(
        resolveMissingModuleError(esm),
        `esm ${relativePath} stdout=${esm.stdout} stderr=${esm.stderr}`,
      ).toBe(true);
      const cjs = run(
        "node",
        [
          "--input-type=module",
          "-e",
          `
            import { createRequire } from "node:module";
            const require = createRequire(import.meta.url);
            require(${JSON.stringify(absolute)});
          `,
        ],
        installDir,
      );
      expect(
        resolveMissingModuleError(cjs),
        `cjs ${relativePath} stdout=${cjs.stdout} stderr=${cjs.stderr}`,
      ).toBe(true);
      failures[relativePath] = `${esm.stderr}\n${cjs.stderr}`;
    }
    expect(Object.keys(failures)).toEqual(FORBIDDEN_FS_RELATIVE_PATHS);
  });

  it("cannot retrieve or invoke the Canonical resolver from the packed public surface or filesystem", () => {
    const result = runNode(
      `
        import { existsSync } from "node:fs";
        import { createRequire } from "node:module";
        import { join } from "node:path";
        import { pathToFileURL } from "node:url";

        const pkgRoot = ${JSON.stringify(installedPkgRoot)};
        const sdk = await import("@cogniweave/sdk");
        const engine = new sdk.InMemoryCogniWeaveEngine({
          environment: "local",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        });
        if (typeof engine.registerEngineCanonicalAuthorizationResolver === "function") {
          throw new Error("resolver registration leaked on the Engine instance");
        }
        if (typeof engine.getEngineCanonicalAuthorizationResolver === "function") {
          throw new Error("resolver lookup leaked on the Engine instance");
        }
        if (typeof engine.canonicalResolver === "function" || typeof engine.canonicalLookup === "function") {
          throw new Error("resolver or lookup method leaked on the Engine instance");
        }
        const proto = Object.getPrototypeOf(engine);
        const names = Object.getOwnPropertyNames(engine).concat(Object.getOwnPropertyNames(proto));
        if (names.includes("registerEngineCanonicalAuthorizationResolver") || names.includes("getEngineCanonicalAuthorizationResolver")) {
          throw new Error("resolver hook names visible on the Engine instance");
        }
        if (names.includes("canonicalResolver") || names.includes("canonicalLookup")) {
          throw new Error("resolver or lookup names visible on the Engine instance");
        }
        if ("getEngineCanonicalAuthorizationResolver" in sdk || "registerEngineCanonicalAuthorizationResolver" in sdk) {
          throw new Error("resolver hooks leaked on the package root");
        }

        const registryPath = join(pkgRoot, "dist/runtime/canonical-resolver-registry.js");
        if (existsSync(registryPath)) {
          throw new Error("resolver registry file is present in the installed package");
        }
        let registryLoaded = false;
        try {
          await import(pathToFileURL(registryPath).href);
          registryLoaded = true;
        } catch {}
        if (registryLoaded) {
          throw new Error("resolver registry was imported from a filesystem path");
        }
        const require = createRequire(import.meta.url);
        let required = false;
        try {
          require(registryPath);
          required = true;
        } catch {}
        if (required) {
          throw new Error("resolver registry was required from a filesystem path");
        }
        console.log(JSON.stringify({ ok: true }));
      `,
      installDir,
    );
    expect(result.status, result.stdout + result.stderr).toBe(0);
    expect(JSON.parse(result.stdout.trim())).toEqual({ ok: true });
  });

  it("keeps the published CLI entry working from the packed package", () => {
    const bin = join(installDir, "node_modules", ".bin", "cogniweave");
    const result = run(bin, ["--version", "--json"], installDir);
    expect(result.status, result.stdout + result.stderr).toBe(0);
    expect(result.stdout).toMatch(/0\.1\.0/);
  });

  it("filters packed listLiveSourcesForAtom results and preserves authorized repair plus fail-closed production behavior", () => {
    const result = runNode(
      `
        const sdk = await import("@cogniweave/sdk");
        const NOW = "2026-11-28T00:00:00.000Z";
        const scope = { workspaceId: "ws_1", projectId: "proj_1", agentId: "agent_main", visibility: "private" };
        const foreign = { workspaceId: "ws_other", projectId: "proj_1", agentId: "agent_main", visibility: "private" };
        const store = new sdk.InMemoryMetadataStore();
        const evidence = {
          id: "ev_shared",
          type: "document",
          uri: "msrc://shared_src",
          snippet: "shared",
          trustScore: 0.9,
          scope,
          locator: { messageIds: [], toolCallIds: [] },
        };
        const atom = {
          id: "atm_owned",
          atomType: "strategy",
          scope,
          claim: { type: "procedural", statement: "owned" },
          trigger: { conditions: [], contextTags: [] },
          applicability: { include: [], exclude: [] },
          provenance: { sourceEventIds: [], evidenceRefs: [evidence.id] },
          versioning: { version: 1 },
          state: { status: "active", conflictsWith: [] },
          metrics: { confidence: 0.8, reuseCount: 0 },
          dedupKey: "atm_owned",
        };
        await store.saveEvidence(evidence);
        await store.saveAtom(atom);
        await store.saveSourceBinding({
          id: "sb_same_backfill",
          sourceIdentityId: "shared_src",
          sourceLocator: "msrc://shared_src",
          status: "active",
          scope,
          createdAt: NOW,
          updatedAt: NOW,
        });
        await store.saveSourceBinding({
          id: "sb_foreign_backfill",
          sourceIdentityId: "shared_src",
          sourceLocator: "msrc://shared_src#foreign",
          status: "active",
          scope: foreign,
          createdAt: NOW,
          updatedAt: NOW,
        });
        await store.putJournal({
          id: "jnl_repair",
          eventKey: "evt_jnl_repair",
          scope,
          objectIds: { eventIds: [], atomIds: [atom.id], entityIds: [], scenarioIds: [], problemIds: [], evidenceIds: [], relationIds: [] },
          derivedPlan: { graphNodeIds: [], graphEdgeIds: [], vectorDocIds: [] },
          status: "COMPLETED",
          phase: "COMPLETED",
          retryCount: 0,
          updatedAt: NOW,
        });
        const local = new sdk.InMemoryCogniWeaveEngine({
          environment: "local",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }, { metadataStore: store });
        const sources = await local.listLiveSourcesForAtom("atm_owned");
        const sourceDump = JSON.stringify(sources);
        if (sources.some((row) => row.sourceBindingId === "sb_foreign_backfill")) {
          throw new Error("foreign binding disclosed");
        }
        if (sourceDump.includes("sb_foreign_backfill") || sourceDump.includes("ws_other") || sourceDump.includes("msrc://shared_src#foreign")) {
          throw new Error("foreign binding fields disclosed");
        }
        if (!sources.some((row) => row.sourceBindingId === "sb_same_backfill")) {
          throw new Error("same-scope backfill missing");
        }
        const rebuilt = await local.rebuildFromTruth({ objectType: "atom", objectId: "atm_owned", scope });
        if (rebuilt.status !== "REBUILT") {
          throw new Error("authorized rebuildFromTruth failed: " + JSON.stringify(rebuilt));
        }
        const repaired = await local.repairIndexes({ scope, journalId: "jnl_repair" });
        if (repaired.status !== "SYNCED") {
          throw new Error("authorized repairIndexes failed: " + JSON.stringify(repaired));
        }
        const runtime = sdk.createTrustedRuntime({ environment: "service" });
        const service = new sdk.InMemoryCogniWeaveEngine({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }, { runtime });
        let denied = false;
        try {
          await service.listLiveSourcesForAtom("atm_owned");
        } catch (error) {
          denied = error instanceof sdk.PrincipalUnavailableError;
        }
        if (!denied) {
          throw new Error("service listLiveSourcesForAtom did not fail closed");
        }
        denied = false;
        try {
          await service.rebuildFromTruth({ objectType: "atom", objectId: "atm_owned", scope });
        } catch (error) {
          denied = error instanceof sdk.PrincipalUnavailableError;
        }
        if (!denied) {
          throw new Error("service rebuildFromTruth did not fail closed");
        }
        console.log(JSON.stringify({
          ok: true,
          sourceIds: sources.map((row) => row.sourceBindingId),
          rebuilt: rebuilt.status,
          repaired: repaired.status,
        }));
      `,
      installDir,
    );
    expect(result.status, result.stdout + result.stderr).toBe(0);
    const payload = JSON.parse(result.stdout.trim()) as {
      ok: boolean;
      sourceIds: string[];
      rebuilt: string;
      repaired: string;
    };
    expect(payload).toMatchObject({ ok: true, rebuilt: "REBUILT", repaired: "SYNCED" });
    expect(payload.sourceIds).toEqual(["sb_same_backfill"]);
  });

  it("does not leak Engine stores or unguarded internals to a packed JavaScript consumer", () => {
    const result = runNode(
      `
        const sdk = await import("@cogniweave/sdk");
        const NOW = "2026-11-28T00:00:00.000Z";
        const scope = { workspaceId: "ws_1", projectId: "proj_1", agentId: "agent_main", visibility: "private" };
        const foreign = { workspaceId: "ws_other", projectId: "proj_1", agentId: "agent_main", visibility: "private" };
        const store = new sdk.InMemoryMetadataStore();
        const evidence = {
          id: "ev_shared",
          type: "document",
          uri: "msrc://shared_src",
          snippet: "shared",
          trustScore: 0.9,
          scope,
          locator: { messageIds: [], toolCallIds: [] },
        };
        const atom = {
          id: "atm_probe",
          atomType: "strategy",
          scope,
          claim: { type: "procedural", statement: "original-claim" },
          trigger: { conditions: [], contextTags: [] },
          applicability: { include: [], exclude: [] },
          provenance: { sourceEventIds: [], evidenceRefs: [evidence.id] },
          versioning: { version: 1 },
          state: { status: "active", conflictsWith: [] },
          metrics: { confidence: 0.8, reuseCount: 0 },
          dedupKey: "atm_probe",
        };
        await store.saveEvidence(evidence);
        await store.saveAtom(atom);
        await store.saveSourceBinding({
          id: "sb_same_backfill",
          sourceIdentityId: "shared_src",
          sourceLocator: "msrc://shared_src",
          status: "active",
          scope,
          createdAt: NOW,
          updatedAt: NOW,
        });
        await store.saveSourceBinding({
          id: "sb_foreign_backfill",
          sourceIdentityId: "shared_src",
          sourceLocator: "msrc://shared_src#foreign",
          status: "active",
          scope: foreign,
          createdAt: NOW,
          updatedAt: NOW,
        });

        const engine = new sdk.InMemoryCogniWeaveEngine({
          environment: "local",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }, { metadataStore: store });

        const STORE_KEYS = [
          "metadataStore",
          "graphStore",
          "vectorStore",
          "_metadataStore",
          "_graphStore",
          "_vectorStore",
          "stores",
          "#metadataStore",
          "#graphStore",
          "#vectorStore",
        ];
        const METHOD_NAMES = [
          "initializeTrustedRuntime",
          "assertEngineAuthorized",
          "ensureSourceLifecycleHydrated",
          "hydrateSourceLifecycleFromStore",
          "persistSourceBinding",
          "persistSourceObjectLink",
          "makeSourceObjectLinkId",
          "liveSourceObjectLinks",
          "ensureEvidenceLinksForBinding",
          "ensureAtomLinksForBinding",
          "evidenceRefsBelongToBinding",
          "ensureDerivedObjectLink",
          "backfillSiblingDerivedLinks",
          "ensureEventLinksForBinding",
          "ensureRelationLinksForBinding",
          "ensureProvenanceObjectLinksForBinding",
          "recomputeProvenanceObjectAfterSourceChange",
          "recomputeRelationAfterSourceChange",
          "objectStillSupportedByLiveEvidence",
          "purgeOrphanObjectsForBinding",
          "removeObjectLinkRows",
          "recomputeAtomAfterSourceChange",
          "persistSourceLifecycleReceipt",
          "loadSourceLifecycleReceipt",
          "runMetadataTransaction",
          "resolveWriteOperationKey",
          "persistWriteOperation",
          "authorizeQueryAccess",
          "resolveJournalCanonicalScope",
          "journalsMatchingResolvedScope",
          "isAuthorizedLiveSourceBinding",
          "evidenceMatchesBinding",
          "findSourceBinding",
          "ensureSourceBinding",
          "applySourceLifecycle",
          "canonicalResolver",
          "canonicalLookup",
          "resolveCanonicalResourceScopeForAuthorization",
          "isEvidenceRetrievable",
        ];

        function collectKeys(value) {
          const names = [];
          const seen = new Set();
          let current = value;
          while (current && current !== Object.prototype && !seen.has(current)) {
            seen.add(current);
            for (const key of Reflect.ownKeys(current)) {
              names.push(typeof key === "symbol" ? String(key) : String(key));
            }
            current = Object.getPrototypeOf(current);
          }
          return names;
        }

        const visible = collectKeys(engine);
        const leakedNames = [...STORE_KEYS, ...METHOD_NAMES].filter((name) => visible.includes(name));
        if (leakedNames.length > 0) {
          throw new Error("internal names visible on instance or prototype: " + leakedNames.join(","));
        }

        const usableStores = [];
        const storeMutations = [];
        const access = {
          dotMetadataStore: engine.metadataStore,
          bracketMetadataStore: engine["metadataStore"],
          bracketGraphStore: engine["graphStore"],
          bracketVectorStore: engine["vectorStore"],
        };
        for (const key of STORE_KEYS) {
          if (key in engine) {
            throw new Error(key + " is visible via the in operator");
          }
          const value = engine[key];
          const looksLikeStore = Boolean(
            value &&
              typeof value === "object" &&
              (typeof value.saveAtom === "function" ||
                typeof value.deleteAtom === "function" ||
                typeof value.saveEntity === "function" ||
                typeof value.deleteEntity === "function"),
          );
          if (looksLikeStore) {
            usableStores.push(key);
            try { await value.deleteAtom?.("atm_probe"); } catch {}
            try { await value.saveAtom?.({ ...atom, id: "atm_injected", claim: { type: "procedural", statement: "injected" }, dedupKey: "atm_injected" }); } catch {}
            try { await value.deleteEntity?.("ent_x"); } catch {}
            try { await value.saveEntity?.({ id: "ent_injected" }); } catch {}
            const after = await store.getAtom("atm_probe");
            const injected = await store.getAtom("atm_injected");
            if (!after || after.claim.statement !== "original-claim" || injected) {
              storeMutations.push(key);
            }
          }
        }
        if (usableStores.length > 0 || storeMutations.length > 0) {
          throw new Error(
            "usable store leaked or mutated Canonical data via " +
              [...new Set([...usableStores, ...storeMutations])].join(","),
          );
        }
        if (Object.values(access).some((value) => value != null)) {
          throw new Error("store fields were reachable as ordinary properties");
        }

        const callable = [];
        const methodMutations = [];
        const forgedBinding = {
          id: "sb_injected",
          sourceIdentityId: "sid_injected",
          sourceLocator: "msrc://injected",
          status: "active",
          scope,
          createdAt: NOW,
          updatedAt: NOW,
        };
        const proto = Object.getPrototypeOf(engine);
        const ctorProto = sdk.InMemoryCogniWeaveEngine.prototype;
        for (const name of METHOD_NAMES) {
          const targets = [engine[name], proto?.[name], ctorProto?.[name]];
          for (const fn of targets) {
            if (typeof fn === "function") {
              callable.push(name);
              try { await fn.call(engine, forgedBinding, "atom", "atm_probe", "purge"); } catch {}
              try { fn.call(engine, forgedBinding, "atom", "atm_probe"); } catch {}
            }
          }
        }
        const listedBindings = typeof store.listSourceBindings === "function" ? await store.listSourceBindings() : [];
        if (listedBindings.some((row) => row.id === "sb_injected")) {
          methodMutations.push("sb_injected");
        }
        const afterMethods = await store.getAtom("atm_probe");
        if (!afterMethods || afterMethods.claim.statement !== "original-claim") {
          methodMutations.push("atm_probe");
        }
        if (callable.length > 0) {
          throw new Error("ungated internals were callable: " + [...new Set(callable)].join(","));
        }
        if (methodMutations.length > 0) {
          throw new Error("direct internal invocation mutated Canonical data");
        }

        const history = await engine.getVersionHistory("atm_probe");
        if (!history.some((row) => row.id === "atm_probe" && row.claim.statement === "original-claim")) {
          throw new Error("authorized getVersionHistory failed");
        }
        const sources = await engine.listLiveSourcesForAtom("atm_probe");
        const sourceDump = JSON.stringify(sources);
        if (sources.some((row) => row.sourceBindingId === "sb_foreign_backfill")) {
          throw new Error("foreign binding disclosed");
        }
        if (sourceDump.includes("sb_foreign_backfill") || sourceDump.includes("ws_other") || sourceDump.includes("msrc://shared_src#foreign")) {
          throw new Error("foreign binding fields disclosed");
        }
        if (!sources.some((row) => row.sourceBindingId === "sb_same_backfill")) {
          throw new Error("same-scope backfill missing");
        }
        const archived = await engine.archiveSource({
          operationId: "op-archive-probe",
          selector: { mode: "identity", sourceIdentityId: "sid_archive_probe" },
          subject: { scope },
          reasonCode: "TEST_ARCHIVE",
        });
        if (archived.currentStatus !== "archived" || archived.sourceIdentityId !== "sid_archive_probe") {
          throw new Error("authorized archiveSource failed: " + JSON.stringify(archived));
        }
        const bindings = await store.listSourceBindings();
        const archivedBinding = bindings.find((row) => row.sourceIdentityId === "sid_archive_probe");
        if (!archivedBinding || archivedBinding.status !== "archived") {
          throw new Error("authorized archiveSource did not persist binding status");
        }
        const sameBinding = bindings.find((row) => row.id === "sb_same_backfill");
        if (!sameBinding || sameBinding.status !== "active") {
          throw new Error("authorized archive mutated the listLiveSourcesForAtom fixture binding");
        }
        const foreignBinding = bindings.find((row) => row.id === "sb_foreign_backfill");
        if (!foreignBinding || foreignBinding.status !== "active") {
          throw new Error("authorized archive mutated a foreign binding");
        }

        const runtime = sdk.createTrustedRuntime({ environment: "service" });
        const service = new sdk.InMemoryCogniWeaveEngine({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }, { runtime });
        let denied = false;
        try {
          await service.listLiveSourcesForAtom("atm_probe");
        } catch (error) {
          denied = error instanceof sdk.PrincipalUnavailableError;
        }
        if (!denied) {
          throw new Error("service listLiveSourcesForAtom did not fail closed");
        }
        denied = false;
        try {
          await service.archiveSource({
            operationId: "op-archive-service",
            selector: { mode: "identity", sourceIdentityId: "shared_src" },
            subject: { scope },
            reasonCode: "TEST_ARCHIVE",
          });
        } catch (error) {
          denied = error instanceof sdk.PrincipalUnavailableError;
        }
        if (!denied) {
          throw new Error("service archiveSource did not fail closed");
        }

        console.log(JSON.stringify({
          ok: true,
          visibleInternalNames: leakedNames,
          usableStores,
          callableInternals: callable,
          sourceIds: sources.map((row) => row.sourceBindingId),
          archived: archived.currentStatus,
        }));
      `,
      installDir,
    );
    expect(result.status, result.stdout + result.stderr).toBe(0);
    const payload = JSON.parse(result.stdout.trim()) as {
      ok: boolean;
      visibleInternalNames: string[];
      usableStores: string[];
      callableInternals: string[];
      sourceIds: string[];
      archived: string;
    };
    expect(payload).toMatchObject({
      ok: true,
      visibleInternalNames: [],
      usableStores: [],
      callableInternals: [],
      archived: "archived",
    });
    expect(payload.sourceIds).toEqual(["sb_same_backfill"]);
  });

  it("cannot unpack the Engine Trusted Runtime assembly from a packed JavaScript consumer", async () => {
    const result = runNode(
      `
        import { inspect } from "node:util";
        import { readFileSync } from "node:fs";
        import { join } from "node:path";

        const pkgRoot = ${JSON.stringify(installedPkgRoot)};
        const sdk = await import("@cogniweave/sdk");
        const typings = [
          readFileSync(join(pkgRoot, "dist/index.d.ts"), "utf8"),
          readFileSync(join(pkgRoot, "dist/contracts.d.ts"), "utf8"),
          readFileSync(join(pkgRoot, "dist/models.d.ts"), "utf8"),
        ].join("\\n");
        const leakedTypings = [
          "resolveTrustedRuntimeAssembly",
          "SealedTrustedRuntimeAssembly",
          "bindEngineTrustedRuntime",
          "resolveEngineTrustedRuntime",
          "getTrustedRuntime",
        ].filter((name) => typings.includes(name));
        if (leakedTypings.length > 0) {
          throw new Error("unpack helpers leaked in public typings: " + leakedTypings.join(","));
        }
        if (/(?:^|[^#\\w])trustedRuntime\\b/.test(typings)) {
          throw new Error("public typings still declare a trustedRuntime property");
        }

        const leakedExports = [
          "resolveTrustedRuntimeAssembly",
          "bindEngineTrustedRuntime",
          "resolveEngineTrustedRuntime",
          "SealedTrustedRuntimeAssembly",
          "getTrustedRuntime",
        ].filter((name) => name in sdk);
        if (leakedExports.length > 0) {
          throw new Error("unpack helpers leaked on the package root: " + leakedExports.join(","));
        }

        const NOW = "2026-11-28T00:00:00.000Z";
        const scope = { workspaceId: "ws_1", projectId: "proj_1", agentId: "agent_main", visibility: "private" };
        const subject = { tenantId: "t_1", ownerType: "user", ownerId: "u_1" };
        const principal = {
          tenantId: "t_1",
          userId: "u_1",
          allowedWorkspaceIds: ["ws_1"],
          subject,
        };
        const metadataStore = new sdk.InMemoryMetadataStore();
        const dataPlaneId = await metadataStore.ensureDataPlaneId();
        const binding = sdk.createMemorySubjectBinding({
          partition: sdk.createMemoryPartitionKeyV1(dataPlaneId, scope),
          scope,
          subject,
        });
        await metadataStore.saveMemorySubjectBinding(binding);
        const bindingQuery = sdk.createAuthoritativeBindingQueryFromMetadataStore(metadataStore);
        const principalProvider = sdk.createDenyByDefaultPrincipalProvider([
          { token: "valid_tok", principal },
        ]);
        const delegationStore = sdk.createMemoryDelegationAuthorizationStore([]);
        const runtime = sdk.createTrustedRuntime({
          environment: "service",
          principalProvider,
          bindingQuery,
          delegationStore,
          ensureDataPlaneId: () => metadataStore.ensureDataPlaneId(),
        });
        const engine = new sdk.InMemoryCogniWeaveEngine({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }, { metadataStore, runtime });

        const HANDLE_KEYS = [
          "trustedRuntime",
          "_trustedRuntime",
          "runtime",
          "getTrustedRuntime",
          "getRuntime",
          "#trustedRuntime",
          "sealedRuntime",
          "trustedRuntimeHandle",
          "assembly",
          "trustedAssembly",
        ];

        function collectKeys(value) {
          const names = [];
          const seen = new Set();
          let current = value;
          while (current && current !== Object.prototype && !seen.has(current)) {
            seen.add(current);
            for (const key of Reflect.ownKeys(current)) {
              names.push(typeof key === "symbol" ? String(key) : String(key));
            }
            current = Object.getPrototypeOf(current);
          }
          return names;
        }

        function isTrustedService(value) {
          if (!value || typeof value !== "object") {
            return false;
          }
          return (
            typeof value.resolvePrincipal === "function" ||
            typeof value.listLiveBindings === "function" ||
            typeof value.getActiveDelegation === "function" ||
            typeof value.ensureDataPlaneId === "function"
          );
        }

        function isAssembly(value) {
          return Boolean(
            value &&
              typeof value === "object" &&
              (isTrustedService(value) ||
                isTrustedService(value.principalProvider) ||
                isTrustedService(value.bindingQuery) ||
                isTrustedService(value.delegationStore) ||
                typeof value.ensureDataPlaneId === "function"),
          );
        }

        function isHandle(value) {
          return Boolean(
            value &&
              typeof value === "object" &&
              (value.environment === "service" || value.environment === "cloud" || value.environment === "local") &&
              typeof value.requireAuth === "boolean",
          );
        }

        const visible = collectKeys(engine);
        const leakedHandleNames = HANDLE_KEYS.filter((name) => visible.includes(name));
        if (leakedHandleNames.length > 0) {
          throw new Error("runtime handle names visible on instance or prototype: " + leakedHandleNames.join(","));
        }

        const handleAccess = {
          dot: engine.trustedRuntime,
          bracket: engine["trustedRuntime"],
          underscore: engine["_trustedRuntime"],
          runtime: engine["runtime"],
          getter: typeof engine.getTrustedRuntime === "function" ? engine.getTrustedRuntime() : engine.getTrustedRuntime,
          inOperator: HANDLE_KEYS.filter((key) => key in engine),
        };
        if (handleAccess.inOperator.length > 0) {
          throw new Error("handle keys visible via in operator: " + handleAccess.inOperator.join(","));
        }
        if ([handleAccess.dot, handleAccess.bracket, handleAccess.underscore, handleAccess.runtime, handleAccess.getter].some((value) => value != null)) {
          throw new Error("runtime handle was reachable as an ordinary property or getter");
        }

        const inspected = inspect(engine, { showHidden: true, depth: 6, getters: true, compact: false });
        if (inspected.includes("principalProvider") || inspected.includes("bindingQuery") || inspected.includes("delegationStore") || inspected.includes("valid_tok")) {
          throw new Error("inspect disclosed trusted services or token material");
        }
        const serialized = JSON.stringify(engine);
        if (serialized.includes("trustedRuntime") || serialized.includes("principalProvider") || serialized.includes("bindingQuery")) {
          throw new Error("JSON serialization disclosed the runtime handle or assembly");
        }
        if (Object.prototype.hasOwnProperty.call(JSON.parse(serialized), "trustedRuntime")) {
          throw new Error("JSON.stringify still emits trustedRuntime");
        }

        let clonedKeys = [];
        try {
          const cloned = structuredClone(engine);
          clonedKeys = collectKeys(cloned);
          if (clonedKeys.includes("trustedRuntime") || isHandle(cloned?.trustedRuntime) || isAssembly(cloned)) {
            throw new Error("structuredClone disclosed the runtime handle or assembly");
          }
        } catch (error) {
          if (error instanceof Error && error.message.includes("structuredClone disclosed")) {
            throw error;
          }
        }

        const proxy = new Proxy(engine, {
          get(target, prop, receiver) {
            return Reflect.get(target, prop, receiver);
          },
        });
        if (proxy.trustedRuntime != null || proxy["trustedRuntime"] != null) {
          throw new Error("Proxy get disclosed the runtime handle");
        }

        class SubEngine extends sdk.InMemoryCogniWeaveEngine {}
        const subclassed = new SubEngine({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }, { metadataStore, runtime });
        if (subclassed.trustedRuntime != null || subclassed["trustedRuntime"] != null) {
          throw new Error("subclass property access disclosed the runtime handle");
        }

        const candidates = [];
        for (const key of HANDLE_KEYS) {
          candidates.push(engine[key], Object.getPrototypeOf(engine)?.[key], sdk.InMemoryCogniWeaveEngine.prototype?.[key]);
        }
        candidates.push(engine, proxy, subclassed);
        for (const name of collectKeys(engine)) {
          try { candidates.push(engine[name]); } catch {}
        }

        function isEngineAssembly(value) {
          return Boolean(
            value &&
              typeof value === "object" &&
              (value.principalProvider === principalProvider ||
                value.bindingQuery === bindingQuery ||
                value.delegationStore === delegationStore),
          );
        }

        const obtainedServices = [];
        const obtainedHandles = [];
        for (const value of candidates) {
          if (value === principalProvider || value === bindingQuery || value === delegationStore || isEngineAssembly(value)) {
            obtainedServices.push("engine-surface");
          }
          if (isHandle(value) && value !== engine.config && value !== runtime) {
            obtainedHandles.push(value);
          }
        }
        if (obtainedHandles.length > 0) {
          throw new Error("engine runtime handle was obtained from the instance surface");
        }

        const unpackNames = Object.getOwnPropertyNames(sdk).filter((name) =>
          /runtime|assembly|trusted|principalProvider|bindingQuery|delegationStore/i.test(name),
        );
        for (const name of unpackNames) {
          const fn = sdk[name];
          if (typeof fn !== "function") {
            continue;
          }
          if (/^create|^is[A-Z]/.test(name)) {
            continue;
          }
          for (const arg of [engine, engine.trustedRuntime, engine["trustedRuntime"], {}, null]) {
            let returned;
            try { returned = fn(arg); } catch { continue; }
            if (returned && typeof returned.then === "function") {
              returned.then(() => {}, () => {});
              continue;
            }
            if (
              returned === principalProvider ||
              returned === bindingQuery ||
              returned === delegationStore ||
              isEngineAssembly(returned)
            ) {
              obtainedServices.push(name);
            }
          }
        }
        if (obtainedServices.length > 0) {
          throw new Error("the Engine's trusted services were obtained from the instance or public SDK exports: " + obtainedServices.join(","));
        }

        // A handle the consumer themselves created must not be unpackable via a
        // public SDK-root helper either.
        if (typeof sdk.resolveTrustedRuntimeAssembly === "function") {
          const unpacked = sdk.resolveTrustedRuntimeAssembly(runtime);
          if (isAssembly(unpacked)) {
            throw new Error("SDK root still unpacks a Trusted Runtime assembly");
          }
        }

        const service = new sdk.CogniWeaveRestService(engine);
        const health = await sdk.routeCogniWeaveHttpRequest(service, { method: "GET", url: "/healthz", headers: {} });
        if (health.status !== 200) {
          throw new Error("authorized REST healthz failed: " + JSON.stringify(health));
        }
        const unauthMetrics = await sdk.routeCogniWeaveHttpRequest(service, { method: "GET", url: "/v1/metrics", headers: {} });
        if (unauthMetrics.status !== 401) {
          throw new Error("service REST missing identity did not fail closed: " + JSON.stringify(unauthMetrics));
        }
        const authedMetrics = await sdk.routeCogniWeaveHttpRequest(service, {
          method: "GET",
          url: "/v1/metrics",
          headers: { authorization: "Bearer valid_tok", "x-cogniweave-tenant-id": "t_1" },
        });
        if (authedMetrics.status !== 200) {
          throw new Error("authorized REST metrics failed: " + JSON.stringify(authedMetrics));
        }

        const rawInput = "Current throughput is dropping and the external API is slow. Should we add synchronous retries?";
        const write = await engine.writeBack({
          rawInput,
          scope,
          sourceType: "chat",
          sourceSessionId: "sess_pack_runtime",
          authorization: { bearerToken: "valid_tok" },
        });
        if (write.status !== "COMPLETED" || !write.journalId) {
          throw new Error("authorized Engine Direct writeBack failed: " + JSON.stringify(write));
        }
        const journal = await sdk.routeCogniWeaveHttpRequest(service, {
          method: "GET",
          url: "/v1/journals/" + write.journalId,
          headers: {
            authorization: "Bearer valid_tok",
            "x-cogniweave-tenant-id": "t_1",
            "x-cogniweave-workspace-id": scope.workspaceId,
            "x-cogniweave-project-id": scope.projectId,
            "x-cogniweave-agent-id": scope.agentId,
            "x-cogniweave-visibility": scope.visibility,
          },
        });
        if (journal.status !== 200 || journal.body?.id !== write.journalId) {
          throw new Error("authorized REST journal read failed: " + JSON.stringify(journal));
        }

        const atomA = {
          id: "atm_opt_a",
          atomType: "strategy",
          scope,
          claim: { type: "procedural", statement: "Always verify forward-only ancestry before production cutover." },
          trigger: { conditions: ["production_cutover"], contextTags: ["release"] },
          applicability: { include: ["prod"], exclude: [] },
          provenance: { sourceEventIds: ["evt_1"], evidenceRefs: ["evd_1"] },
          versioning: { version: 1 },
          state: { status: "active", conflictsWith: [] },
          metrics: { confidence: 0.85, reuseCount: 3 },
          dedupKey: "k_opt",
        };
        const atomB = { ...atomA, id: "atm_opt_b", provenance: { sourceEventIds: ["evt_2"], evidenceRefs: ["evd_2"] } };
        const optStore = new sdk.InMemoryMetadataStore();
        const optDataPlaneId = await optStore.ensureDataPlaneId();
        const optCaller = { tenantId: "t_1", ownerType: "user", ownerId: "u_1" };
        const optBinding = sdk.createMemorySubjectBinding({
          partition: sdk.createMemoryPartitionKeyV1(optDataPlaneId, scope),
          scope,
          subject: optCaller,
        });
        await optStore.saveAtom(atomA);
        await optStore.saveAtom(atomB);
        await optStore.saveMemorySubjectBinding(optBinding);
        const optRuntime = sdk.createTrustedRuntime({
          environment: "service",
          principalProvider: sdk.createDenyByDefaultPrincipalProvider([{ token: "valid_tok", principal }]),
          bindingQuery: sdk.createAuthoritativeBindingQueryFromMetadataStore(optStore),
        });
        const job = await sdk.runOptimizationJob({
          tenantId: "t_1",
          subjectId: "u_1",
          scope,
          optimizationType: "consolidation",
          atoms: [atomA, atomB],
          executionContext: {
            actorUserId: "u_1",
            tenantId: "t_1",
            scope,
            caller: optCaller,
            dataPlaneId: optDataPlaneId,
          },
          runtime: optRuntime,
          authorization: { bearerToken: "valid_tok" },
          metadataStore: optStore,
          graphStore: new sdk.InMemoryGraphStore(),
          vectorStore: new sdk.InMemoryVectorStore(),
        });
        if (job.status !== "completed" || job.authorization?.decision !== "allow") {
          throw new Error("authorized optimization job failed: " + JSON.stringify(job));
        }

        const closedRuntime = sdk.createTrustedRuntime({ environment: "service" });
        const closedEngine = new sdk.InMemoryCogniWeaveEngine({
          environment: "service",
          metadataBackend: "memory",
          graphBackend: "memory",
          evidenceBackend: "memory",
          vectorBackend: "memory",
        }, { runtime: closedRuntime });
        let directDenied = false;
        try {
          await closedEngine.writeBack({
            rawInput,
            scope,
            sourceType: "chat",
            sourceSessionId: "sess_closed",
          });
        } catch (error) {
          directDenied = error instanceof sdk.PrincipalUnavailableError;
        }
        if (!directDenied) {
          throw new Error("service Engine Direct writeBack did not fail closed");
        }
        const closedService = new sdk.CogniWeaveRestService(closedEngine);
        const closedRest = await sdk.routeCogniWeaveHttpRequest(closedService, {
          method: "GET",
          url: "/v1/metrics",
          headers: {},
        });
        const closedRestDenied =
          closedRest.status === 401 ||
          (closedRest.status === 503 && closedRest.body?.error === "principal_unavailable");
        if (!closedRestDenied) {
          throw new Error("service REST without a trusted principal did not fail closed: " + JSON.stringify(closedRest));
        }
        let optDenied = false;
        try {
          await sdk.runOptimizationJob({
            tenantId: "t_1",
            subjectId: "u_1",
            scope,
            optimizationType: "consolidation",
            atoms: [atomA, atomB],
            executionContext: {
              actorUserId: "u_1",
              tenantId: "t_1",
              scope,
              caller: optCaller,
              dataPlaneId: optDataPlaneId,
            },
            runtime: sdk.createTrustedRuntime({ environment: "cloud" }),
            metadataStore: optStore,
          });
        } catch (error) {
          optDenied =
            error instanceof sdk.PrincipalUnavailableError ||
            error instanceof sdk.UntrustedRuntimeError ||
            (error && typeof error === "object" && (error.name === "PrincipalUnavailableError" || error.code === "principal_unavailable"));
        }
        if (!optDenied) {
          throw new Error("cloud optimization without a trusted principal did not fail closed");
        }

        console.log(JSON.stringify({
          ok: true,
          leakedExports,
          leakedTypings,
          leakedHandleNames,
          clonedKeysHasHandle: clonedKeys.includes("trustedRuntime"),
          writeStatus: write.status,
          journalId: journal.body?.id,
          jobStatus: job.status,
          unauthMetrics: unauthMetrics.status,
          closedRest: closedRest.status,
          closedRestError: closedRest.body?.error ?? null,
        }));
      `,
      installDir,
    );
    expect(result.status, result.stdout + result.stderr).toBe(0);
    const payload = JSON.parse(result.stdout.trim()) as {
      ok: boolean;
      leakedExports: string[];
      leakedTypings: string[];
      leakedHandleNames: string[];
      clonedKeysHasHandle: boolean;
      writeStatus: string;
      journalId: string;
      jobStatus: string;
      unauthMetrics: number;
      closedRest: number;
      closedRestError: string | null;
    };
    expect(payload).toMatchObject({
      ok: true,
      leakedExports: [],
      leakedTypings: [],
      leakedHandleNames: [],
      clonedKeysHasHandle: false,
      writeStatus: "COMPLETED",
      jobStatus: "completed",
      unauthMetrics: 401,
    });
    expect([401, 503]).toContain(payload.closedRest);
    if (payload.closedRest === 503) {
      expect(payload.closedRestError).toBe("principal_unavailable");
    }
    expect(payload.journalId).toBeTruthy();
  });
});
