import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
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

describe("CW-09-02-R5-A-R1 built package export surface", () => {
  let tempRoot = "";
  let installDir = "";
  let exportMap: Record<string, unknown> = {};
  let tarballName = "";

  beforeAll(() => {
    if (!existsSync(join(packageRoot, "dist", "index.js"))) {
      execFileSync("pnpm", ["exec", "tsc", "-p", "tsconfig.build.json"], {
        cwd: packageRoot,
        stdio: "pipe",
      });
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
    const init = run("npm", ["init", "-y"], installDir, env);
    if (init.status !== 0) {
      throw new Error(`npm init failed:\n${init.stdout}\n${init.stderr}`);
    }
    const install = run("npm", ["install", tarballPath], installDir, env);
    if (install.status !== 0) {
      throw new Error(`npm install failed:\n${install.stdout}\n${install.stderr}`);
    }
    const installedPkg = JSON.parse(
      readFileSync(join(installDir, "node_modules", "@cogniweave", "sdk", "package.json"), "utf8"),
    ) as { exports?: Record<string, unknown> };
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
        "export const leaked = [rebuildFromTruth, registerEngineCanonicalAuthorizationResolver];",
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
    expect(`${forbidden.stdout}\n${forbidden.stderr}`).toMatch(/journal\/repair|not exported|Cannot find module/i);

    const allowed = run(typescriptBin, ["-p", "tsconfig.allowed.json"], installDir);
    expect(allowed.stderr + allowed.stdout, `allowed types failed:\n${allowed.stdout}\n${allowed.stderr}`).toBe("");
    expect(allowed.status).toBe(0);
  });

  it("cannot replace the Canonical resolver or invoke repair helpers from the public package", () => {
    const result = runNode(
      `
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
        const hooks = Object.getOwnPropertyNames(engine).concat(Object.getOwnPropertyNames(Object.getPrototypeOf(engine)));
        if (hooks.includes("registerEngineCanonicalAuthorizationResolver") || hooks.includes("getEngineCanonicalAuthorizationResolver")) {
          throw new Error("resolver hook names visible on the Engine instance");
        }
        console.log(JSON.stringify({ ok: true }));
      `,
      installDir,
    );
    expect(result.status, result.stdout + result.stderr).toBe(0);
    expect(JSON.parse(result.stdout.trim())).toEqual({ ok: true });
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
});
