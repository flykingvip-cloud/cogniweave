#!/usr/bin/env node
/**
 * Produce the publishable SDK layout.
 *
 * Public JavaScript entrypoints are bundled so internal modules such as
 * `journal/repair` and `runtime/canonical-resolver-registry` are inlined and
 * are not emitted as standalone executable files.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const packageRoot = resolvePackageRoot();
const distDir = join(packageRoot, "dist");

const JS_ENTRIES = [
  { entry: "src/index.ts", outfile: "dist/index.js" },
  { entry: "src/models.ts", outfile: "dist/models.js" },
  { entry: "src/contracts.ts", outfile: "dist/contracts.js" },
  { entry: "src/cli.ts", outfile: "dist/cli.js" },
];

const DTS_ENTRIES = [
  { entry: "src/index.ts", outfile: "dist/index.d.ts" },
  { entry: "src/models.ts", outfile: "dist/models.d.ts" },
  { entry: "src/contracts.ts", outfile: "dist/contracts.d.ts" },
];

const PUBLISHED_DIST_FILES = new Set([
  "index.js",
  "index.d.ts",
  "models.js",
  "models.d.ts",
  "contracts.js",
  "contracts.d.ts",
  "cli.js",
]);

const FORBIDDEN_PATH_FRAGMENTS = [
  "journal/repair",
  "canonical-resolver-registry",
  "src/",
];

function resolvePackageRoot() {
  return dirname(dirname(fileURLToPath(import.meta.url)));
}

function listFilesRecursive(root) {
  const results = [];
  const walk = (current) => {
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

function assertSafePublishedLayout() {
  const emitted = listFilesRecursive(distDir).map((file) => relative(distDir, file));
  const unexpected = emitted.filter((file) => !PUBLISHED_DIST_FILES.has(file));
  if (unexpected.length > 0) {
    throw new Error(`dist contains unpublished internals: ${unexpected.sort().join(", ")}`);
  }
  const missing = [...PUBLISHED_DIST_FILES].filter((file) => !emitted.includes(file));
  if (missing.length > 0) {
    throw new Error(`dist is missing required public files: ${missing.sort().join(", ")}`);
  }
  for (const file of emitted) {
    const normalized = file.replaceAll("\\", "/");
    for (const fragment of FORBIDDEN_PATH_FRAGMENTS) {
      if (normalized.includes(fragment)) {
        throw new Error(`dist emits forbidden path ${normalized}`);
      }
    }
  }
  for (const file of ["index.js", "cli.js", "models.js", "contracts.js"]) {
    const source = readFileSync(join(distDir, file), "utf8");
    if (source.includes("./journal/repair") || source.includes("./canonical-resolver-registry")) {
      throw new Error(`${file} still references a standalone internal module path`);
    }
  }
}

async function bundleJavaScript() {
  for (const item of JS_ENTRIES) {
    await esbuild.build({
      absWorkingDir: packageRoot,
      entryPoints: [item.entry],
      outfile: item.outfile,
      bundle: true,
      format: "esm",
      platform: "node",
      target: "node22",
      sourcemap: false,
      legalComments: "none",
      logLevel: "info",
    });
    const outfile = join(packageRoot, item.outfile);
    if (readFileSync(outfile, "utf8").trim().length === 0) {
      writeFileSync(outfile, "export {};\n");
    }
  }
}

function bundleTypings() {
  const generator = join(
    packageRoot,
    "node_modules",
    "dts-bundle-generator",
    "dist",
    "bin",
    "dts-bundle-generator.js",
  );
  for (const item of DTS_ENTRIES) {
    execFileSync(
      process.execPath,
      [
        generator,
        "--no-banner",
        "--silent",
        "--project",
        "tsconfig.json",
        "-o",
        item.outfile,
        item.entry,
      ],
      { cwd: packageRoot, stdio: "inherit" },
    );
    const typings = readFileSync(join(packageRoot, item.outfile), "utf8");
    if (/from\s+["']\.\.?(\/|\\)/.test(typings)) {
      throw new Error(`${item.outfile} still contains relative internal type imports`);
    }
    if (
      typings.includes("getEngineCanonicalAuthorizationResolver") ||
      typings.includes("registerEngineCanonicalAuthorizationResolver") ||
      typings.includes("canonical-resolver-registry")
    ) {
      throw new Error(`${item.outfile} re-exposes a closed resolver hook or typings path`);
    }
    if (
      typings.includes("resolveTrustedRuntimeAssembly") ||
      typings.includes("SealedTrustedRuntimeAssembly") ||
      typings.includes("bindEngineTrustedRuntime") ||
      typings.includes("resolveEngineTrustedRuntime") ||
      typings.includes("createSealedProductionRuntime") ||
      typings.includes("issueProductionRuntimePermit") ||
      typings.includes("createProductionEngine") ||
      typings.includes("createOfficialProductionAdapterBundle") ||
      typings.includes("runWithSimulatedProductionProcess") ||
      typings.includes("installSimulatedProcessTrustForTests") ||
      typings.includes("clearSimulatedProductionRuntimeSlot")
    ) {
      throw new Error(`${item.outfile} re-exposes a Trusted Runtime unpack helper, production issuance permit, or test-only process trust hook`);
    }
    if (/(?:^|[^#\w])trustedRuntime\b/.test(typings) || typings.includes("getTrustedRuntime")) {
      throw new Error(`${item.outfile} re-exposes a public Trusted Runtime handle property or getter`);
    }
  }
}

rmSync(distDir, { recursive: true, force: true });
mkdirSync(distDir, { recursive: true });
await bundleJavaScript();
bundleTypings();
assertSafePublishedLayout();
process.stdout.write(
  `SDK build wrote ${[...PUBLISHED_DIST_FILES].sort().join(", ")}\n`,
);
