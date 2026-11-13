import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { NapiCli } from "@napi-rs/cli";

// build.ts lives at the project root, so a single dirname yields the repo root.
const root = dirname(fileURLToPath(import.meta.url));

function run(cmd: string, args: string[]): void {
  execFileSync(cmd, args, { cwd: root, stdio: "inherit" });
}

function git(args: string[]): string {
  return execFileSync("git", args, { cwd: root }).toString().trim();
}

// Wait until napi has actually written its artifacts (notably the .node binary)
// into `dir`. napi's build promise resolves before the copy completes, so we
// poll instead of trusting the promise.
async function waitForBuildOutput(dir: string, timeoutMs = 30000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (existsSync(dir) && readdirSync(dir).some((f) => f.endsWith(".node"))) {
      return;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`timed out waiting for napi output in ${dir}`);
}

// Derive a filesystem/ref-safe build id from the package integrity hash.
// `npm_package_integrity` is only present when this package is installed as a
// dependency from the registry (e.g. during `npm install` / `npm ci` of a
// consumer); it is undefined for a local `npm run build`, in which case we fall
// back to an ephemeral id so every local build still gets its own directory.
function computeBuildId(): string {
  const integrity = process.env["npm_package_integrity"] ?? "";
  console.log(`[build] npm_package_integrity = ${integrity || "(undefined)"}`);

  // SRI format is "<algo>-<base64hash>" (e.g. "sha512-..."); the algorithm
  // prefix is not a useful id, so we take the hash portion.
  let source = integrity.includes("-") ? integrity.split("-", 2)[1] : integrity;
  if (!source) {
    source = createHash("sha256")
      .update(`${Date.now()}-${process.pid}-${Math.random()}`)
      .digest("hex");
    console.log("[build] integrity unavailable — using generated fallback id");
  }

  // Sanitize to a token safe for directory and git ref names (base64 may
  // contain `+`, `/`, `=`).
  return source.slice(0, 7).replace(/\+/g, "-").replace(/\//g, "_");
}

async function runBuild(): Promise<void> {
  const args = process.argv.slice(2);
  const isRelease = args.includes("--release") || args.includes("-r");
  const useNapiCross = args.includes("--use-napi-cross");
  const crossCompile = args.includes("--cross-compile") || args.includes("-x");
  const useCross = args.includes("--use-cross");

  const targetIdx = args.findIndex((a) => a === "--target" || a === "-t");
  const target = targetIdx !== -1 && args[targetIdx + 1] ? args[targetIdx + 1] : undefined;

  const buildId = computeBuildId();
  const outDir = join("dist", buildId);
  console.log(`[build] buildId = ${buildId}`);
  console.log(`[build] napi output dir = ${outDir}`);

  const cli = new NapiCli();
  await cli.build({
    platform: true,
    esm: true,
    outputDir: outDir,
    release: isRelease,
    target,
    useNapiCross,
    crossCompile,
    useCross,
  });

  // napi's build promise can resolve before cargo finishes copying the native
  // binary into outputDir, so poll until the .node artifact actually lands.
  await waitForBuildOutput(join(root, outDir));

  // Mirror the generated artifacts into dist/ so the static import in
  // src/lib.test.ts (`../dist/index.js`) and `vp pack` / `vp check` keep working
  // while each build's real artifacts live isolated under dist/<buildId>/.
  const distDir = join(root, "dist");
  mkdirSync(distDir, { recursive: true });
  const produced = readdirSync(join(root, outDir));
  for (const f of produced) {
    copyFileSync(join(root, outDir, f), join(distDir, f));
  }
  console.log(`[build] mirrored ${produced.length} artifact(s) ${outDir}/* -> dist/`);

  // Pack, then check. The native binary is only recorded if the check passes.
  console.log("[build] npm run pack");
  run("npm", ["run", "pack"]);

  console.log("[build] npm run check");
  run("npm", ["run", "check"]);

  // Record each built .node binary as a git blob and expose its oid via
  // refs/builds/<buildId>/<exe-oid>.
  console.log("[build] check passed — recording native binary build artifact(s)");
  const nodeFiles = produced.filter((f) => f.endsWith(".node"));
  if (nodeFiles.length === 0) {
    console.warn(`[build] no .node binary found in ${outDir}; skipping git blob/ref`);
    return;
  }
  for (const f of nodeFiles) {
    const abs = join(root, outDir, f);
    const oid = git(["hash-object", "-w", abs]);
    const ref = `refs/builds/${buildId}/${oid}`;
    git(["update-ref", ref, oid]);
    console.log(`[build] recorded ${f} -> blob ${oid}`);
    console.log(`[build]   ref: ${ref}`);
  }
  console.log(`[build] done (buildId=${buildId})`);
}

void runBuild().catch((err) => {
  console.error(err);
  process.exit(1);
});
