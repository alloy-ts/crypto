import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
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

// Print npm_package_integrity for diagnostics. It is only defined when this
// package is installed as a registry dependency and is undefined for a local
// `npm run build`, so it is no longer used as the build id (see computeBuildId).
function printIntegrityDiagnostics(): void {
  const integrity = process.env["npm_package_integrity"] ?? "";
  console.log(`[build] npm_package_integrity = ${integrity || "(undefined)"}`);
}

// The build id is the current HEAD *full* sha (40 hex chars). The shorter
// shorthand aliases are derived from it but the canonical id is always the full
// sha, so two different commits can never collide on the canonical ref.
function computeBuildId(): string {
  return git(["rev-parse", "HEAD"]);
}

// Resolve the object an exact leaf ref points at, or undefined when that exact
// ref does not exist. `git rev-parse --verify --quiet` returns the oid on
// success and fails silently (exit 1, no stderr) when the ref is missing, so it
// doubles as a clean existence probe.
function refLeafOid(ref: string): string | undefined {
  try {
    const out = execFileSync("git", ["rev-parse", "--verify", "--quiet", ref], {
      cwd: root,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
    return out || undefined;
  } catch {
    return undefined;
  }
}

// Create a short, human-friendly alias for a build's recorded blob. The alias
// lives under refs/builds/short/<len>/<prefix> (length-segmented) because git
// forbids a ref whose name is a prefix of another ref's name — and a shorter
// shorthand is always a textual prefix of a longer one (or of the full sha). The
// length segment removes that ambiguity so collisions can be resolved by
// extending the prefix (7 -> 8 -> 9 -> ...) until the alias name is unique.
//
// The alias's value is the same blob oid as the canonical refs/builds/<full>/<oid>
// ref, so resolving it "redirects" to the longer sha's recorded binary.
//
// `prevOid` is the blob this build's alias previously pointed at (when a build
// is re-recorded after a binary change but the same HEAD). In that case we
// update the existing alias in place rather than treating it as a foreign
// collision and extending the prefix.
function ensureShorthand(fullSha: string, oid: string, prevOid?: string): void {
  let len = 7;
  while (len <= fullSha.length) {
    const cand = fullSha.slice(0, len);
    const ref = `refs/builds/short/${len}/${cand}`;
    const existing = refLeafOid(ref);
    if (existing === undefined) {
      git(["update-ref", ref, oid]);
      console.log(`[build] shorthand alias ${ref} -> blob ${oid}`);
      return;
    }
    if (existing === oid) {
      // Already correct (e.g. re-recorded to the same binary).
      console.log(`[build] shorthand alias ${ref} already points at ${oid}`);
      return;
    }
    if (prevOid !== undefined && existing === prevOid) {
      // This build's own alias from a previous recording; update in place.
      git(["update-ref", ref, oid]);
      console.log(`[build] shorthand alias ${ref} updated -> blob ${oid}`);
      return;
    }
    // Alias name taken by a *different* build's blob -> collision. Extend.
    len++;
  }
  // Would only happen if every prefix up to the full sha collided, which is
  // impossible in practice; the full-sha canonical ref remains authoritative.
  console.log(
    `[build] no unique shorthand available for ${fullSha.slice(0, 7)}..; ` +
      `canonical refs/builds/${fullSha} is authoritative`,
  );
}

// The recorded exe oid for a build id, taken from refs/builds/<id>/<exe-oid>
// (the ref points at the git blob of the recorded .node). Returns undefined when
// nothing has been recorded yet for this id — i.e. the build status is
// "Not Build".
function getRecordedOid(buildId: string): string | undefined {
  const out = git(["for-each-ref", "--format=%(objectname)", `refs/builds/${buildId}`]);
  const oids = out
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  return oids[0];
}

// The current blob hash of the built .node for a build id, computed from the
// on-disk artifact in dist/<buildId>/. Returns undefined when that artifact is
// not present (e.g. a fresh checkout where dist/ is git-ignored).
function getCurrentBinaryOid(buildId: string): string | undefined {
  const dir = join(root, "dist", buildId);
  if (!existsSync(dir)) return undefined;
  const nodeFile = readdirSync(dir, { withFileTypes: true }).find(
    (e) => e.isFile() && e.name.endsWith(".node"),
  );
  if (!nodeFile) return undefined;
  return git(["hash-object", join(dir, nodeFile.name)]);
}

// Mirror the generated artifacts into dist/ so the static import in
// src/lib.test.ts (`../dist/index.js`) and `vp pack` / `vp check` keep working
// while each build's real artifacts live isolated under dist/<buildId>/. napi
// leaves a `.napi-rs-filesystem-transaction.swp` temp directory in its output
// dir, so we only copy regular files and skip it.
function mirrorArtifacts(buildId: string): void {
  const outDir = join(root, "dist", buildId);
  const distDir = join(root, "dist");
  mkdirSync(distDir, { recursive: true });
  const entries = readdirSync(outDir, { withFileTypes: true });
  const produced = entries.filter(
    (e) => e.isFile() && e.name !== ".napi-rs-filesystem-transaction.swp",
  );
  for (const e of produced) {
    copyFileSync(join(outDir, e.name), join(distDir, e.name));
  }
  console.log(`[build] mirrored ${produced.length} artifact(s) dist/${buildId}/* -> dist/`);
}

async function runBuild(): Promise<void> {
  const args = process.argv.slice(2);
  const isRelease = args.includes("--release") || args.includes("-r");
  const useNapiCross = args.includes("--use-napi-cross");
  const crossCompile = args.includes("--cross-compile") || args.includes("-x");
  const useCross = args.includes("--use-cross");

  const targetIdx = args.findIndex((a) => a === "--target" || a === "-t");
  const target = targetIdx !== -1 && args[targetIdx + 1] ? args[targetIdx + 1] : undefined;

  printIntegrityDiagnostics();

  const buildId = computeBuildId();
  const outDir = join("dist", buildId);
  console.log(`[build] buildId = ${buildId} (HEAD full sha)`);
  console.log(`[build] napi output dir = ${outDir}`);

  // Decide whether a rebuild is actually needed:
  //  - status "Not Build":  no refs/builds/<id> record yet -> build.
  //  - status "Build":      recorded oid exists, but the on-disk binary does not
  //                        match it (or is absent) -> rebuild; otherwise skip.
  const recordedOid = getRecordedOid(buildId);
  const alreadyBuilt = recordedOid !== undefined;

  if (alreadyBuilt) {
    const currentOid = getCurrentBinaryOid(buildId);
    if (currentOid && currentOid === recordedOid) {
      // Up to date: just make sure dist/ is materialized from the recorded build
      // so consumers (vp check / tests) keep working, then skip the heavy build.
      if (existsSync(join(root, "dist", "index.js"))) {
        console.log("[build] dist/index.js already present");
      } else {
        mirrorArtifacts(buildId);
      }
      console.log(
        `[build] build ${buildId} already recorded and matches (${currentOid}); skipping rebuild`,
      );
      return;
    }
    console.log(
      `[build] build ${buildId} recorded (${recordedOid}) but binary mismatch ` +
        `(current ${currentOid ?? "(none)"}); rebuilding`,
    );
  } else {
    console.log(`[build] build ${buildId} not built yet; building`);
  }

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

  mirrorArtifacts(buildId);

  // Pack, then check. The native binary is only recorded if the check passes.
  console.log("[build] npm run pack");
  run("npm", ["run", "pack"]);

  console.log("[build] npm run check");
  run("npm", ["run", "check"]);

  // Record each built .node binary as a git blob and expose its oid via
  // refs/builds/<buildId>/<exe-oid>. A re-record (same HEAD, new binary) must
  // drop the previous canonical child(ren) first so the recorded oid stays
  // single-valued.
  console.log("[build] check passed — recording native binary build artifact(s)");
  const prevOid = getRecordedOid(buildId);
  if (prevOid !== undefined) {
    const stale = git(["for-each-ref", "--format=%(refname)", `refs/builds/${buildId}`])
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    for (const r of stale) {
      git(["update-ref", "-d", r]);
      console.log(`[build] removed stale canonical ref ${r}`);
    }
  }
  const produced = readdirSync(join(root, outDir));
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
  // Once the full-sha canonical ref(s) exist, also publish a short alias that
  // redirects to the recorded binary; it self-extends (7 -> 8 -> ...) on a
  // prefix collision with another build, and updates in place on a re-record.
  const canonicalOid = getRecordedOid(buildId);
  if (canonicalOid) {
    ensureShorthand(buildId, canonicalOid, prevOid);
  }
  console.log(`[build] done (buildId=${buildId})`);
}

void runBuild().catch((err) => {
  console.error(err);
  process.exit(1);
});
