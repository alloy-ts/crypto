import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

type ConfigEntry = { key: string; value: string };

// Parse the top-level `config:` mapping from repo.manifest.yml.
// Each entry is a list item of the form `  - key: value`; the value may itself
// contain colons (e.g. an ssh public key), so we split only on the first colon.
function parseManifestConfig(text: string): ConfigEntry[] {
  const lines = text.split(/\r?\n/);
  const entries: ConfigEntry[] = [];
  let inConfig = false;

  for (const line of lines) {
    // Enter the `config:` block.
    if (/^config:\s*$/.test(line)) {
      inConfig = true;
      continue;
    }
    // A new top-level key (no leading whitespace) ends the `config` block.
    if (inConfig && /^\S/.test(line)) {
      inConfig = false;
    }
    if (!inConfig) continue;

    const item = line.match(/^\s*-\s*(.+)$/)?.[1]?.trim();
    if (!item) continue;

    const colon = item.indexOf(":");
    if (colon === -1) continue;

    const key = item.slice(0, colon).trim();
    const value = item.slice(colon + 1).trim();
    if (key) entries.push({ key, value });
  }

  return entries;
}

function git(args: string[]): void {
  execFileSync("git", args, { cwd: root, stdio: "inherit" });
}

function npm(args: string[]): void {
  execFileSync("npm", args, { cwd: root, stdio: "inherit" });
}

// `prepare` is triggered by `npm install`, `npm ci`, `npm pack` and `npm publish`
// (npm_lifecycle_event is always "prepare" in those cases; npm_command tells us
// the parent command). Those are exactly the events that should also produce a
// build, so we trigger one from setup on that set.
const BUILD_TRIGGER_COMMANDS = new Set(["install", "ci", "pack", "publish"]);

function vp(args: string[]): void {
  // Prefer the locally-installed CLI; fall back to npx when it is not on PATH
  // (e.g. when setup.ts is run directly rather than via an npm script).
  const localBin = join(root, "node_modules", ".bin", "vp");
  try {
    execFileSync(localBin, args, { cwd: root, stdio: "inherit" });
  } catch {
    execFileSync("npx", ["--no-install", "vp", ...args], {
      cwd: root,
      stdio: "inherit",
    });
  }
}

function main(): void {
  const lifecycleEvent = process.env["npm_lifecycle_event"] ?? "";
  const npmCommand = process.env["npm_command"] ?? "";
  console.log(`[setup] npm_lifecycle_event = ${lifecycleEvent || "(none)"}`);
  console.log(`[setup] npm_command = ${npmCommand || "(none)"}`);

  const manifest = readFileSync(join(root, "repo.manifest.yml"), "utf8");
  const entries = parseManifestConfig(manifest);
  if (entries.length === 0) {
    throw new Error("repo.manifest.yml: no `config:` entries found");
  }

  const hooksPathEntry = entries.find((e) => e.key === "core.hooksPath");
  const hooksDir = hooksPathEntry ? dirname(hooksPathEntry.value) : join("scripts", "hooks");

  // (Re)install the Vite+ hook dispatcher. Clear any pre-set hooksPath first so
  // vp always (re)generates the dispatcher instead of short-circuiting because
  // the path is "already set".
  try {
    git(["config", "--local", "--unset", "core.hooksPath"]);
  } catch {
    // Not set yet — that's fine.
  }
  console.log(`[setup] vp config --hooks-dir ${hooksDir}`);
  vp(["config", "--hooks-dir", hooksDir, "--hooks"]);

  // Apply every manifest `config:` entry as a local git config value.
  for (const { key, value } of entries) {
    console.log(`[setup] git config --local ${key} ${value}`);
    git(["config", "--local", key, value]);
  }

  // Build on the events that trigger `prepare` and want a build. When setup.ts
  // is run directly (`npm run prepare`, npm_command = "run-script") we skip the
  // build so it can be invoked standalone without rebuilding.
  if (BUILD_TRIGGER_COMMANDS.has(npmCommand)) {
    console.log(`[setup] ${npmCommand} triggers a build — running npm run build`);
    npm(["run", "build"]);
  } else {
    console.log(`[setup] no build for lifecycle event "${lifecycleEvent || "none"}"`);
  }

  console.log("[setup] repo setup complete");
}

main();
