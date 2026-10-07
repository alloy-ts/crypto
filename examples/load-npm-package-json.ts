import { fileURLToPath } from "node:url";

import { Config, Environment, File, FileFormat } from "../src/main.ts";

// Resolve package.json from this file's location so the example works from any cwd.
const packageJsonPath = fileURLToPath(new URL("../package.json", import.meta.url));

// ---------------------------------------------------------------------------
// 1. Load package.json as a plain JSON file source
// ---------------------------------------------------------------------------
const config = Config.builder()
  .addSource(new File(packageJsonPath, FileFormat.Json))
  .build();

console.log("=== 1. JSON file source ===");
console.log("name       :", config.getString("name"));
console.log("version    :", config.getString("version"));
console.log("type       :", config.getString("type"));
console.log("entry point:", config.getTable("exports")["./package.json"]);
console.log("napi targets:", config.getArray("napi.targets")?.length, "platform(s)");
console.log("scripts.test:", config.getString("scripts.test"));
console.log("deps       :", Object.keys(config.getTable("devDependencies")).length, "devDependencies");
console.log("whole object keys:", Object.keys(config.tryDeserialize() as object).join(", "));

// ---------------------------------------------------------------------------
// 2. Nested access is just a dotted path; camelCase keys keep their case
// ---------------------------------------------------------------------------
console.log("\n=== 2. Nested keys ===");
console.log("packageManager:", config.getString("devEngines.packageManager.name"));
console.log("npm override   :", config.getString("overrides.vite"));

// ---------------------------------------------------------------------------
// 3. No format hint: the extension is probed (package -> package.json)
// ---------------------------------------------------------------------------
const auto = Config.builder()
  .addSource(File.withName(packageJsonPath.replace(/\.json$/, "")))
  .build();

console.log("\n=== 3. Extension-less discovery ===");
console.log("name       :", auto.getString("name"));

// ---------------------------------------------------------------------------
// 4. Layering: defaults < file < environment < explicit override
// ---------------------------------------------------------------------------
// The prefix is stripped, the rest is lower-cased and `_` nests the key,
// so PKG_LOG_LEVEL becomes the table `log` with a `level` entry.
process.env["PKG_LOG_LEVEL"] = "debug";

const layered = Config.builder()
  .setDefault("log.level", "info")
  .addSource(new File(packageJsonPath, FileFormat.Json))
  .addSource(Environment.withPrefix("PKG").separator("_"))
  .setOverride("version", "0.0.0-local")
  .build();

console.log("\n=== 4. Layered sources ===");
console.log("log.level (from env) :", layered.getString("log.level"));
console.log("version (override)   :", layered.getString("version"));
console.log("name (from file)     :", layered.getString("name"));
try {
  // env keys are lower-cased, so the flat camelCase spelling does not resolve
  layered.getString("logLevel");
} catch (error) {
  console.log("logLevel (camelCase) :", (error as Error).message);
}

// ---------------------------------------------------------------------------
// 5. Optional files: a missing source is skipped when required(false)
// ---------------------------------------------------------------------------
const optional = new File(fileURLToPath(new URL("./nope.json", import.meta.url)), FileFormat.Json);
optional.required(false);

const resilient = Config.builder()
  .addSource(optional)
  .addSource(new File(packageJsonPath, FileFormat.Json))
  .build();

console.log("\n=== 5. Optional source ===");
console.log("name       :", resilient.getString("name"));
