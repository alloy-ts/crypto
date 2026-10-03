#!/usr/bin/env node

import { execSync } from "child_process";
import process from "process";

const TARGET_MATRIX = [
  { target: "x86_64-apple-darwin", flags: "-x" },
  { target: "aarch64-apple-darwin", flags: "-x" },
  { target: "x86_64-pc-windows-msvc", flags: "-x" },
  { target: "i686-pc-windows-msvc", flags: "-x" },
  { target: "aarch64-pc-windows-msvc", flags: "-x" },
  { target: "x86_64-unknown-linux-gnu", flags: "--use-napi-cross" },
  { target: "aarch64-unknown-linux-gnu", flags: "--use-napi-cross" },
  { target: "x86_64-unknown-linux-musl", flags: "-x" },
  { target: "aarch64-unknown-linux-musl", flags: "-x" },
  { target: "armv7-unknown-linux-gnueabihf", flags: "--use-napi-cross" },
  { target: "powerpc64le-unknown-linux-gnu", flags: "--use-napi-cross" },
  { target: "s390x-unknown-linux-gnu", flags: "--use-napi-cross" },
];

function parseArgs() {
  const args = process.argv.slice(2);
  let targetFilter = null;
  let release = false;
  let dryRun = false;
  let buildAll = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--target" && i + 1 < args.length) {
      targetFilter = args[++i];
    } else if (args[i] === "--release") {
      release = true;
    } else if (args[i] === "--dry-run") {
      dryRun = true;
    } else if (args[i] === "--all") {
      buildAll = true;
    }
  }

  return { targetFilter, release, dryRun, buildAll };
}

async function runCrossBuild() {
  const { targetFilter, release, dryRun, buildAll } = parseArgs();

  let targetsToBuild = [];

  if (targetFilter) {
    const match = TARGET_MATRIX.find((t) => t.target === targetFilter);
    targetsToBuild = match ? [match] : [{ target: targetFilter, flags: "-x" }];
  } else if (buildAll) {
    targetsToBuild = TARGET_MATRIX;
  } else {
    // Default: build host platform or first linux target if specified
    targetsToBuild = [TARGET_MATRIX[0]];
  }

  console.log(`\n🚀 Starting Local Cross-Build Pipeline (${targetsToBuild.length} target(s))...`);

  for (const { target, flags } of targetsToBuild) {
    const cmd = `node build.mjs --target ${target} ${flags} ${release ? "--release" : ""}`.trim();
    console.log(`\n⚙️  Building target: ${target}`);
    console.log(`   Command: ${cmd}`);

    if (dryRun) {
      console.log(`   [Dry Run] Skipped execution.`);
      continue;
    }

    try {
      execSync(cmd, { stdio: "inherit", env: { ...process.env, DEBUG: "napi:*" } });
      console.log(`✅ Target ${target} built successfully.`);
    } catch (err) {
      console.error(`❌ Target ${target} failed to build:`, err.message);
      if (!buildAll) {
        process.exit(1);
      }
    }
  }

  console.log(`\n✨ Cross-build process complete!`);
}

runCrossBuild().catch((err) => {
  console.error("Fatal error during cross-build:", err);
  process.exit(1);
});
