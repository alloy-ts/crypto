import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

console.log("\n==============================================");
console.log(" 🏃 Running Local TypeScript CI Pipeline");
console.log("==============================================\n");

const nodeBinPath = path.resolve(process.cwd(), "node_modules/.bin");
const envVars = {
  ...process.env,
  PATH: `${nodeBinPath}:${process.env.PATH}`,
  DEBUG: "napi:*",
  MACOSX_DEPLOYMENT_TARGET: "10.13",
};

interface CIStep {
  title: string;
  command: string | (() => void);
}

const steps: CIStep[] = [
  { title: "Check & Lint (ci:check)", command: "vp check src" },
  { title: "Native Addon Build (ci:build)", command: "npm run build" },
  { title: "Unit Tests (VP)", command: "vp test src/main.test.ts" },
  { title: "Unit Tests (CJS)", command: "npm test" },
  { title: "Cross-Build Matrix (Dry Run)", command: "node build.mjs --use-cross --dry-run" },
  {
    title: "Prepublish Tarball Creation (test:prepublish)",
    command: "npm pack",
  },
  {
    title: "Publish From Prepublished Tarball (Dry Run)",
    command: () => {
      const files = fs.readdirSync(process.cwd()).filter((f) => f.endsWith(".tgz"));
      if (files.length === 0) {
        throw new Error("No prepublished .tgz tarball found for publishing");
      }
      const tarball = files[0];
      console.log(`    Publishing directly from prepublished tarball: ${tarball}`);
      execSync(`npm publish ${tarball} --dry-run`, { stdio: "inherit", env: envVars });
    },
  },
];

let passed = 0;
let failed = 0;
const startTime = Date.now();

for (let i = 0; i < steps.length; i++) {
  const step = steps[i];
  console.log(`▶️  Step ${i + 1}/${steps.length}: [${step.title}]`);

  try {
    if (typeof step.command === "function") {
      step.command();
    } else {
      console.log(`    Command: "${step.command}"`);
      execSync(step.command, { stdio: "inherit", env: envVars });
    }
    console.log(`✅ [${step.title}] Passed.\n`);
    passed++;
  } catch (err: any) {
    console.error(`❌ [${step.title}] Failed:`, err.message, "\n");
    failed++;
    break;
  }
}

const durationSec = ((Date.now() - startTime) / 1000).toFixed(2);
console.log("==============================================");
console.log(` 📊 CI Summary: ${passed} passed, ${failed} failed (${durationSec}s)`);
console.log("==============================================\n");

if (failed > 0) {
  process.exit(1);
}
