#!/usr/bin/env node

import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import process from "process";
import YAML from "yaml";

function findConfigFile() {
  const candidates = [
    ".ci.yml",
    ".ci.yaml",
    ".github/workflows/ci.yml",
    ".github/workflows/ci.yaml",
  ];
  for (const file of candidates) {
    if (fs.existsSync(path.resolve(process.cwd(), file))) {
      return file;
    }
  }
  return null;
}

async function runLocalCI() {
  const configFile = findConfigFile();
  if (!configFile) {
    console.error("❌ No local CI file (.ci.yml or .github/workflows/ci.yml) found.");
    process.exit(1);
  }

  console.log(`\n📋 Loading local CI workflow from: ${configFile}`);
  const rawContent = fs.readFileSync(path.resolve(process.cwd(), configFile), "utf8");
  const workflow = YAML.parse(rawContent);

  const pipelineName = workflow.name || "Local CI Workflow";
  console.log(`\n==============================================`);
  console.log(` 🏃 Running ${pipelineName}`);
  console.log(`==============================================`);

  const nodeBinPath = path.resolve(process.cwd(), "node_modules/.bin");
  const envVars = {
    ...process.env,
    PATH: `${nodeBinPath}:${process.env.PATH}`,
    ...workflow.env,
  };

  const jobs = workflow.jobs || {};

  let totalPassed = 0;
  let totalFailed = 0;
  const startTime = Date.now();

  for (const [jobId, jobDef] of Object.entries(jobs)) {
    const jobName = jobDef.name || jobId;
    console.log(`\n▶️  Executing Job: [${jobName}] (${jobId})`);

    const steps = jobDef.steps || [];
    let jobFailed = false;

    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      const stepNum = i + 1;

      if (step.uses) {
        console.log(`   Step ${stepNum}: uses action [${step.uses}] (local environment setup)`);
        if (step.with) {
          console.log(`          With params: ${JSON.stringify(step.with)}`);
        }
        continue;
      }

      if (step.run) {
        const command = step.run;
        console.log(`   Step ${stepNum}: run command -> "${command}"`);
        try {
          execSync(command, { stdio: "inherit", env: envVars });
          console.log(`   ✅ Step ${stepNum} passed.`);
        } catch (err) {
          console.error(`   ❌ Step ${stepNum} failed!`, err.message);
          jobFailed = true;
          break;
        }
      }
    }

    if (jobFailed) {
      totalFailed++;
      console.error(`❌ Job [${jobName}] failed.`);
    } else {
      totalPassed++;
      console.log(`✅ Job [${jobName}] completed successfully.`);
    }
  }

  const durationSec = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log(`\n==============================================`);
  console.log(` 📊 CI Summary: ${totalPassed} passed, ${totalFailed} failed (${durationSec}s)`);
  console.log(`==============================================\n`);

  if (totalFailed > 0) {
    process.exit(1);
  }
}

runLocalCI().catch((err) => {
  console.error("Fatal error during local CI execution:", err);
  process.exit(1);
});
