import { readFileSync } from 'fs'
import { resolve } from 'path'
import { createBuildCommand, NapiCli } from '@napi-rs/cli'

const rawArgs = process.argv.slice(2)
const isTargetAll = rawArgs.includes('--target-all') || rawArgs.includes('--all')
const isDryRun = rawArgs.includes('--dry-run')

// Clean custom flags before passing to NapiCli createBuildCommand
const cleanArgs = rawArgs.filter((arg) => arg !== '--target-all' && arg !== '--all' && arg !== '--dry-run')

const build = createBuildCommand(cleanArgs)
const options = build.getOptions()
const cli = new NapiCli()

function getTargetsFromPackageJson() {
  try {
    const pkgPath = resolve(process.cwd(), 'package.json')
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'))
    return pkg.napi?.targets || []
  } catch {
    return []
  }
}

function determineCrossFlags(target) {
  // If explicitly specified in options, respect them
  if (options.useNapiCross || options.useCross || options.crossCompile) {
    return {
      useNapiCross: options.useNapiCross,
      useCross: options.useCross,
      crossCompile: options.crossCompile,
    }
  }

  // Cross-build defaults based on target triple
  if (
    target.includes('linux-gnu') ||
    target.includes('gnueabihf') ||
    target.includes('powerpc') ||
    target.includes('s390x')
  ) {
    return { useNapiCross: true }
  }

  return { crossCompile: true }
}

async function runBuild() {
  if (isTargetAll) {
    const targets = getTargetsFromPackageJson()
    if (targets.length === 0) {
      console.warn('⚠️ No targets found in package.json napi.targets')
      return
    }

    console.log(`\n🚀 Starting Cross-Build for ${targets.length} target(s) listed in package.json...`)

    for (const target of targets) {
      const crossFlags = determineCrossFlags(target)
      const buildOptions = {
        ...options,
        ...crossFlags,
        target,
        outputDir: options.outputDir || './dist',
        cargoOptions: build.cargoOptions,
      }

      console.log(`\n⚙️  Building target: ${target}`)
      console.log(`   Options: target=${target}, release=${Boolean(buildOptions.release)}, crossFlags=${JSON.stringify(crossFlags)}`)

      if (isDryRun) {
        console.log(`   [Dry Run] Skipped build execution.`)
        continue
      }

      const { task } = await cli.build(buildOptions)
      await task
      console.log(`✅ Target ${target} built successfully.`)
    }

    console.log(`\n✨ All targets cross-built successfully!`)
  } else {
    if (isDryRun) {
      console.log(`[Dry Run] Single build options:`, {
        ...options,
        outputDir: options.outputDir || './dist',
        cargoOptions: build.cargoOptions,
      })
      return
    }

    const { task } = await cli.build({
      ...options,
      outputDir: options.outputDir || './dist',
      cargoOptions: build.cargoOptions,
    })
    await task
  }
}

runBuild().catch((err) => {
  console.error('Fatal build error:', err)
  process.exit(1)
})
