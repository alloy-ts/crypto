import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { createBuildCommand, NapiCli } from '@napi-rs/cli'

const DEFAULT_TARGET_MATRIX = [
  { target: 'x86_64-apple-darwin', flags: '-x' },
  { target: 'aarch64-apple-darwin', flags: '-x' },
  { target: 'x86_64-pc-windows-msvc', flags: '-x' },
  { target: 'i686-pc-windows-msvc', flags: '-x' },
  { target: 'aarch64-pc-windows-msvc', flags: '-x' },
  { target: 'x86_64-unknown-linux-gnu', flags: '--use-napi-cross' },
  { target: 'aarch64-unknown-linux-gnu', flags: '--use-napi-cross' },
  { target: 'x86_64-unknown-linux-musl', flags: '-x' },
  { target: 'aarch64-unknown-linux-musl', flags: '-x' },
  { target: 'armv7-unknown-linux-gnueabihf', flags: '--use-napi-cross' },
  { target: 'powerpc64le-unknown-linux-gnu', flags: '--use-napi-cross' },
  { target: 's390x-unknown-linux-gnu', flags: '--use-napi-cross' },
  { target: 'wasm32-wasip1-threads', flags: '-x' },
]

function loadNapiTargets() {
  try {
    const pkgPath = path.resolve(process.cwd(), 'package.json')
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
    if (Array.isArray(pkg.napi?.targets) && pkg.napi.targets.length > 0) {
      return pkg.napi.targets
    }
  } catch {
    // Ignore error and use default
  }
  return DEFAULT_TARGET_MATRIX.map((t) => t.target)
}

function parseArgs() {
  const args = process.argv.slice(2)

  const useCross = args.includes('--use-cross')
  const buildAll = args.includes('--target-all') || args.includes('--all') || useCross
  const isRelease = args.includes('--release') || args.includes('-r')
  const dryRun = args.includes('--dry-run')

  const useNapiCross = args.includes('--use-napi-cross')
  const crossCompile = args.includes('-x') || args.includes('--cross-compile')

  let targetFilter = null
  const targetIdx = args.indexOf('--target')
  if (targetIdx !== -1 && args[targetIdx + 1]) {
    targetFilter = args[targetIdx + 1]
  }

  const filteredArgs = args.filter(
    (arg) =>
      arg !== '--target-all' &&
      arg !== '--all' &&
      arg !== '--dry-run' &&
      arg !== '--use-cross'
  )

  return {
    targetFilter,
    isRelease,
    dryRun,
    buildAll,
    useCross,
    useNapiCross,
    crossCompile,
    filteredArgs,
  }
}

async function runBuild() {
  const {
    targetFilter,
    isRelease,
    dryRun,
    buildAll,
    useCross,
    useNapiCross,
    crossCompile,
    filteredArgs,
  } = parseArgs()

  const buildCommand = createBuildCommand(filteredArgs)
  const options = buildCommand.getOptions()
  const cli = new NapiCli()

  const pkgNapiTargets = loadNapiTargets()

  let targetsToBuild = []

  if (targetFilter) {
    targetsToBuild = [targetFilter]
  } else if (buildAll) {
    targetsToBuild = pkgNapiTargets
  } else {
    targetsToBuild = [null]
  }

  console.log(`\n🚀 Starting Local Build Pipeline (${targetsToBuild.length} target(s))...`)

  for (const target of targetsToBuild) {
    const isNapiCrossTarget =
      target &&
      (target.includes('gnueabihf') ||
        target.includes('powerpc') ||
        target.includes('s390x') ||
        target.includes('linux-gnu'))

    const effectiveUseNapiCross = useNapiCross || (target ? isNapiCrossTarget : false)
    const effectiveCrossCompile = crossCompile || (target ? !isNapiCrossTarget : false)

    console.log(`\n⚙️  Building target: ${target || 'default host'}`)

    if (dryRun) {
      console.log(`   [Dry Run] Skipped build execution for ${target || 'default host'}.`)
      continue
    }

    try {
      const buildOpts = {
        ...options,
        cwd: options.cwd || process.cwd(),
        outputDir: options.outputDir || './dist',
        release: isRelease,
        cargoOptions: buildCommand.cargoOptions,
      }

      if (target) {
        buildOpts.target = target
      }
      if (useCross) buildOpts.useCross = true
      if (effectiveUseNapiCross) buildOpts.useNapiCross = true
      if (effectiveCrossCompile) buildOpts.crossCompile = true

      const { task } = await cli.build(buildOpts)
      await task
      console.log(`✅ Target ${target || 'default host'} built successfully.`)
    } catch (err) {
      console.error(`❌ Target ${target || 'default host'} failed to build:`, err.message)
      if (!buildAll) {
        process.exit(1)
      }
    }
  }

  console.log(`\n✨ Build process complete!`)
}

runBuild().catch((err) => {
  console.error('Fatal error during build:', err)
  process.exit(1)
})
