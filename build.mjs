import { createBuildCommand, NapiCli } from '@napi-rs/cli'

const build = createBuildCommand(process.argv.slice(2))
const options = build.getOptions()
const cli = new NapiCli()

const { task } = await cli.build({
  ...options,
  outputDir: 'build',
  cargoOptions: build.cargoOptions,
})

await task

import { readFileSync, writeFileSync } from 'fs'
import { join } from 'path'

const indexPath = join(process.cwd(), 'build', 'index.js')
const dtsPath = join(process.cwd(), 'build', 'index.d.ts')

try {
  let indexContent = readFileSync(indexPath, 'utf8')
  if (indexContent.includes('module.exports.argon2 = nativeBinding.argon2')) {
    indexContent = indexContent.replace(
      'module.exports.argon2 = nativeBinding.argon2',
      `const _nativeArgon2 = nativeBinding.argon2\n` +
      `const _wrappedArgon2 = function argon2(algorithm, parameters, callback) {\n` +
      `  const promise = _nativeArgon2(algorithm, parameters)\n` +
      `  if (typeof callback === 'function') {\n` +
      `    promise.then((derivedKey) => callback(null, derivedKey), (err) => callback(err))\n` +
      `    return\n` +
      `  }\n` +
      `  return promise\n` +
      `}\n` +
      `nativeBinding.argon2 = _wrappedArgon2\n` +
      `module.exports.argon2 = _wrappedArgon2`
    )
    writeFileSync(indexPath, indexContent, 'utf8')
  }

  let dtsContent = readFileSync(dtsPath, 'utf8')
  if (dtsContent.includes('export declare function argon2(algorithm: string, parameters: Argon2Parameters): Promise<Buffer>')) {
    dtsContent = dtsContent.replace(
      'export declare function argon2(algorithm: string, parameters: Argon2Parameters): Promise<Buffer>',
      'export declare function argon2(algorithm: string, parameters: Argon2Parameters, callback?: ((err: Error | null, derivedKey: Buffer) => void) | null): Promise<Buffer>'
    )
    writeFileSync(dtsPath, dtsContent, 'utf8')
  }
} catch (e) {
  console.error('Failed to post-process build output:', e)
}
