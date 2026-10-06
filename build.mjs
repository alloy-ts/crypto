import { createBuildCommand, NapiCli } from '@napi-rs/cli'

const build = createBuildCommand(process.argv.slice(2))
const options = build.getOptions()
const cli = new NapiCli()

import { copyFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const { task } = await cli.build({
  ...options,
  outputDir: 'build',
  cargoOptions: build.cargoOptions,
})

await task

for (const file of readdirSync('build')) {
  copyFileSync(join('build', file), join('.', file))
}
