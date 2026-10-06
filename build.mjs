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

import fs from 'node:fs'

fs.copyFileSync('build/index.js', 'index.js')
fs.copyFileSync('build/index.d.ts', 'index.d.ts')
for (const file of fs.readdirSync('build')) {
  if (file.endsWith('.node')) {
    fs.copyFileSync(`build/${file}`, file)
  }
}
