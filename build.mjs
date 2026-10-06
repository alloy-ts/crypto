import { writeFileSync } from 'node:fs'
import { createBuildCommand, NapiCli } from '@napi-rs/cli'

const build = createBuildCommand(process.argv.slice(2))
const options = build.getOptions()
const cli = new NapiCli()

const { task } = await cli.build({
  ...options,
  outputDir: 'dist',
  cargoOptions: build.cargoOptions,
})

await task

writeFileSync('index.js', "module.exports = require('./dist/index.js')\n")
writeFileSync('index.d.ts', "export * from './dist/index'\n")
