import { createBuildCommand, NapiCli } from "@napi-rs/cli";

const build = createBuildCommand(process.argv.slice(2));
const options = build.getOptions();
const cli = new NapiCli();

const { task } = await cli.build({
  ...options,
  cargoOptions: build.cargoOptions,
  outputDir: options.outputDir || "./dist",
});

await task;
