import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    entry: ["./src/main.ts"],
    format: "esm",
    outDir: "dist",
    exports: true,
    dts: {
      generator: "tsgo",
    },
    deps: {
      resolveDepSubpath: true,
    },
  },
  staged: {
    "*": "vp check src",
  },
  fmt: {},
  lint: {
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: { "vite-plus/prefer-vite-plus-imports": "error" },
  },
  run: {
    cache: true,
    tasks: {
      "ci:check": {
        command: "vp check src",
      },
      "ci:test": {
        command: "vp test src/main.test.ts",
      },
      "ci:build": {
        command: "npm run build",
        cache: {
          output: ["dist/**"],
        },
      },
      "ci:cross-build": {
        command: "node build.mjs --target-all --dry-run",
      },
      "ci:publish-dry-run": {
        command: "npm pack --dry-run",
      },
      ci: {
        command: "tsx src/ci.ts",
      },
    },
  },
});
