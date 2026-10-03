# Starter Template

TypeScript starter template with local CI runner, task caching, and cross-platform native compilation.

## Development

- Configure local hooks:

```bash
npm run prepare
```

- Install dependencies:

```bash
vp install
```

- Run unit tests:

```bash
vp test
```

- Run dev mode:

```bash
npm run dev
```

- Build native library for host platform:

```bash
npm run build
```

- Code formatting & linting:

```bash
npm run fmt
npm run lint
npm run check
```

## Local CI & Orchestration

This project supports running complete CI jobs locally without requiring external cloud services (like GitHub Actions) or heavy Docker containers.

### Local Task Runner & Caching

Using `vite-plus` (`vp`) and `@voidzero-dev/vite-task-client`, local CI tasks are defined in `vite.config.ts` and leverage content-addressed task caching:

```bash
# Run the local CI task pipeline with task caching
vp run ci
```

Specific local CI task steps can also be executed individually:

```bash
vp run ci:check        # Code formatting and lint checks
vp run ci:test         # Unit tests
vp run ci:build        # Host native build
vp run ci:cross-build  # Cross-build target matrix
vp run ci:publish-dry-run  # Dry-run package publish verification
```

### Declarative YAML CI Workflows (`.ci.yml`)

Local CI steps can be written in a simple YAML workflow format (`.ci.yml`):

```yaml
name: Local CI Pipeline

jobs:
  check:
    name: Check & Lint
    steps:
      - uses: voidzero-dev/setup-vp@v1
        with:
          node-version: '22'
          cache: true
      - run: vp check src scripts

  build:
    name: Native Addon Build
    steps:
      - run: npm run build

  test:
    name: Unit Tests
    steps:
      - run: vp test src/main.test.ts
      - run: npm test

  cross-build:
    name: Cross-Build Matrix
    steps:
      - run: node scripts/cross-build.mjs --dry-run --all

  publish:
    name: Publish Check
    steps:
      - run: npm pack --dry-run
```

Execute the local YAML CI runner natively:

```bash
npm run ci:local
```

### Native Cross-Building

Cross-compilation for foreign target matrix (`x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, etc.) is supported directly on the host using `@napi-rs/cli` and `cargo-zigbuild` / `cargo-xwin` / `--use-napi-cross`:

```bash
# Cross-build for a specific target natively:
node scripts/cross-build.mjs --target x86_64-unknown-linux-gnu

# Run dry-run cross-build for all targets:
node scripts/cross-build.mjs --dry-run --all
```

### Pre-Commit Hooks

Git pre-commit hooks are configured via `vite.config.ts` (`staged`). Whenever you commit code, `vp check src scripts` automatically runs on staged files to guarantee code quality.
