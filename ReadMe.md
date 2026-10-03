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
# Run the complete local CI task pipeline with task caching
vp run ci
```

Specific local CI task steps can also be executed individually:

```bash
vp run ci:check            # Code formatting and lint checks
vp run ci:test             # Unit tests
vp run ci:build            # Host native build
vp run ci:cross-build      # Dry-run cross-build target matrix
vp run ci:publish-dry-run  # Dry-run package publish verification
```

### TypeScript Local CI Pipeline (`src/ci.ts`)

Instead of parsing YAML, local CI steps are orchestrated in a clean, executable TypeScript file (`src/ci.ts`):

```bash
# Run the local TypeScript CI pipeline script
npm run ci:local
```

### Direct Cross-Building (`build.mjs`)

`build.mjs` dynamically reads the target matrix from `napi.targets` in `package.json` and supports direct cross-building:

```bash
# Build for all targets listed in package.json napi.targets:
npm run ci:cross-build

# Dry-run cross-build configuration for all targets:
node build.mjs --target-all --dry-run

# Build for a specific target:
node build.mjs --target x86_64-unknown-linux-gnu --use-napi-cross
```

### Pre-Commit Hooks

Git pre-commit hooks are configured via `vite.config.ts` (`staged`). Whenever you commit code, `vp check src` automatically runs on staged files to guarantee code quality.
