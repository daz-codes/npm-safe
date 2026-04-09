# CLAUDE.md — npm-safe

## Project Overview
Secure npm install wrapper CLI. Intercepts `npm install`, diffs lockfile changes, applies security rules, optionally sandboxes flagged packages in Docker, and reports/blocks suspicious behaviour.

## Commands
- `npm test` — run tests (unit: `src/**/*.test.js`)
- `node --test test/scenarios/*.test.js` — run attack scenario integration tests
- `npm run lint` — lint with eslint
- `node bin/npm-safe.js` — run CLI locally
- `node bin/npm-safe.js audit` — analysis only, no install
- `node bin/npm-safe.js approve <pkg@version>` — add to allowlist

## Code Conventions
- ES modules (`"type": "module"` in package.json)
- No TypeScript — plain JS for speed and simplicity
- Node 20+ required
- Prefer async/await over callbacks
- Use named exports, not default exports
- Error handling: throw descriptive errors, catch at CLI boundary only
- No classes unless managing stateful resources (e.g., Docker containers)
- Keep functions small and testable — max ~40 lines

## File Layout
- `bin/` — CLI entry points only, minimal logic
- `src/` — all business logic, organised by domain
- `src/lockfile/` — package-lock.json parsing and diffing
- `src/rules/` — rule definitions and evaluation engine
- `src/registry/` — npm registry API calls
- `src/sandbox/` — Docker sandbox lifecycle and monitoring
- `src/report/` — terminal output formatting
- `src/config/` — config file loading and merging
- `test/scenarios/` — attack scenario integration tests
- `test/fixtures/attacks/` — lockfile, strace, and registry attack fixtures

## Key Dependencies
- `commander` — CLI framework
- `chalk` — terminal colours
- `dockerode` — Docker API (Phase 2+)

## Rules System
- Rules are objects with `{ id, severity, description, check }` 
- `check` is a function returning truthy if rule triggers
- Severities: `block` (exit 1), `warn` (report but continue), `info`
- Users override via `.npm-safe.json`

## Exit Codes
- 0 = clean
- 1 = blocked (BLOCK-level rule fired)
- 2 = warnings only

## Testing
- Test framework: node:test (built-in, no deps)
- Test files: colocated as `*.test.js` next to source
- Integration tests: `test/scenarios/` (lockfile-attacks, registry-attacks, sandbox-attacks)
- Fixtures in `test/fixtures/`
- Use real npm registry responses as fixture data, not mocks of mocks

## Important Notes
- Always run `npm install --ignore-scripts` as the first step — never run package scripts without explicit approval
- Lockfile format: support both v2 and v3 (npm 7+ and 9+)
- Registry metadata: cache per-run in memory, don't hit registry repeatedly for same package
- Docker sandbox: `--network none` is non-negotiable
