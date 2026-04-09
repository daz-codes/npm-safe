# safe-install — Secure npm Install Wrapper

## What This Is

A CLI tool (`safe-install`) that wraps `npm install` to catch suspicious package behaviour before it hits your project. It intercepts dependency changes, applies security rules, sandboxes flagged packages in Docker, and diffs behaviour between versions.

**It won't catch everything.** The goal is to flag the obvious and suspicious, then ask for human approval before proceeding.

## Tech Stack

- **Node.js** (ES modules, no TypeScript for MVP — keep it lean)
- **Docker** via `dockerode` for sandboxing
- **strace** inside containers for syscall monitoring
- **Commander.js** for CLI
- **chalk** for terminal output

## Architecture

```
safe-install <args>
    │
    ├─ 1. Snapshot current package-lock.json
    ├─ 2. Run `npm install --ignore-scripts` (dry-run style)
    ├─ 3. Diff package-lock.json → identify new/changed packages
    ├─ 4. Apply static rules to each changed package
    │     ├─ Has install scripts? → FLAG
    │     ├─ New transitive dep? → FLAG
    │     ├─ No repository field? → FLAG
    │     ├─ Maintainer changed? → FLAG (if npm registry metadata available)
    │     └─ Pass → ALLOW
    ├─ 5. Flagged packages → Docker sandbox analysis
    │     ├─ Install in isolated container (--network none)
    │     ├─ Monitor with strace: network, file writes, process spawning
    │     └─ Compare against behaviour profile of previous version
    ├─ 6. Generate report
    │     ├─ BLOCK: definite policy violations
    │     ├─ WARN: suspicious but inconclusive
    │     └─ ALLOW: clean
    └─ 7. Prompt for approval or auto-block based on config
```

## Project Structure

```
safe-install/
├── bin/
│   └── safe-install.js          # CLI entry point
├── src/
│   ├── index.js                 # Main orchestrator
│   ├── lockfile/
│   │   ├── snapshot.js           # Read + parse package-lock.json
│   │   └── diff.js               # Diff two lockfile snapshots
│   ├── rules/
│   │   ├── engine.js             # Rule evaluation engine
│   │   └── defaults.js           # Default rule definitions
│   ├── registry/
│   │   └── metadata.js           # Fetch npm registry metadata
│   ├── sandbox/
│   │   ├── docker.js             # Docker container lifecycle via dockerode
│   │   ├── monitor.js            # Parse strace output
│   │   └── profiles.js           # Store/load behaviour profiles
│   ├── report/
│   │   └── formatter.js          # Terminal report output
│   └── config/
│       └── loader.js             # Load .safe-install.json config
├── profiles/                     # Stored behaviour profiles (gitignored)
├── sandbox/
│   └── Dockerfile                # Sandbox container image
├── .safe-install.json            # Project-level config
├── package.json
└── README.md
```

## Phase 1 — Static Analysis CLI (Build First)

This is the MVP. No Docker, no sandboxing. Just lockfile diffing and rule checking.

### What to build:

1. **`bin/safe-install.js`** — CLI entry point using Commander
   - `safe-install` (default: runs install + analysis)
   - `safe-install audit` (analysis only, no install)
   - `safe-install approve <package@version>` (add to allowlist)

2. **`src/lockfile/snapshot.js`** — Parse package-lock.json (v2/v3 format)
   - Return a map of `{ name@version: { version, resolved, integrity, hasScripts, dependencies } }`

3. **`src/lockfile/diff.js`** — Compare two snapshots
   - Categorise: added, removed, updated, unchanged
   - For updated: include old and new version

4. **`src/rules/defaults.js`** — Default rules as objects:
   ```js
   export const defaultRules = [
     {
       id: 'no-install-scripts',
       severity: 'block',
       description: 'Package defines install/postinstall/preinstall scripts',
       check: (pkg, meta) => meta?.scripts?.preinstall || meta?.scripts?.install || meta?.scripts?.postinstall
     },
     {
       id: 'no-repository',
       severity: 'warn',
       description: 'Package has no repository field in registry metadata',
       check: (pkg, meta) => !meta?.repository
     },
     {
       id: 'new-transitive-dep',
       severity: 'warn',
       description: 'New transitive dependency introduced',
       check: (pkg, context) => context.isTransitive && context.isNew
     },
     {
       id: 'maintainer-changed',
       severity: 'warn',
       description: 'Package maintainer changed between versions',
       check: (pkg, meta, prevMeta) => {
         // Compare maintainer lists
       }
     }
   ]
   ```

5. **`src/rules/engine.js`** — Run all rules against a package, return results

6. **`src/registry/metadata.js`** — Fetch from `https://registry.npmjs.org/<pkg>/<version>`
   - Extract: scripts, repository, maintainers, dist info
   - Cache responses locally during a run

7. **`src/report/formatter.js`** — Pretty terminal output
   - Group by severity (BLOCK / WARN / ALLOW)
   - Show package name, version change, which rules triggered
   - Summary line at the end

8. **`src/config/loader.js`** — Load `.safe-install.json`:
   ```json
   {
     "allowlist": ["esbuild@0.19.0", "sharp@*"],
     "rules": {
       "no-install-scripts": { "severity": "warn" },
       "no-repository": { "enabled": false }
     },
     "autoApprove": false
   }
   ```

### Phase 1 acceptance criteria:
- Running `safe-install` in a project with a package.json diffs the lockfile, checks rules, and prints a report
- Packages on the allowlist skip rule checks
- Exit code 1 if any BLOCK-level rules fire
- Exit code 0 otherwise

## Phase 2 — Docker Sandbox

### What to build:

1. **`sandbox/Dockerfile`**:
   ```dockerfile
   FROM node:20-slim
   RUN apt-get update && apt-get install -y strace
   WORKDIR /sandbox
   ```

2. **`src/sandbox/docker.js`** — Using dockerode:
   - Build sandbox image if not present
   - Create container with: `--network none`, read-only root fs (except /sandbox), resource limits
   - Copy tarball of flagged package into container
   - Run `npm install` inside container with strace wrapper
   - Collect strace output
   - Destroy container

3. **`src/sandbox/monitor.js`** — Parse strace output:
   - Network syscalls: `connect`, `sendto`, `socket` → extract IPs/ports
   - File writes: `openat` with write flags, `write` → extract paths
   - Process spawning: `execve`, `clone` → extract commands
   - Return structured behaviour profile

4. **`src/sandbox/profiles.js`**:
   - Save behaviour profiles to `profiles/<package>/<version>.json`
   - Load previous version profile for comparison
   - Diff two profiles: new network calls, new file writes, new processes

### Sandbox rules (extend `defaults.js`):
```js
{
  id: 'sandbox-network-attempt',
  severity: 'block',
  description: 'Package attempted network access during install',
  check: (pkg, meta, prevMeta, sandboxResult) => sandboxResult?.network?.length > 0
},
{
  id: 'sandbox-unexpected-process',
  severity: 'warn',
  description: 'Package spawned unexpected process during install',
  check: (pkg, meta, prevMeta, sandboxResult) => {
    const allowed = ['node', 'npm', 'sh', 'node-gyp'];
    return sandboxResult?.processes?.some(p => !allowed.includes(p.command));
  }
}
```

## Phase 3 — Behavioural Diffing

### What to build:

1. Extend `src/sandbox/profiles.js` with a `diffProfiles(prev, current)` function
2. Flag significant changes:
   - New network endpoints that didn't exist in prior version
   - New file writes outside node_modules
   - New child processes
   - Significant size changes in installed output
3. Add to report: "Behaviour diff: v1.2.3 → v1.2.4"

## Phase 4 — CI Integration

### What to build:

1. **GitHub Action** (`action.yml`):
   - Runs `safe-install audit` on PR
   - Posts comment with report
   - Blocks merge if BLOCK rules fire
   - Stores profiles as artifacts for future diffs

2. **Renovate integration**:
   - `postUpgradeTasks` hook to run safe-install
   - Auto-approve if all rules pass + no sandbox flags

## Phase 5 — Threat Coverage Hardening

Closes gaps identified in `THREATS.md` against known npm attack techniques.

### What to build:

1. **Dependency confusion detection** — new rules in `defaults.js`:
   ```js
   {
     id: 'registry-source-changed',
     severity: 'block',
     description: 'Package resolved URL points to a different registry than before',
     check: (pkg) => {
       // Compare resolved URL host between previous and current version
     }
   },
   {
     id: 'unexpected-registry',
     severity: 'warn',
     description: 'Package resolves outside configured registries',
     check: (pkg, meta, prevMeta, context) => {
       // Check resolved URL against allowlisted registry hosts in config
     }
   }
   ```

2. **Extended lifecycle script detection** — update `no-install-scripts` rule:
   - Also check `preuninstall` and `uninstall` scripts
   - These can execute arbitrary commands during `npm uninstall`

3. **`.npmrc` integrity checking** — new module `src/config/npmrc.js`:
   - Snapshot `.npmrc` (project-level and user-level) before install
   - After install, verify no changes were made
   - Dedicated `npmrc-tampered` rule (BLOCK)
   - In sandbox mode: specific rule for `.npmrc` write attempts

4. **Enhanced maintainer analysis** — extend `maintainer-changed` rule:
   - Flag new maintainers added (INFO severity — not necessarily malicious)
   - `rapid-publish` rule — warn when multiple versions published in a short time window
   - `version-gap` rule — warn when version number jumps unexpectedly (e.g. 1.2.3 → 9.0.0)

5. **Script approval workflow** — new CLI command:
   - `safe-install run-scripts <pkg@version>` — explicitly approve and run install scripts for a reviewed package
   - Records approval in `.safe-install.json` with timestamp and approver

6. **Config extensions** — extend `.safe-install.json`:
   ```json
   {
     "registries": ["https://registry.npmjs.org"],
     "scriptApprovals": {
       "esbuild@0.19.0": { "approved": "2024-03-15", "by": "alice" }
     }
   }
   ```

### Phase 5 acceptance criteria:
- Dependency confusion attacks detected by registry URL diffing
- All lifecycle scripts (including uninstall) flagged
- `.npmrc` changes during install are blocked
- Maintainer additions surfaced in report
- Rapid-publish and version-gap patterns detected

## Phase 6 — npx Wrapper

Extends protection to `npx`, which downloads and executes packages without installation.

### What to build:

1. **`bin/safe-npx.js`** — CLI wrapper for npx:
   - Intercepts `npx <pkg>` invocations
   - Fetches registry metadata for the target package
   - Runs Phase 1 static analysis (install scripts, repository, maintainers)
   - Checks against allowlist in `.safe-install.json`
   - If clean or allowlisted: proxies to real `npx`
   - If flagged: blocks with report, suggests `safe-install approve`

2. **npx allowlist policy** — extend config:
   ```json
   {
     "npx": {
       "allowlist": ["typescript@*", "eslint@*"],
       "blockUnknown": true
     }
   }
   ```

3. **npx audit logging** — `src/npx/logger.js`:
   - Log every npx invocation with package name, version, timestamp
   - Store in `.safe-install-npx.log` for audit trail
   - Optional: warn if a package was last audited more than N days ago

### Phase 6 acceptance criteria:
- `safe-npx <pkg>` performs static analysis before execution
- Unknown packages are blocked when `blockUnknown: true`
- Allowlisted packages execute without delay
- Audit log records all npx invocations

## Phase 7 — Lockfile Integrity & Advanced Heuristics

### What to build:

1. **Lockfile integrity verification**:
   - Verify `integrity` hashes in package-lock.json match actual downloaded tarballs
   - Detect lockfile injection attacks where integrity hashes are modified

2. **Typosquat detection** — `src/rules/typosquat.js`:
   - Compare new package names against popular packages using edit distance
   - Flag `lod-ash`, `lodassh`, `lodas` when `lodash` exists
   - Maintain a list of top-1000 npm packages for comparison

3. **Provenance verification**:
   - Check npm package provenance attestations (npm's `--provenance` feature)
   - Flag packages without provenance when coming from repos that support it

4. **Starjacking detection**:
   - Compare repository URL in package metadata against actual GitHub repo
   - Flag when repository field points to a popular project the package isn't affiliated with

## Key Design Decisions

- **`--ignore-scripts` first, always.** The real install never runs scripts unless explicitly approved.
- **Registry metadata is fetched, not assumed.** Don't trust lockfile alone — check the registry for scripts, maintainers, etc.
- **Profiles are stored per-project.** Different projects may use different versions, and the same package may behave differently depending on peer deps.
- **Rules are data, not code.** The default rules are objects with check functions. Users override severity or disable via config, not by editing source.
- **Exit codes matter.** CI integration depends on clean exit codes: 0 = safe, 1 = blocked, 2 = warnings.

## Getting Started (for development)

```bash
mkdir safe-install && cd safe-install
npm init -y
npm install commander chalk dockerode
```

Start with Phase 1. Get the lockfile diff and static rules working before touching Docker.

## Testing Strategy

- Unit test each rule against fixture package metadata
- Integration test: create a temp project, add a known-bad package, verify it flags
- Sandbox tests: mock dockerode or use a real Docker daemon in CI
- Use `verdaccio` (local npm registry) for reproducible install tests
