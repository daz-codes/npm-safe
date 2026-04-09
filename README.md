# npm-safe

A security-first wrapper around `npm install`. Analyses every package before it touches your `node_modules`.

Instead of blindly installing whatever npm resolves, `npm-safe` diffs the lockfile, checks 29 security rules, and shows you what's about to happen — **before** anything is installed.

```
npm-safe install express
```

```
🔒 npm-safe report

⚠️  WARNINGS
  ms 2.1.3
    ⚠️  WARN New transitive dependency introduced
    ⚠️  WARN Package name is suspiciously similar to a popular package
    ℹ️  INFO Package has no SLSA provenance attestation
  ...

✅ 1 package(s) clean

⚠️  64 warnings  ✅ 1 clean

🔶 Proceed with install? [y/N]
```

## Why

npm's default behaviour is to download, extract, and **run install scripts** for every package in your dependency tree. A single compromised package can exfiltrate credentials, install backdoors, or mine crypto — all before you see a single line of output.

`npm-safe` flips this: **analyse first, install second**.

## Install

```bash
npm install -g npm-safe
```

Requires Node 20+.

## Usage

### Install packages

```bash
# Interactive — analyses, shows report, prompts before installing
npm-safe install axios

# Install multiple packages
npm-safe install express lodash chalk
```

### Analyse without installing

```bash
# Dry run — update lockfile and report, but don't install
npm-safe install axios --dry-run

# Audit existing lockfile (no install at all)
npm-safe audit
```

### CI / automation

```bash
# CI mode — no prompts, installs unless blocked, exit 0 on warnings
npm-safe install --ci

# Auto-yes — no prompts, but still exit 2 on warnings
npm-safe install --yes

# JSON output for parsing
npm-safe install --format json --ci
```

### Approve reviewed packages

```bash
# Add to allowlist (skips all rules for this package)
npm-safe approve lodash@*
npm-safe approve esbuild@0.19.0

# Approve and run install scripts for a reviewed package
npm-safe run-scripts esbuild@0.19.0
```

### Safe npx

```bash
# Analyse a package before executing it
npx-safe cowsay "hello"
```

## How it works

1. **Lockfile-only install** — runs `npm install --ignore-scripts --package-lock-only` to resolve dependencies without touching `node_modules`
2. **Diff** — compares the lockfile before and after to find added, updated, and removed packages
3. **Analyse** — runs every changed package through 29 security rules, checking registry metadata, lockfile integrity, and optionally sandboxing in Docker
4. **Report** — shows findings with severity levels (BLOCK, WARN, INFO)
5. **Prompt** — asks for confirmation before proceeding (unless `--ci` or `--yes`)
6. **Install** — if approved, runs `npm install --ignore-scripts` to actually install
7. **Revert** — if blocked or declined, restores the original lockfile

Install scripts are **never** run automatically. Use `npm-safe run-scripts <pkg@version>` to explicitly approve and execute them after review.

## Security rules

29 built-in rules across six categories:

### Lifecycle scripts
| Rule | Severity | Description |
|------|----------|-------------|
| `no-install-scripts` | BLOCK | Package defines install/uninstall lifecycle hooks |

### Supply chain integrity
| Rule | Severity | Description |
|------|----------|-------------|
| `integrity-mismatch` | BLOCK | Tarball hash doesn't match lockfile |
| `registry-source-changed` | BLOCK | Package resolved from a different registry than before |
| `scope-changed` | BLOCK | Unscoped package replaced a scoped one (dependency confusion) |
| `unexpected-registry` | WARN | Package resolved outside configured registries |

### Package metadata
| Rule | Severity | Description |
|------|----------|-------------|
| `maintainer-changed` | WARN | A previous maintainer was removed |
| `maintainer-added` | INFO | New maintainer added |
| `rapid-publish` | WARN | Multiple versions published within 24 hours |
| `version-gap` | WARN | Unexpected version number jump |
| `no-repository` | WARN | No repository field in registry metadata |
| `no-license` | WARN | No license declared |
| `recent-release` | WARN | Published less than 7 days ago |

### Reputation signals
| Rule | Severity | Description |
|------|----------|-------------|
| `typosquat-suspect` | WARN | Name suspiciously similar to a popular package |
| `starjacking-suspect` | WARN | Claims a popular GitHub repo it doesn't belong to |
| `no-provenance` | INFO | No SLSA provenance attestation |
| `low-download-count` | WARN | New package with < 100 weekly downloads |
| `dormant-package` | WARN | No releases for 1+ year before this version |
| `new-transitive-dep` | WARN | New transitive dependency introduced |

### Sandbox runtime (requires Docker)
| Rule | Severity | Description |
|------|----------|-------------|
| `sandbox-network-attempt` | BLOCK | Network access during install |
| `sandbox-unexpected-process` | WARN | Unexpected process spawned |
| `sandbox-file-write-outside-modules` | BLOCK | File writes outside node_modules |
| `sandbox-npmrc-write` | BLOCK | Attempted to write .npmrc |

### Behaviour diff (compares versions)
| Rule | Severity | Description |
|------|----------|-------------|
| `behaviour-diff-new-network` | BLOCK | New network endpoints vs previous version |
| `behaviour-diff-new-process` | WARN | New processes spawned vs previous version |
| `behaviour-diff-new-file-write` | BLOCK | New file writes outside modules vs previous version |
| `behaviour-diff-size-change` | WARN | Install size changed by > 2x or < 50% |

## Configuration

Create a `.npm-safe.json` in your project root:

```json
{
  "allowlist": [
    "lodash@*",
    "esbuild@0.19.0"
  ],
  "rules": {
    "no-provenance": { "enabled": false },
    "new-transitive-dep": { "severity": "info" },
    "no-install-scripts": { "severity": "warn" }
  },
  "registries": [
    "https://registry.npmjs.org",
    "https://npm.internal.company.com"
  ],
  "sandbox": {
    "enabled": true,
    "timeout": 60,
    "memoryLimit": "256m",
    "cpuLimit": 0.5
  }
}
```

### Rule overrides

Every rule can be:
- **Disabled**: `{ "enabled": false }`
- **Downgraded**: `{ "severity": "info" }` (block → warn → info)
- **Upgraded**: `{ "severity": "block" }` (warn → block)

### Allowlist

Packages matching the allowlist skip all rules:
- `"lodash@4.17.21"` — exact version
- `"lodash@*"` — any version
- `"lodash"` — any version (shorthand)

## Exit codes

| Code | Meaning | CI behaviour |
|------|---------|-------------|
| 0 | Clean | Pass |
| 1 | Blocked — a BLOCK-level rule fired | Fail |
| 2 | Warnings only | Pass with `--ci`, fail otherwise |
| 3 | Tool error | Fail |

## Docker sandbox

When `sandbox.enabled` is true and Docker is available, packages with install scripts are executed in an isolated container with:

- **No network** (`--network none`)
- **Read-only filesystem** (except `/tmp` and `~/.npm`)
- **Memory and CPU limits**
- **Non-root user**
- **strace monitoring** — tracks every network connection, file write, and process spawn

The sandbox results are compared against previous versions to detect behavioural changes (new network endpoints, new file writes, etc.).

If Docker isn't available, the tool continues without sandboxing and logs a warning.

## License

MIT
