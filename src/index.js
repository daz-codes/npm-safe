import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { takeSnapshot } from './lockfile/snapshot.js';
import { diffSnapshots, getChangedPackages } from './lockfile/diff.js';
import { verifyIntegrity } from './lockfile/integrity.js';
import { createEngine } from './rules/engine.js';
import { createRegistryClient } from './registry/metadata.js';
import { checkProvenance } from './registry/provenance.js';
import { checkTyposquat } from './rules/typosquat.js';
import { checkStarjacking } from './rules/starjacking.js';
import { snapshotNpmrc, verifyNpmrc } from './config/npmrc.js';
import { loadConfig } from './config/loader.js';
import { formatReport, getExitCode } from './report/formatter.js';
import { fetchWeeklyDownloads, isDormantPackage } from './registry/downloads.js';

const exec = promisify(execFile);

export async function runInstallAndAnalyse(projectDir = process.cwd(), args = [], { dryRun = false } = {}) {
  const config = await loadConfig(projectDir);

  // 1. Snapshot before
  let before;
  try {
    before = await takeSnapshot(projectDir);
  } catch {
    // No lockfile yet — empty baseline
    before = new Map();
  }

  // 2. Snapshot .npmrc files before install
  const npmrcBefore = await snapshotNpmrc(projectDir);

  // 3. Run npm install --ignore-scripts (lockfile-only in dry-run mode)
  // Reject npm flags in args to prevent --registry injection and similar attacks.
  // Only package specifiers (e.g. "lodash", "@scope/pkg@1.0.0") are allowed.
  for (const arg of args) {
    if (arg.startsWith('-')) {
      throw new Error(`npm flags are not allowed in package arguments: ${arg}`);
    }
  }

  const npmArgs = ['install', '--ignore-scripts'];
  if (dryRun) npmArgs.push('--package-lock-only');
  npmArgs.push(...args);

  await exec('npm', npmArgs, { cwd: projectDir, stdio: 'pipe' });

  // 4. Verify .npmrc was not tampered with
  const npmrcChanges = await verifyNpmrc(npmrcBefore);

  // 5. Snapshot after
  const after = await takeSnapshot(projectDir);

  // 6. Diff + analyse
  return analyse(before, after, config, projectDir, npmrcChanges);
}

export async function runAuditOnly(projectDir = process.cwd()) {
  const config = await loadConfig(projectDir);

  // Audit needs an existing lockfile — snapshot it against empty
  let current;
  try {
    current = await takeSnapshot(projectDir);
  } catch (err) {
    throw new Error(`Cannot audit: no package-lock.json found. ${err.message}`);
  }

  // Diff against empty to flag everything
  const empty = new Map();
  return analyse(empty, current, config, projectDir);
}

async function analyse(before, after, config, projectDir, npmrcChanges = []) {
  const diff = diffSnapshots(before, after);
  const changed = getChangedPackages(diff);

  if (changed.size === 0) {
    return { evaluations: [], diff, exitCode: 0, report: '\nNo package changes detected.\n', warnings: [] };
  }

  const engine = createEngine(config);
  const registry = createRegistryClient();
  const sandboxEnabled = config.sandbox?.enabled === true;
  const evaluations = [];

  // Lazy-load sandbox modules only when needed (avoids loading dockerode otherwise)
  let dockerClient = null;
  let parseStraceLog = null;
  let profileStore = null;
  let diffProfiles = null;
  let sandboxAvailable = false;
  if (sandboxEnabled) {
    try {
      const [dockerMod, monitorMod, profilesMod] = await Promise.all([
        import('./sandbox/docker.js'),
        import('./sandbox/monitor.js'),
        import('./sandbox/profiles.js'),
      ]);
      dockerClient = dockerMod.createDockerClient(config);
      // Verify Docker is reachable before proceeding
      await dockerClient.ensureImage();
      parseStraceLog = monitorMod.parseStraceLog;
      diffProfiles = profilesMod.diffProfiles;
      const profileDir = config.profiles?.directory || './profiles';
      profileStore = profilesMod.createProfileStore(profileDir);
      sandboxAvailable = true;
    } catch (err) {
      registry.warnings.push(
        `Sandbox unavailable: ${err.message}. ` +
        'Install Docker or set sandbox.enabled to false. Continuing without sandbox.'
      );
    }
  }

  // Build set of bare names for removed scoped packages (for scope-changed detection)
  const removedScopedBareNames = new Set();
  for (const [, pkg] of diff.removed) {
    if (pkg.name.startsWith('@')) {
      const bare = pkg.name.split('/').pop();
      removedScopedBareNames.add(bare);
    }
  }

  // Read top-level deps from package.json to determine transitive
  let directDeps = new Set();
  try {
    const pkgRaw = await readFile(join(projectDir, 'package.json'), 'utf8');
    const pkgJson = JSON.parse(pkgRaw);
    const allDirect = {
      ...pkgJson.dependencies,
      ...pkgJson.devDependencies,
    };
    directDeps = new Set(Object.keys(allDirect));
  } catch {
    // If we can't read package.json, treat all as direct
  }

  for (const [, pkg] of changed) {
    const meta = await registry.fetchVersionMetadata(pkg.name, pkg.version);

    let prevMeta = null;
    if (pkg.previousVersion) {
      prevMeta = await registry.fetchVersionMetadata(pkg.name, pkg.previousVersion);
    }

    // Phase 7: typosquat + starjacking (synchronous, no network)
    const typosquat = pkg.changeType === 'added' ? checkTyposquat(pkg.name) : null;
    const starjacking = meta ? checkStarjacking(pkg.name, meta) : null;

    // Phase 7: provenance (async, hits registry)
    let provenance = null;
    try {
      provenance = await checkProvenance(pkg.name, pkg.version, registry.warnings);
    } catch {
      // Non-fatal — provenance is best-effort
    }

    // Download anomaly detection
    const weeklyDownloads = pkg.changeType === 'added'
      ? await fetchWeeklyDownloads(pkg.name, registry.warnings)
      : null;

    // Dormancy detection — check if long gap since last publish
    let dormant = false;
    if (pkg.changeType === 'updated') {
      const fullMeta = await registry.fetchMetadata(pkg.name);
      if (fullMeta) dormant = isDormantPackage(fullMeta, pkg.version);
    }

    // Scope-changed detection — unscoped package replaces a scoped one with the same bare name
    const isUnscoped = !pkg.name.startsWith('@');
    const scopeChanged = isUnscoped && pkg.changeType === 'added' && removedScopedBareNames.has(pkg.name);

    const context = {
      isNew: pkg.changeType === 'added',
      isTransitive: !directDeps.has(pkg.name),
      resolved: pkg.resolved || null,
      previousResolved: pkg.previousResolved || null,
      registries: config.registries || null,
      integrityMismatch: false, // set after integrity verification pass
      typosquat,
      provenance,
      starjacking,
      weeklyDownloads,
      dormant,
      scopeChanged,
      sandboxResult: null,
      profileDiff: null,
    };

    // Sandbox flagged packages (those with install scripts)
    if (sandboxAvailable && needsSandbox(pkg, meta)) {
      try {
        const raw = await dockerClient.runSandbox(pkg.name, pkg.version);
        context.sandboxResult = parseStraceLog(raw.straceLog);

        // Attach file count from sandbox output for size tracking
        const fileCount = raw.fileList.split('\n').filter(Boolean).length;
        context.sandboxResult.fileCount = fileCount;

        // Load previous profile before saving current (avoids comparing against self)
        const prevProfile = await profileStore.loadPreviousProfile(pkg.name, pkg.version);
        await profileStore.saveProfile(pkg.name, pkg.version, context.sandboxResult);
        if (prevProfile) {
          context.profileDiff = diffProfiles(prevProfile, context.sandboxResult);
        }
      } catch (err) {
        registry.warnings.push(`Sandbox failed for ${pkg.name}@${pkg.version}: ${err.message}`);
      }
    }

    const evaluation = engine.evaluate(pkg, meta, prevMeta, context);
    evaluations.push(evaluation);
  }

  // Phase 7: Lockfile integrity verification (downloads tarballs — do after main loop)
  // Only verify changed packages, not the entire lockfile
  const changedSnapshot = new Map();
  for (const [key, pkg] of changed) changedSnapshot.set(key, pkg);
  const integrityMismatches = await verifyIntegrity(changedSnapshot, registry.warnings);

  // Mark mismatched packages and re-evaluate through the engine so config overrides apply
  const mismatchNames = new Set(integrityMismatches.map((m) => `${m.name}@${m.version}`));
  for (const ev of evaluations) {
    const key = `${ev.package.name}@${ev.package.version}`;
    if (mismatchNames.has(key)) {
      const mismatch = integrityMismatches.find((m) => `${m.name}@${m.version}` === key);
      const ctx = { integrityMismatch: true };
      const result = engine.evaluate(ev.package, null, null, ctx);
      const integrityResult = result.results.find((r) => r.ruleId === 'integrity-mismatch');
      if (integrityResult) {
        integrityResult.description = `Tarball hash mismatch: expected ${mismatch.expected}, got ${mismatch.actual}`;
        ev.results.push(integrityResult);
      }
    }
  }

  // Flag npmrc tampering
  for (const change of npmrcChanges) {
    registry.warnings.push(`BLOCK: .npmrc ${change.type} at ${change.path}`);
    evaluations.push({
      package: { name: '.npmrc', version: change.path, changeType: change.type },
      results: [{
        ruleId: 'npmrc-tampered',
        severity: 'block',
        description: `.npmrc file ${change.type} at ${change.path}`,
      }],
      skipped: false,
      profileDiff: null,
    });
  }

  const report = formatReport(evaluations, registry.warnings);
  const exitCode = getExitCode(evaluations);

  return { evaluations, diff, exitCode, report, warnings: registry.warnings };
}

function needsSandbox(pkg, meta) {
  return pkg.hasScripts ||
    meta?.scripts?.preinstall ||
    meta?.scripts?.install ||
    meta?.scripts?.postinstall;
}
