import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseLockfile } from '../../src/lockfile/snapshot.js';
import { diffSnapshots, getChangedPackages } from '../../src/lockfile/diff.js';
import { createEngine } from '../../src/rules/engine.js';
import { getExitCode } from '../../src/report/formatter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, '..', 'fixtures', 'attacks', 'lockfile');

async function loadLockfile(name) {
  const raw = await readFile(join(FIXTURES, name), 'utf8');
  return parseLockfile(JSON.parse(raw));
}

function runPipeline(before, after, config = {}) {
  const diff = diffSnapshots(before, after);
  const changed = getChangedPackages(diff);
  return { diff, changed };
}

function findRule(evaluation, ruleId) {
  return evaluation.results.find((r) => r.ruleId === ruleId);
}

describe('Lockfile attack scenarios', () => {

  describe('Same-version republish', () => {
    it('detects same version with different integrity as an update', async () => {
      const before = await loadLockfile('same-version-republish-before.json');
      const after = await loadLockfile('same-version-republish-after.json');
      const { diff, changed } = runPipeline(before, after);

      // Should NOT be in "unchanged" — integrity differs
      assert.equal(diff.unchanged.size, 0, 'package should not be unchanged');
      // Should be detected as an update
      assert.equal(diff.updated.size, 1, 'should detect 1 updated package');
      assert.equal(diff.added.size, 0, 'should not be treated as added');

      const [, pkg] = [...changed][0];
      assert.equal(pkg.name, 'left-pad');
      assert.equal(pkg.version, '1.3.0');
      assert.equal(pkg.previousVersion, '1.3.0', 'previous version should match (same-version republish)');
      assert.equal(pkg.changeType, 'updated');
    });

    it('triggers integrity-mismatch when context flag is set', async () => {
      const before = await loadLockfile('same-version-republish-before.json');
      const after = await loadLockfile('same-version-republish-after.json');
      const { changed } = runPipeline(before, after);
      const engine = createEngine({});

      const [, pkg] = [...changed][0];
      // Simulate integrity verification failure (normally done by downloading the tarball)
      const context = { integrityMismatch: true };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(findRule(evaluation, 'integrity-mismatch'), 'should trigger integrity-mismatch');
      assert.equal(findRule(evaluation, 'integrity-mismatch').severity, 'block');
      assert.equal(getExitCode([evaluation]), 1, 'exit code should be 1 (blocked)');
    });
  });

  describe('Registry confusion (scope swap)', () => {
    it('detects unscoped package replacing a scoped package', async () => {
      const before = await loadLockfile('scope-swap-before.json');
      const after = await loadLockfile('scope-swap-after.json');
      const diff = diffSnapshots(before, after);

      // @myorg/utils should be removed, utils should be added
      assert.equal(diff.removed.size, 1, 'scoped package should be removed');
      assert.equal(diff.added.size, 1, 'unscoped package should be added');

      const removedPkg = [...diff.removed.values()][0];
      assert.equal(removedPkg.name, '@myorg/utils');

      const addedPkg = [...diff.added.values()][0];
      assert.equal(addedPkg.name, 'utils');
    });

    it('triggers scope-changed BLOCK rule', async () => {
      const before = await loadLockfile('scope-swap-before.json');
      const after = await loadLockfile('scope-swap-after.json');
      const diff = diffSnapshots(before, after);
      const changed = getChangedPackages(diff);
      const engine = createEngine({});

      // Build scope-changed detection (mirrors src/index.js logic)
      const removedScopedBareNames = new Set();
      for (const [, pkg] of diff.removed) {
        if (pkg.name.startsWith('@')) {
          removedScopedBareNames.add(pkg.name.split('/').pop());
        }
      }

      const [, pkg] = [...changed][0];
      const scopeChanged = !pkg.name.startsWith('@') &&
        pkg.changeType === 'added' &&
        removedScopedBareNames.has(pkg.name);

      const context = { isNew: true, scopeChanged };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(findRule(evaluation, 'scope-changed'), 'should trigger scope-changed');
      assert.equal(findRule(evaluation, 'scope-changed').severity, 'block');
      assert.equal(getExitCode([evaluation]), 1, 'exit code should be 1 (blocked)');
    });
  });

  describe('Registry source changed (dependency confusion)', () => {
    it('detects registry host change between versions', async () => {
      const before = await loadLockfile('registry-confusion-before.json');
      const after = await loadLockfile('registry-confusion-after.json');
      const { changed } = runPipeline(before, after);
      const engine = createEngine({});

      const [, pkg] = [...changed][0];
      assert.equal(pkg.name, 'internal-utils');
      assert.equal(pkg.changeType, 'updated');

      const context = {
        resolved: pkg.resolved,
        previousResolved: pkg.previousResolved,
      };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(findRule(evaluation, 'registry-source-changed'), 'should trigger registry-source-changed');
      assert.equal(findRule(evaluation, 'registry-source-changed').severity, 'block');
      assert.equal(getExitCode([evaluation]), 1, 'exit code should be 1 (blocked)');
    });

    it('confirms resolved URLs point to different hosts', async () => {
      const before = await loadLockfile('registry-confusion-before.json');
      const after = await loadLockfile('registry-confusion-after.json');
      const { changed } = runPipeline(before, after);

      const [, pkg] = [...changed][0];
      const currentHost = new URL(pkg.resolved).host;
      const previousHost = new URL(pkg.previousResolved).host;

      assert.equal(currentHost, 'registry.npmjs.org');
      assert.equal(previousHost, 'npm.internal.company.com');
      assert.notEqual(currentHost, previousHost);
    });
  });

  describe('Lockfile injection (SSRF via private IP)', () => {
    it('detects package resolved to private IP as unexpected registry', async () => {
      const before = await loadLockfile('lockfile-injection-before.json');
      const after = await loadLockfile('lockfile-injection-after.json');
      const { changed } = runPipeline(before, after);
      const engine = createEngine({
        registries: ['https://registry.npmjs.org'],
      });

      // Find the SSRF package
      let ssrfPkg;
      for (const [, pkg] of changed) {
        if (pkg.name === 'ssrf-pkg') ssrfPkg = pkg;
      }
      assert.ok(ssrfPkg, 'ssrf-pkg should be in changed packages');
      assert.equal(ssrfPkg.resolved, 'http://192.168.1.100:8080/ssrf-pkg/-/ssrf-pkg-1.0.0.tgz');

      const context = {
        isNew: true,
        resolved: ssrfPkg.resolved,
        registries: ['https://registry.npmjs.org'],
      };
      const evaluation = engine.evaluate(ssrfPkg, null, null, context);

      assert.ok(findRule(evaluation, 'unexpected-registry'), 'should trigger unexpected-registry');
      assert.equal(findRule(evaluation, 'unexpected-registry').severity, 'warn');
    });

    it('private IP host does not match any configured registry', async () => {
      const after = await loadLockfile('lockfile-injection-after.json');
      const ssrfEntry = [...after.values()].find((p) => p.name === 'ssrf-pkg');
      const host = new URL(ssrfEntry.resolved).host;

      assert.equal(host, '192.168.1.100:8080');
      assert.notEqual(host, 'registry.npmjs.org');
    });
  });

  describe('Combined lockfile attacks', () => {
    it('same-version republish + registry change produces multiple violations', async () => {
      // Simulate a package that changed both integrity AND registry host
      const engine = createEngine({
        registries: ['https://registry.npmjs.org'],
      });

      const pkg = {
        name: 'hijacked-lib',
        version: '2.0.0',
        previousVersion: '1.0.0',
        resolved: 'https://evil-mirror.example.com/hijacked-lib-2.0.0.tgz',
        previousResolved: 'https://registry.npmjs.org/hijacked-lib/-/hijacked-lib-1.0.0.tgz',
        changeType: 'updated',
      };

      const context = {
        resolved: pkg.resolved,
        previousResolved: pkg.previousResolved,
        registries: ['https://registry.npmjs.org'],
        integrityMismatch: true,
      };

      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(findRule(evaluation, 'registry-source-changed'), 'should trigger registry-source-changed');
      assert.ok(findRule(evaluation, 'unexpected-registry'), 'should trigger unexpected-registry');
      assert.ok(findRule(evaluation, 'integrity-mismatch'), 'should trigger integrity-mismatch');
      assert.equal(getExitCode([evaluation]), 1, 'should be blocked');

      // Count block-severity rules
      const blocks = evaluation.results.filter((r) => r.severity === 'block');
      assert.ok(blocks.length >= 2, 'should have at least 2 block-level violations');
    });
  });
});
