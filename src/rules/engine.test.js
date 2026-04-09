import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createEngine } from './engine.js';

describe('rules engine', () => {
  it('flags packages with install scripts', () => {
    const engine = createEngine();
    const pkg = { name: 'bad-pkg', version: '1.0.0' };
    const meta = { scripts: { postinstall: 'node exploit.js' } };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'no-install-scripts');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'block');
  });

  it('flags packages with no repository', () => {
    const engine = createEngine();
    const pkg = { name: 'no-repo', version: '1.0.0' };
    const meta = { scripts: {}, repository: null };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'no-repository');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'warn');
  });

  it('does not flag no-repository when meta is null (registry unreachable)', () => {
    const engine = createEngine();
    const pkg = { name: 'offline-pkg', version: '1.0.0' };

    const result = engine.evaluate(pkg, null, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'no-repository');
    assert.equal(triggered, undefined);
  });

  it('flags new transitive dependencies', () => {
    const engine = createEngine();
    const pkg = { name: 'transitive', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { isTransitive: true, isNew: true };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'new-transitive-dep');
    assert.ok(triggered);
  });

  it('flags maintainer changes', () => {
    const engine = createEngine();
    const pkg = { name: 'pkg', version: '2.0.0' };
    const meta = {
      scripts: {},
      repository: { url: 'https://github.com/a/b' },
      maintainers: [{ name: 'new-person' }],
    };
    const prevMeta = {
      maintainers: [{ name: 'original-author' }],
    };

    const result = engine.evaluate(pkg, meta, prevMeta, {});
    const triggered = result.results.find((r) => r.ruleId === 'maintainer-changed');
    assert.ok(triggered);
  });

  it('skips allowlisted packages', () => {
    const engine = createEngine({ allowlist: ['bad-pkg@1.0.0'] });
    const pkg = { name: 'bad-pkg', version: '1.0.0' };
    const meta = { scripts: { postinstall: 'node exploit.js' } };

    const result = engine.evaluate(pkg, meta, null, {});
    assert.equal(result.skipped, true);
    assert.equal(result.results.length, 0);
  });

  it('supports wildcard allowlist entries', () => {
    const engine = createEngine({ allowlist: ['bad-pkg@*'] });
    const pkg = { name: 'bad-pkg', version: '9.9.9' };
    const meta = { scripts: { postinstall: 'node exploit.js' } };

    const result = engine.evaluate(pkg, meta, null, {});
    assert.equal(result.skipped, true);
  });

  it('respects rule severity overrides', () => {
    const engine = createEngine({
      rules: { 'no-install-scripts': { severity: 'warn' } },
    });
    const pkg = { name: 'pkg', version: '1.0.0' };
    const meta = { scripts: { postinstall: 'echo hi' } };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'no-install-scripts');
    assert.equal(triggered.severity, 'warn');
  });

  it('disables rules when enabled is false', () => {
    const engine = createEngine({
      rules: { 'no-repository': { enabled: false } },
    });
    const pkg = { name: 'no-repo', version: '1.0.0' };
    const meta = { scripts: {}, repository: null };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'no-repository');
    assert.equal(triggered, undefined);
  });

  it('returns clean result for safe package', () => {
    const engine = createEngine();
    const pkg = { name: 'safe', version: '1.0.0' };
    const meta = {
      scripts: {},
      repository: { url: 'https://github.com/a/b' },
      maintainers: [{ name: 'alice' }],
      license: 'MIT',
    };

    const result = engine.evaluate(pkg, meta, null, { isTransitive: false, isNew: true });
    assert.equal(result.results.length, 0);
    assert.equal(result.skipped, false);
  });

  it('blocks sandbox network attempts', () => {
    const engine = createEngine();
    const pkg = { name: 'net-pkg', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      sandboxResult: {
        network: [{ syscall: 'connect', address: '93.184.216.34', port: 443 }],
        fileWrites: [],
        processes: [],
      },
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'sandbox-network-attempt');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'block');
  });

  it('warns on unexpected sandbox processes', () => {
    const engine = createEngine();
    const pkg = { name: 'proc-pkg', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      sandboxResult: {
        network: [],
        fileWrites: [],
        processes: [
          { command: 'node', executable: '/usr/bin/node' },
          { command: 'curl', executable: '/usr/bin/curl' },
        ],
      },
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'sandbox-unexpected-process');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'warn');
  });

  it('does not warn when sandbox processes are all allowed', () => {
    const engine = createEngine();
    const pkg = { name: 'ok-pkg', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      sandboxResult: {
        network: [],
        fileWrites: [],
        processes: [
          { command: 'node', executable: '/usr/bin/node' },
          { command: 'sh', executable: '/bin/sh' },
          { command: 'npm', executable: '/usr/local/bin/npm' },
        ],
      },
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'sandbox-unexpected-process');
    assert.equal(triggered, undefined);
  });

  it('blocks file writes outside node_modules', () => {
    const engine = createEngine();
    const pkg = { name: 'write-pkg', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      sandboxResult: {
        network: [],
        fileWrites: [{ path: '/tmp/evil' }],
        processes: [],
      },
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'sandbox-file-write-outside-modules');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'block');
  });

  it('allows file writes inside sandbox node_modules', () => {
    const engine = createEngine();
    const pkg = { name: 'ok-write', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      sandboxResult: {
        network: [],
        fileWrites: [{ path: '/sandbox/node_modules/ok-write/data.json' }],
        processes: [],
      },
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'sandbox-file-write-outside-modules');
    assert.equal(triggered, undefined);
  });

  it('does not trigger sandbox rules when no sandbox result', () => {
    const engine = createEngine();
    const pkg = { name: 'no-sandbox', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { sandboxResult: null };

    const result = engine.evaluate(pkg, meta, null, context);
    const sandboxRules = result.results.filter((r) => r.ruleId.startsWith('sandbox-'));
    assert.equal(sandboxRules.length, 0);
  });

  it('blocks on new network endpoints in behaviour diff', () => {
    const engine = createEngine();
    const pkg = { name: 'diff-pkg', version: '2.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      profileDiff: {
        hasChanges: true,
        newNetwork: [{ address: '10.0.0.1', port: 4444 }],
        newFileWrites: [],
        newProcesses: [],
        sizeChange: null,
      },
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'behaviour-diff-new-network');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'block');
  });

  it('warns on new processes in behaviour diff', () => {
    const engine = createEngine();
    const pkg = { name: 'diff-pkg', version: '2.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      profileDiff: {
        hasChanges: true,
        newNetwork: [],
        newFileWrites: [],
        newProcesses: [{ command: 'wget' }],
        sizeChange: null,
      },
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'behaviour-diff-new-process');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'warn');
  });

  it('blocks on new file writes outside node_modules in behaviour diff', () => {
    const engine = createEngine();
    const pkg = { name: 'diff-pkg', version: '2.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      profileDiff: {
        hasChanges: true,
        newNetwork: [],
        newFileWrites: [{ path: '/etc/crontab' }],
        newProcesses: [],
        sizeChange: null,
      },
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'behaviour-diff-new-file-write');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'block');
  });

  it('warns on significant size change in behaviour diff', () => {
    const engine = createEngine();
    const pkg = { name: 'bloat-pkg', version: '2.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      profileDiff: {
        hasChanges: true,
        newNetwork: [],
        newFileWrites: [],
        newProcesses: [],
        sizeChange: { before: 50, after: 500, ratio: 10 },
      },
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'behaviour-diff-size-change');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'warn');
  });

  it('does not trigger behaviour-diff rules when no profileDiff', () => {
    const engine = createEngine();
    const pkg = { name: 'no-diff', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { profileDiff: null };

    const result = engine.evaluate(pkg, meta, null, context);
    const diffRules = result.results.filter((r) => r.ruleId.startsWith('behaviour-diff-'));
    assert.equal(diffRules.length, 0);
  });

  it('passes profileDiff through to evaluation result', () => {
    const engine = createEngine();
    const pkg = { name: 'pkg', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const profileDiff = {
      hasChanges: true,
      newNetwork: [{ address: '1.2.3.4', port: 80 }],
      newFileWrites: [],
      newProcesses: [],
      sizeChange: null,
    };

    const result = engine.evaluate(pkg, meta, null, { profileDiff });
    assert.deepEqual(result.profileDiff, profileDiff);
  });

  // --- Phase 5 rules ---

  it('detects lifecycle scripts including uninstall hooks', () => {
    const engine = createEngine();
    const pkg = { name: 'uninstall-pkg', version: '1.0.0' };
    const meta = { scripts: { preuninstall: 'rm -rf /' }, repository: { url: 'https://github.com/a/b' } };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'no-install-scripts');
    assert.ok(triggered);
  });

  it('blocks when registry source changes', () => {
    const engine = createEngine();
    const pkg = { name: 'confused', version: '2.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      resolved: 'https://registry.npmjs.org/confused/-/confused-2.0.0.tgz',
      previousResolved: 'https://private.registry.com/confused/-/confused-1.0.0.tgz',
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'registry-source-changed');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'block');
  });

  it('does not flag registry-source-changed for same host', () => {
    const engine = createEngine();
    const pkg = { name: 'ok-pkg', version: '2.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      resolved: 'https://registry.npmjs.org/ok/-/ok-2.0.0.tgz',
      previousResolved: 'https://registry.npmjs.org/ok/-/ok-1.0.0.tgz',
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'registry-source-changed');
    assert.equal(triggered, undefined);
  });

  it('warns when package resolves outside configured registries', () => {
    const engine = createEngine();
    const pkg = { name: 'rogue', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      resolved: 'https://evil-registry.com/rogue/-/rogue-1.0.0.tgz',
      registries: ['https://registry.npmjs.org'],
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'unexpected-registry');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'warn');
  });

  it('does not trigger unexpected-registry when no registries configured', () => {
    const engine = createEngine();
    const pkg = { name: 'ok', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      resolved: 'https://anything.com/ok.tgz',
      registries: null,
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'unexpected-registry');
    assert.equal(triggered, undefined);
  });

  it('flags new maintainer added', () => {
    const engine = createEngine();
    const pkg = { name: 'pkg', version: '2.0.0' };
    const meta = {
      scripts: {},
      repository: { url: 'https://github.com/a/b' },
      maintainers: [{ name: 'alice' }, { name: 'bob' }],
    };
    const prevMeta = {
      maintainers: [{ name: 'alice' }],
    };

    const result = engine.evaluate(pkg, meta, prevMeta, {});
    const triggered = result.results.find((r) => r.ruleId === 'maintainer-added');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'info');
  });

  it('warns on rapid publish', () => {
    const engine = createEngine();
    const pkg = { name: 'rapid', version: '1.0.1' };
    const now = new Date();
    const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' }, time: now.toISOString() };
    const prevMeta = { time: hourAgo.toISOString() };

    const result = engine.evaluate(pkg, meta, prevMeta, {});
    const triggered = result.results.find((r) => r.ruleId === 'rapid-publish');
    assert.ok(triggered);
  });

  it('does not flag rapid-publish when versions are days apart', () => {
    const engine = createEngine();
    const pkg = { name: 'slow', version: '1.0.1' };
    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' }, time: now.toISOString() };
    const prevMeta = { time: weekAgo.toISOString() };

    const result = engine.evaluate(pkg, meta, prevMeta, {});
    const triggered = result.results.find((r) => r.ruleId === 'rapid-publish');
    assert.equal(triggered, undefined);
  });

  it('warns on unexpected version gap', () => {
    const engine = createEngine();
    const pkg = { name: 'jumped', version: '9.0.0', previousVersion: '1.2.3' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'version-gap');
    assert.ok(triggered);
  });

  it('does not flag normal version increments', () => {
    const engine = createEngine();
    const pkg = { name: 'normal', version: '2.0.0', previousVersion: '1.5.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'version-gap');
    assert.equal(triggered, undefined);
  });

  it('blocks sandbox .npmrc write attempts', () => {
    const engine = createEngine();
    const pkg = { name: 'npmrc-writer', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = {
      sandboxResult: {
        network: [],
        fileWrites: [{ path: '/home/sandboxuser/.npmrc' }],
        processes: [],
      },
    };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'sandbox-npmrc-write');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'block');
  });

  // --- Phase 7 rules ---

  it('blocks on integrity mismatch', () => {
    const engine = createEngine();
    const pkg = { name: 'tampered', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { integrityMismatch: true };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'integrity-mismatch');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'block');
  });

  it('does not flag integrity when match is good', () => {
    const engine = createEngine();
    const pkg = { name: 'good', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { integrityMismatch: false };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'integrity-mismatch');
    assert.equal(triggered, undefined);
  });

  it('warns on typosquat suspect', () => {
    const engine = createEngine();
    const pkg = { name: 'lodasj', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { typosquat: { suspect: 'lodasj', similarTo: 'lodash', distance: 1 } };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'typosquat-suspect');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'warn');
  });

  it('does not flag typosquat when null', () => {
    const engine = createEngine();
    const pkg = { name: 'unique-name', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { typosquat: null };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'typosquat-suspect');
    assert.equal(triggered, undefined);
  });

  it('reports info when no provenance', () => {
    const engine = createEngine();
    const pkg = { name: 'no-prov', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { provenance: { hasProvenance: false, attestations: [] } };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'no-provenance');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'info');
  });

  it('does not flag provenance when present', () => {
    const engine = createEngine();
    const pkg = { name: 'proven', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { provenance: { hasProvenance: true, attestations: [{ predicateType: 'https://slsa.dev/provenance/v1' }] } };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'no-provenance');
    assert.equal(triggered, undefined);
  });

  it('warns on starjacking suspect', () => {
    const engine = createEngine();
    const pkg = { name: 'malicious', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { starjacking: { packageName: 'malicious', claimedRepo: 'facebook/react' } };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'starjacking-suspect');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'warn');
  });

  it('does not flag starjacking when null', () => {
    const engine = createEngine();
    const pkg = { name: 'legit', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { starjacking: null };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'starjacking-suspect');
    assert.equal(triggered, undefined);
  });

  // --- Download anomaly rules ---

  it('warns on new package with low download count', () => {
    const engine = createEngine();
    const pkg = { name: 'sketchy-pkg', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { isNew: true, weeklyDownloads: 5 };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'low-download-count');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'warn');
  });

  it('does not flag low-download-count for popular packages', () => {
    const engine = createEngine();
    const pkg = { name: 'popular', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { isNew: true, weeklyDownloads: 50000 };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'low-download-count');
    assert.equal(triggered, undefined);
  });

  it('does not flag low-download-count for updated packages', () => {
    const engine = createEngine();
    const pkg = { name: 'updated-pkg', version: '2.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { isNew: false, weeklyDownloads: 5 };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'low-download-count');
    assert.equal(triggered, undefined);
  });

  it('warns on dormant package', () => {
    const engine = createEngine();
    const pkg = { name: 'abandoned', version: '2.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { dormant: true };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'dormant-package');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'warn');
  });

  it('does not flag dormant when false', () => {
    const engine = createEngine();
    const pkg = { name: 'active', version: '2.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { dormant: false };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'dormant-package');
    assert.equal(triggered, undefined);
  });

  // --- Scope-changed rule ---

  it('blocks when unscoped package replaces scoped package', () => {
    const engine = createEngine();
    const pkg = { name: 'utils', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { scopeChanged: true };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'scope-changed');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'block');
  });

  it('does not flag scope-changed when false', () => {
    const engine = createEngine();
    const pkg = { name: 'normal-pkg', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' } };
    const context = { scopeChanged: false };

    const result = engine.evaluate(pkg, meta, null, context);
    const triggered = result.results.find((r) => r.ruleId === 'scope-changed');
    assert.equal(triggered, undefined);
  });

  // --- License rule ---

  it('warns on package with no license', () => {
    const engine = createEngine();
    const pkg = { name: 'no-lic', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' }, license: null };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'no-license');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'warn');
  });

  it('does not flag UNLICENSED as missing license', () => {
    // UNLICENSED is a deliberate "proprietary" declaration, not a missing license
    const engine = createEngine();
    const pkg = { name: 'unlicensed', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' }, license: 'UNLICENSED' };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'no-license');
    assert.equal(triggered, undefined);
  });

  it('does not flag standard licenses', () => {
    const engine = createEngine();
    const pkg = { name: 'mit-pkg', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' }, license: 'MIT' };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'no-license');
    assert.equal(triggered, undefined);
  });

  it('does not flag no-license when meta is null', () => {
    const engine = createEngine();
    const pkg = { name: 'offline', version: '1.0.0' };

    const result = engine.evaluate(pkg, null, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'no-license');
    assert.equal(triggered, undefined);
  });

  // --- Release age rule ---

  it('warns on version published less than 7 days ago', () => {
    const engine = createEngine();
    const pkg = { name: 'fresh', version: '1.0.0' };
    const hourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' }, license: 'MIT', time: hourAgo };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'recent-release');
    assert.ok(triggered);
    assert.equal(triggered.severity, 'warn');
  });

  it('does not flag version published more than 7 days ago', () => {
    const engine = createEngine();
    const pkg = { name: 'mature', version: '1.0.0' };
    const monthAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' }, license: 'MIT', time: monthAgo };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'recent-release');
    assert.equal(triggered, undefined);
  });

  it('does not flag recent-release when no time available', () => {
    const engine = createEngine();
    const pkg = { name: 'no-time', version: '1.0.0' };
    const meta = { scripts: {}, repository: { url: 'https://github.com/a/b' }, license: 'MIT', time: null };

    const result = engine.evaluate(pkg, meta, null, {});
    const triggered = result.results.find((r) => r.ruleId === 'recent-release');
    assert.equal(triggered, undefined);
  });
});
