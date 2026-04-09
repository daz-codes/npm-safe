import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseStraceLog } from '../../src/sandbox/monitor.js';
import { diffProfiles } from '../../src/sandbox/profiles.js';
import { createEngine } from '../../src/rules/engine.js';
import { getExitCode } from '../../src/report/formatter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const STRACE_DIR = join(__dirname, '..', 'fixtures', 'attacks', 'strace');

async function loadStrace(filename) {
  const raw = await readFile(join(STRACE_DIR, filename), 'utf8');
  return parseStraceLog(raw);
}

function findRule(evaluation, ruleId) {
  return evaluation.results.find((r) => r.ruleId === ruleId);
}

function hasRule(evaluation, ruleId) {
  return evaluation.results.some((r) => r.ruleId === ruleId);
}

function makePkg(overrides = {}) {
  return {
    name: 'test-pkg',
    version: '1.0.0',
    resolved: 'https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz',
    integrity: 'sha512-abc123',
    changeType: 'added',
    hasScripts: true,
    ...overrides,
  };
}

describe('Sandbox attack scenarios', () => {

  describe('Network exfiltration', () => {
    it('parses network connections from strace log', async () => {
      const result = await loadStrace('network-exfiltration.log');

      assert.ok(result.network.length > 0, 'should detect network activity');

      // Should detect the exfiltration IP
      const exfilConn = result.network.find((n) => n.address === '45.33.32.156');
      assert.ok(exfilConn, 'should detect connection to exfiltration IP');
      assert.equal(exfilConn.port, 443);

      // Should detect DNS query to 8.8.8.8
      const dnsConn = result.network.find((n) => n.address === '8.8.8.8');
      assert.ok(dnsConn, 'should detect DNS connection');
      assert.equal(dnsConn.port, 53);

      // Should detect IPv6 connection
      const ipv6Conn = result.network.find((n) => n.address === '2607:f8b0:4004:800::200e');
      assert.ok(ipv6Conn, 'should detect IPv6 connection');
      assert.equal(ipv6Conn.port, 8443);
    });

    it('triggers sandbox-network-attempt BLOCK rule', async () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'exfil-pkg' });
      const sandboxResult = await loadStrace('network-exfiltration.log');

      const context = { sandboxResult };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(hasRule(evaluation, 'sandbox-network-attempt'), 'should trigger network block');
      assert.equal(findRule(evaluation, 'sandbox-network-attempt').severity, 'block');
      assert.equal(getExitCode([evaluation]), 1, 'should exit 1 (blocked)');
    });
  });

  describe('Sensitive path rename/symlink operations', () => {
    it('parses file write operations targeting sensitive paths', async () => {
      const result = await loadStrace('sensitive-path-ops.log');

      assert.ok(result.fileWrites.length > 0, 'should detect file writes');

      // Check for specific sensitive targets
      const paths = result.fileWrites.map((f) => f.path);

      assert.ok(paths.includes('/etc/cron.d/backdoor'), 'should detect cron backdoor rename');
      assert.ok(paths.includes('/root/.bashrc'), 'should detect bashrc symlink');
      assert.ok(paths.includes('/root/.ssh/authorized_keys'), 'should detect SSH key injection');
      assert.ok(paths.includes('/etc/ld.so.preload'), 'should detect ld.so.preload write');
      assert.ok(paths.includes('/usr/lib/libevil.so'), 'should detect library injection');
      assert.ok(paths.includes('/etc/resolv.conf'), 'should detect DNS hijack attempt');
      assert.ok(paths.includes('/root/.npmrc'), 'should detect npmrc credential theft');
    });

    it('triggers sandbox-file-write-outside-modules BLOCK', async () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'path-manip' });
      const sandboxResult = await loadStrace('sensitive-path-ops.log');

      const context = { sandboxResult };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(hasRule(evaluation, 'sandbox-file-write-outside-modules'), 'should trigger file write block');
      assert.equal(findRule(evaluation, 'sandbox-file-write-outside-modules').severity, 'block');
    });

    it('triggers sandbox-npmrc-write for .npmrc targeting', async () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'path-manip' });
      const sandboxResult = await loadStrace('sensitive-path-ops.log');

      const context = { sandboxResult };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(hasRule(evaluation, 'sandbox-npmrc-write'), 'should trigger npmrc write block');
      assert.equal(findRule(evaluation, 'sandbox-npmrc-write').severity, 'block');
    });
  });

  describe('Unexpected binary execution', () => {
    it('parses unexpected process spawns', async () => {
      const result = await loadStrace('unexpected-binaries.log');

      assert.ok(result.processes.length > 0, 'should detect process spawns');

      const commands = result.processes.map((p) => p.command);
      assert.ok(commands.includes('curl'), 'should detect curl');
      assert.ok(commands.includes('wget'), 'should detect wget');
      assert.ok(commands.includes('python3'), 'should detect python3');
      assert.ok(commands.includes('cc'), 'should detect compiler');
      assert.ok(commands.includes('whoami'), 'should detect whoami');
      assert.ok(commands.includes('chmod'), 'should detect chmod');
    });

    it('triggers sandbox-unexpected-process WARN rule', async () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'shady-pkg' });
      const sandboxResult = await loadStrace('unexpected-binaries.log');

      const context = { sandboxResult };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(hasRule(evaluation, 'sandbox-unexpected-process'), 'should trigger unexpected process');
      assert.equal(findRule(evaluation, 'sandbox-unexpected-process').severity, 'warn');
    });

    it('whitelisted processes (node, sh, bash, npm) are not flagged alone', () => {
      const engine = createEngine({});
      const pkg = makePkg();

      // Only whitelisted processes
      const sandboxResult = {
        network: [],
        fileWrites: [],
        processes: [
          { executable: '/usr/bin/node', command: 'node', args: '"node", "index.js"' },
          { executable: '/bin/sh', command: 'sh', args: '"sh", "-c", "echo hello"' },
          { executable: '/bin/bash', command: 'bash', args: '"bash"' },
          { executable: '/usr/bin/npm', command: 'npm', args: '"npm", "install"' },
        ],
      };

      const context = { sandboxResult };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(!hasRule(evaluation, 'sandbox-unexpected-process'),
        'whitelisted processes should not trigger');
    });
  });

  describe('Writes outside /sandbox/node_modules', () => {
    it('parses file writes to unauthorized locations', async () => {
      const result = await loadStrace('writes-outside-modules.log');

      // Writes inside /sandbox/node_modules and /sandbox/package should be OK
      const outsideWrites = result.fileWrites.filter(
        (f) => !f.path.startsWith('/sandbox/node_modules') && !f.path.startsWith('/sandbox/package')
      );

      assert.ok(outsideWrites.length > 0, 'should detect writes outside allowed paths');

      const outsidePaths = outsideWrites.map((f) => f.path);
      assert.ok(outsidePaths.some((p) => p.includes('.npmrc')), 'should detect npmrc write');
      assert.ok(outsidePaths.some((p) => p.startsWith('/tmp/')), 'should detect /tmp write');
      assert.ok(outsidePaths.some((p) => p === '/sandbox/.env'), 'should detect .env write');
      assert.ok(outsidePaths.some((p) => p === '/etc/hosts'), 'should detect /etc/hosts write');
      assert.ok(outsidePaths.some((p) => p.startsWith('/usr/local/bin/')), 'should detect bin write');
    });

    it('triggers both file-write and npmrc-write BLOCK rules', async () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'escape-pkg' });
      const sandboxResult = await loadStrace('writes-outside-modules.log');

      const context = { sandboxResult };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(hasRule(evaluation, 'sandbox-file-write-outside-modules'));
      assert.ok(hasRule(evaluation, 'sandbox-npmrc-write'));
      assert.equal(getExitCode([evaluation]), 1, 'should be blocked');
    });
  });

  describe('Behaviour diff: new network endpoints', () => {
    it('triggers behaviour-diff-new-network when new endpoints appear', () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'evolving-pkg', version: '2.0.0', previousVersion: '1.0.0', changeType: 'updated' });

      const prevProfile = {
        network: [{ address: '104.16.0.0', port: 443, syscall: 'connect' }],
        fileWrites: [],
        processes: [{ executable: '/usr/bin/node', command: 'node', args: '"node"' }],
        fileCount: 50,
      };

      const currentProfile = {
        network: [
          { address: '104.16.0.0', port: 443, syscall: 'connect' },     // existing
          { address: '45.33.32.156', port: 8080, syscall: 'connect' },   // NEW - suspicious
          { address: '10.0.0.1', port: 6379, syscall: 'connect' },       // NEW - internal redis?
        ],
        fileWrites: [],
        processes: [{ executable: '/usr/bin/node', command: 'node', args: '"node"' }],
        fileCount: 52,
      };

      const profileDiff = diffProfiles(prevProfile, currentProfile);
      assert.ok(profileDiff.hasChanges, 'should detect changes');
      assert.equal(profileDiff.newNetwork.length, 2, 'should find 2 new endpoints');

      const context = { profileDiff, sandboxResult: currentProfile };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(hasRule(evaluation, 'behaviour-diff-new-network'), 'should trigger new network rule');
      assert.equal(findRule(evaluation, 'behaviour-diff-new-network').severity, 'block');
    });
  });

  describe('Behaviour diff: new file writes outside modules', () => {
    it('triggers behaviour-diff-new-file-write for new sensitive writes', () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'sneaky-pkg', version: '2.0.0', previousVersion: '1.0.0', changeType: 'updated' });

      const prevProfile = {
        network: [],
        fileWrites: [
          { path: '/sandbox/node_modules/sneaky-pkg/cache.json', syscall: 'openat' },
        ],
        processes: [],
        fileCount: 30,
      };

      const currentProfile = {
        network: [],
        fileWrites: [
          { path: '/sandbox/node_modules/sneaky-pkg/cache.json', syscall: 'openat' }, // existing
          { path: '/tmp/exfil.dat', syscall: 'openat' },                               // NEW
          { path: '/etc/cron.d/miner', syscall: 'rename' },                            // NEW
        ],
        processes: [],
        fileCount: 32,
      };

      const profileDiff = diffProfiles(prevProfile, currentProfile);
      assert.ok(profileDiff.hasChanges);
      assert.equal(profileDiff.newFileWrites.length, 2, 'should detect 2 new file writes');

      const context = { profileDiff, sandboxResult: currentProfile };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(hasRule(evaluation, 'behaviour-diff-new-file-write'));
      assert.equal(findRule(evaluation, 'behaviour-diff-new-file-write').severity, 'block');
    });

    it('does not trigger for new writes inside /sandbox/node_modules', () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'ok-pkg', version: '2.0.0', previousVersion: '1.0.0', changeType: 'updated' });

      const prevProfile = {
        network: [],
        fileWrites: [],
        processes: [],
        fileCount: 10,
      };

      const currentProfile = {
        network: [],
        fileWrites: [
          { path: '/sandbox/node_modules/ok-pkg/newfile.js', syscall: 'openat' },
          { path: '/sandbox/package/dist/bundle.js', syscall: 'openat' },
        ],
        processes: [],
        fileCount: 12,
      };

      const profileDiff = diffProfiles(prevProfile, currentProfile);
      const context = { profileDiff, sandboxResult: currentProfile };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(!hasRule(evaluation, 'behaviour-diff-new-file-write'),
        'writes inside allowed paths should not trigger');
    });
  });

  describe('Behaviour diff: new processes', () => {
    it('triggers behaviour-diff-new-process for newly spawned processes', () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'proc-pkg', version: '2.0.0', previousVersion: '1.0.0', changeType: 'updated' });

      const prevProfile = {
        network: [],
        fileWrites: [],
        processes: [
          { executable: '/usr/bin/node', command: 'node', args: '"node", "build.js"' },
        ],
        fileCount: 20,
      };

      const currentProfile = {
        network: [],
        fileWrites: [],
        processes: [
          { executable: '/usr/bin/node', command: 'node', args: '"node", "build.js"' },
          { executable: '/usr/bin/curl', command: 'curl', args: '"curl", "http://evil.com"' },
          { executable: '/usr/bin/python3', command: 'python3', args: '"python3", "-c", "import os"' },
        ],
        fileCount: 20,
      };

      const profileDiff = diffProfiles(prevProfile, currentProfile);
      assert.ok(profileDiff.hasChanges);
      assert.equal(profileDiff.newProcesses.length, 2, 'should detect 2 new processes');

      const context = { profileDiff, sandboxResult: currentProfile };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(hasRule(evaluation, 'behaviour-diff-new-process'));
      assert.equal(findRule(evaluation, 'behaviour-diff-new-process').severity, 'warn');
    });
  });

  describe('Behaviour diff: size change', () => {
    it('triggers behaviour-diff-size-change when install doubles in size', () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'bloat-pkg', version: '2.0.0', previousVersion: '1.0.0', changeType: 'updated' });

      const prevProfile = {
        network: [],
        fileWrites: [],
        processes: [],
        fileCount: 50,
      };

      const currentProfile = {
        network: [],
        fileWrites: [],
        processes: [],
        fileCount: 150, // 3x increase
      };

      const profileDiff = diffProfiles(prevProfile, currentProfile);
      assert.ok(profileDiff.hasChanges);
      assert.equal(profileDiff.sizeChange.ratio, 3, 'ratio should be 3x');

      const context = { profileDiff };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(hasRule(evaluation, 'behaviour-diff-size-change'));
      assert.equal(findRule(evaluation, 'behaviour-diff-size-change').severity, 'warn');
    });

    it('triggers when install shrinks below 50%', () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'shrink-pkg', version: '2.0.0', previousVersion: '1.0.0', changeType: 'updated' });

      const prevProfile = {
        network: [],
        fileWrites: [],
        processes: [],
        fileCount: 100,
      };

      const currentProfile = {
        network: [],
        fileWrites: [],
        processes: [],
        fileCount: 10, // 90% shrink — suspicious
      };

      const profileDiff = diffProfiles(prevProfile, currentProfile);
      assert.ok(profileDiff.sizeChange.ratio < 0.5, 'ratio should be < 0.5');

      const context = { profileDiff };
      const evaluation = engine.evaluate(pkg, null, null, context);

      assert.ok(hasRule(evaluation, 'behaviour-diff-size-change'));
    });
  });

  describe('Combined sandbox attack', () => {
    it('fires multiple sandbox rules for an aggressive package', async () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'mega-malware', version: '2.0.0', previousVersion: '1.0.0', changeType: 'updated' });

      // Combine network exfiltration strace with write-outside-modules
      const networkResult = await loadStrace('network-exfiltration.log');
      const writeResult = await loadStrace('writes-outside-modules.log');

      // Merge the two sandbox results
      const sandboxResult = {
        network: networkResult.network,
        fileWrites: writeResult.fileWrites,
        processes: [
          ...networkResult.processes,
          { executable: '/usr/bin/curl', command: 'curl', args: '"curl", "http://evil.com"' },
        ],
      };

      // Previous version was clean
      const prevProfile = {
        network: [],
        fileWrites: [{ path: '/sandbox/node_modules/mega-malware/data.json', syscall: 'openat' }],
        processes: [{ executable: '/usr/bin/node', command: 'node', args: '"node"' }],
        fileCount: 20,
      };

      const currentProfile = {
        ...sandboxResult,
        fileCount: 85,
      };

      const profileDiff = diffProfiles(prevProfile, currentProfile);

      const context = { sandboxResult, profileDiff };
      const evaluation = engine.evaluate(pkg, null, null, context);

      // Should trigger all sandbox rules
      assert.ok(hasRule(evaluation, 'sandbox-network-attempt'), 'should block network');
      assert.ok(hasRule(evaluation, 'sandbox-file-write-outside-modules'), 'should block file writes');
      assert.ok(hasRule(evaluation, 'sandbox-npmrc-write'), 'should block npmrc write');
      assert.ok(hasRule(evaluation, 'sandbox-unexpected-process'), 'should warn unexpected process');
      assert.ok(hasRule(evaluation, 'behaviour-diff-new-network'), 'should block new network in diff');
      assert.ok(hasRule(evaluation, 'behaviour-diff-new-file-write'), 'should block new file writes in diff');
      assert.ok(hasRule(evaluation, 'behaviour-diff-new-process'), 'should warn new processes in diff');
      assert.ok(hasRule(evaluation, 'behaviour-diff-size-change'), 'should warn size change');

      assert.equal(getExitCode([evaluation]), 1, 'should be blocked');

      const blockCount = evaluation.results.filter((r) => r.severity === 'block').length;
      assert.ok(blockCount >= 4, `should have at least 4 BLOCK-level violations, got ${blockCount}`);
    });
  });

  describe('Exit code verification', () => {
    it('returns exit 1 for BLOCK sandbox violations', async () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'net-pkg' });
      const sandboxResult = await loadStrace('network-exfiltration.log');

      const evaluation = engine.evaluate(pkg, null, null, { sandboxResult });
      assert.equal(getExitCode([evaluation]), 1);
    });

    it('returns exit 2 for WARN-only violations', () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'warn-pkg' });

      // Only unexpected processes (WARN), no network or file writes outside modules
      const sandboxResult = {
        network: [],
        fileWrites: [{ path: '/sandbox/node_modules/warn-pkg/data.json', syscall: 'openat' }],
        processes: [
          { executable: '/usr/bin/node', command: 'node', args: '"node"' },
          { executable: '/usr/bin/python3', command: 'python3', args: '"python3"' },
        ],
      };

      const evaluation = engine.evaluate(pkg, null, null, { sandboxResult });
      assert.ok(hasRule(evaluation, 'sandbox-unexpected-process'));
      assert.ok(!hasRule(evaluation, 'sandbox-network-attempt'));
      assert.ok(!hasRule(evaluation, 'sandbox-file-write-outside-modules'));
      assert.equal(getExitCode([evaluation]), 2, 'warn-only should exit 2');
    });

    it('returns exit 0 for clean sandbox results', () => {
      const engine = createEngine({});
      const pkg = makePkg({ name: 'clean-pkg' });

      const sandboxResult = {
        network: [],
        fileWrites: [{ path: '/sandbox/node_modules/clean-pkg/index.js', syscall: 'openat' }],
        processes: [{ executable: '/usr/bin/node', command: 'node', args: '"node"' }],
      };

      const evaluation = engine.evaluate(pkg, null, null, { sandboxResult });
      assert.ok(!hasRule(evaluation, 'sandbox-network-attempt'));
      assert.ok(!hasRule(evaluation, 'sandbox-file-write-outside-modules'));
      assert.ok(!hasRule(evaluation, 'sandbox-unexpected-process'));
    });
  });
});
