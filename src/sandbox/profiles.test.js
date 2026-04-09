import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdir, rm } from 'node:fs/promises';
import { createProfileStore, diffProfiles } from './profiles.js';

describe('createProfileStore', () => {
  it('saves and loads a profile', async () => {
    const dir = join(tmpdir(), `safe-install-profiles-${Date.now()}`);
    await mkdir(dir, { recursive: true });

    const store = createProfileStore(dir);
    const profile = {
      network: [{ syscall: 'connect', address: '1.2.3.4', port: 443 }],
      fileWrites: [{ path: '/sandbox/node_modules/pkg/data.json' }],
      processes: [{ executable: '/usr/bin/node', command: 'node', args: '"node"' }],
    };

    await store.saveProfile('test-pkg', '1.0.0', profile);
    const loaded = await store.loadProfile('test-pkg', '1.0.0');
    assert.deepEqual(loaded, profile);

    await rm(dir, { recursive: true });
  });

  it('returns null for missing profile', async () => {
    const dir = join(tmpdir(), `safe-install-profiles-${Date.now()}`);
    const store = createProfileStore(dir);
    const loaded = await store.loadProfile('nonexistent', '0.0.0');
    assert.equal(loaded, null);
  });

  it('loads previous profile by version', async () => {
    const dir = join(tmpdir(), `safe-install-profiles-${Date.now()}`);
    await mkdir(dir, { recursive: true });

    const store = createProfileStore(dir);
    const v1 = { network: [], fileWrites: [], processes: [] };
    const v2 = { network: [{ syscall: 'connect', address: '5.6.7.8', port: 80 }], fileWrites: [], processes: [] };

    await store.saveProfile('pkg', '1.0.0', v1);
    await store.saveProfile('pkg', '2.0.0', v2);

    const prev = await store.loadPreviousProfile('pkg', '2.0.0');
    assert.deepEqual(prev, v1);

    await rm(dir, { recursive: true });
  });

  it('sorts versions by semver, not filesystem order', async () => {
    const dir = join(tmpdir(), `safe-install-profiles-${Date.now()}`);
    await mkdir(dir, { recursive: true });

    const store = createProfileStore(dir);
    const profile = { network: [], fileWrites: [], processes: [] };

    // Save out of order to ensure readdir order doesn't matter
    await store.saveProfile('pkg', '10.0.0', { ...profile, tag: '10' });
    await store.saveProfile('pkg', '2.0.0', { ...profile, tag: '2' });
    await store.saveProfile('pkg', '1.0.0', { ...profile, tag: '1' });
    await store.saveProfile('pkg', '3.5.1', { ...profile, tag: '3.5.1' });

    // Asking for previous of 11.0.0 should return 10.0.0, not 3.5.1 or 2.0.0
    const prev = await store.loadPreviousProfile('pkg', '11.0.0');
    assert.equal(prev.tag, '10');

    // Asking for previous of 3.5.1 should return 2.0.0
    const prev2 = await store.loadPreviousProfile('pkg', '3.5.1');
    assert.equal(prev2.tag, '2');

    await rm(dir, { recursive: true });
  });

  it('handles pre-release versions correctly', async () => {
    const dir = join(tmpdir(), `safe-install-profiles-${Date.now()}`);
    await mkdir(dir, { recursive: true });

    const store = createProfileStore(dir);
    const profile = { network: [], fileWrites: [], processes: [] };

    await store.saveProfile('pkg', '1.0.0', { ...profile, tag: 'release' });
    await store.saveProfile('pkg', '2.0.0-beta.1', { ...profile, tag: 'beta' });

    // Previous of 2.0.0 should be 2.0.0-beta.1 (pre-release sorts before release)
    const prev = await store.loadPreviousProfile('pkg', '2.0.0');
    assert.equal(prev.tag, 'beta');

    // Previous of 2.0.0-beta.1 should be 1.0.0 (beta is above 1.0.0)
    const prev2 = await store.loadPreviousProfile('pkg', '2.0.0-beta.1');
    assert.equal(prev2.tag, 'release');

    await rm(dir, { recursive: true });
  });
});

describe('diffProfiles', () => {
  it('detects new network calls', () => {
    const prev = {
      network: [{ address: '1.2.3.4', port: 443 }],
      fileWrites: [],
      processes: [],
    };
    const current = {
      network: [
        { address: '1.2.3.4', port: 443 },
        { address: '5.6.7.8', port: 80 },
      ],
      fileWrites: [],
      processes: [],
    };

    const result = diffProfiles(prev, current);
    assert.ok(result.hasChanges);
    assert.equal(result.newNetwork.length, 1);
    assert.equal(result.newNetwork[0].address, '5.6.7.8');
  });

  it('detects new file writes', () => {
    const prev = {
      network: [],
      fileWrites: [{ path: '/sandbox/node_modules/pkg/a.js' }],
      processes: [],
    };
    const current = {
      network: [],
      fileWrites: [
        { path: '/sandbox/node_modules/pkg/a.js' },
        { path: '/tmp/suspicious' },
      ],
      processes: [],
    };

    const result = diffProfiles(prev, current);
    assert.ok(result.hasChanges);
    assert.equal(result.newFileWrites.length, 1);
    assert.equal(result.newFileWrites[0].path, '/tmp/suspicious');
  });

  it('detects new processes', () => {
    const prev = {
      network: [],
      fileWrites: [],
      processes: [{ command: 'node' }, { command: 'sh' }],
    };
    const current = {
      network: [],
      fileWrites: [],
      processes: [{ command: 'node' }, { command: 'sh' }, { command: 'curl' }],
    };

    const result = diffProfiles(prev, current);
    assert.ok(result.hasChanges);
    assert.equal(result.newProcesses.length, 1);
    assert.equal(result.newProcesses[0].command, 'curl');
  });

  it('returns no changes for identical profiles', () => {
    const profile = {
      network: [{ address: '1.2.3.4', port: 443 }],
      fileWrites: [{ path: '/sandbox/node_modules/pkg/a.js' }],
      processes: [{ command: 'node' }],
    };

    const result = diffProfiles(profile, profile);
    assert.equal(result.hasChanges, false);
  });

  it('computes size change ratio', () => {
    const prev = {
      network: [],
      fileWrites: [],
      processes: [],
      fileCount: 50,
    };
    const current = {
      network: [],
      fileWrites: [],
      processes: [],
      fileCount: 500,
    };

    const result = diffProfiles(prev, current);
    assert.ok(result.hasChanges);
    assert.ok(result.sizeChange);
    assert.equal(result.sizeChange.before, 50);
    assert.equal(result.sizeChange.after, 500);
    assert.equal(result.sizeChange.ratio, 10);
  });

  it('does not flag minor size changes', () => {
    const prev = {
      network: [],
      fileWrites: [],
      processes: [],
      fileCount: 100,
    };
    const current = {
      network: [],
      fileWrites: [],
      processes: [],
      fileCount: 110,
    };

    const result = diffProfiles(prev, current);
    assert.equal(result.hasChanges, false);
    assert.equal(result.sizeChange.ratio, 1.1);
  });

  it('returns null sizeChange when fileCount missing', () => {
    const prev = { network: [], fileWrites: [], processes: [] };
    const current = { network: [], fileWrites: [], processes: [] };

    const result = diffProfiles(prev, current);
    assert.equal(result.sizeChange, null);
  });

  it('returns null when prev is missing', () => {
    const result = diffProfiles(null, { network: [], fileWrites: [], processes: [] });
    assert.equal(result, null);
  });
});
