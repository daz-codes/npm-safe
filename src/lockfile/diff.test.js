import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseLockfile } from './snapshot.js';
import { diffSnapshots, getChangedPackages } from './diff.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, '..', '..', 'test', 'fixtures');

async function loadFixture(name) {
  const raw = await readFile(join(FIXTURES, name), 'utf8');
  return parseLockfile(JSON.parse(raw));
}

describe('diffSnapshots', () => {
  it('detects added packages', async () => {
    const before = await loadFixture('lockfile-v3-before.json');
    const after = await loadFixture('lockfile-v3-after.json');
    const diff = diffSnapshots(before, after);

    assert.ok(diff.added.size >= 1);
    // new-dep and transitive are added
    const addedNames = [...diff.added.values()].map((p) => p.name);
    assert.ok(addedNames.includes('new-dep'));
    assert.ok(addedNames.includes('transitive'));
  });

  it('detects updated packages', async () => {
    const before = await loadFixture('lockfile-v3-before.json');
    const after = await loadFixture('lockfile-v3-after.json');
    const diff = diffSnapshots(before, after);

    assert.equal(diff.updated.size, 1);
    const updated = [...diff.updated.values()][0];
    assert.equal(updated.name, 'safe-dep');
    assert.equal(updated.previousVersion, '1.0.0');
    assert.equal(updated.version, '1.1.0');
  });

  it('detects removed packages', async () => {
    const before = await loadFixture('lockfile-v3-after.json');
    const after = await loadFixture('lockfile-v3-before.json');
    const diff = diffSnapshots(before, after);

    assert.ok(diff.removed.size >= 1);
    const removedNames = [...diff.removed.values()].map((p) => p.name);
    assert.ok(removedNames.includes('new-dep'));
  });

  it('returns empty diff for identical snapshots', async () => {
    const snapshot = await loadFixture('lockfile-v3-before.json');
    const diff = diffSnapshots(snapshot, snapshot);

    assert.equal(diff.added.size, 0);
    assert.equal(diff.removed.size, 0);
    assert.equal(diff.updated.size, 0);
    assert.equal(diff.unchanged.size, 1);
  });

  it('handles multiple instances of the same package at different depths', () => {
    const before = new Map([
      ['foo@1.0.0', { name: 'foo', version: '1.0.0' }],
    ]);
    const after = new Map([
      ['foo@1.0.0', { name: 'foo', version: '1.0.0' }],
      ['foo@2.0.0:node_modules/bar/node_modules/foo', { name: 'foo', version: '2.0.0' }],
    ]);

    const diff = diffSnapshots(before, after);

    // foo@1.0.0 is unchanged, foo@2.0.0 (nested) is added since the only
    // before candidate (foo@1.0.0) is already matched to the unchanged entry
    assert.equal(diff.unchanged.size, 1);
    assert.equal(diff.added.size, 1);
    const added = [...diff.added.values()][0];
    assert.equal(added.version, '2.0.0');
    assert.equal(diff.updated.size, 0);
  });

  it('detects removal when all instances of a package disappear', () => {
    const before = new Map([
      ['foo@1.0.0', { name: 'foo', version: '1.0.0' }],
      ['bar@1.0.0', { name: 'bar', version: '1.0.0' }],
    ]);
    const after = new Map([
      ['bar@1.0.0', { name: 'bar', version: '1.0.0' }],
    ]);

    const diff = diffSnapshots(before, after);
    assert.equal(diff.removed.size, 1);
    assert.equal([...diff.removed.values()][0].name, 'foo');
  });
});

describe('getChangedPackages', () => {
  it('merges added and updated into changed map', async () => {
    const before = await loadFixture('lockfile-v3-before.json');
    const after = await loadFixture('lockfile-v3-after.json');
    const diff = diffSnapshots(before, after);
    const changed = getChangedPackages(diff);

    assert.ok(changed.size >= 2);
    for (const [, pkg] of changed) {
      assert.ok(['added', 'updated'].includes(pkg.changeType));
    }
  });
});
