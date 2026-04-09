import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseLockfile } from './snapshot.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, '..', '..', 'test', 'fixtures');

describe('parseLockfile', () => {
  it('parses v3 lockfile into package map', async () => {
    const raw = await readFile(join(FIXTURES, 'lockfile-v3-before.json'), 'utf8');
    const lock = JSON.parse(raw);
    const snapshot = parseLockfile(lock);

    assert.equal(snapshot.size, 1);
    assert.ok(snapshot.has('safe-dep@1.0.0'));

    const pkg = snapshot.get('safe-dep@1.0.0');
    assert.equal(pkg.name, 'safe-dep');
    assert.equal(pkg.version, '1.0.0');
    assert.equal(pkg.hasScripts, false);
  });

  it('detects install scripts', async () => {
    const raw = await readFile(join(FIXTURES, 'lockfile-v3-after.json'), 'utf8');
    const lock = JSON.parse(raw);
    const snapshot = parseLockfile(lock);

    const newDep = snapshot.get('new-dep@2.0.0');
    assert.equal(newDep.hasScripts, true);
  });

  it('handles nested node_modules (transitive deps)', async () => {
    const raw = await readFile(join(FIXTURES, 'lockfile-v3-after.json'), 'utf8');
    const lock = JSON.parse(raw);
    const snapshot = parseLockfile(lock);

    // Nested deps get a path-qualified key to avoid collisions
    const nestedKey = 'transitive@1.0.0:node_modules/new-dep/node_modules/transitive';
    assert.ok(snapshot.has(nestedKey));
    assert.equal(snapshot.get(nestedKey).name, 'transitive');
  });

  it('does not collide when same package appears at different depths', () => {
    const lock = {
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/foo': { version: '1.0.0' },
        'node_modules/bar/node_modules/foo': { version: '1.0.0' },
      },
    };
    const snapshot = parseLockfile(lock);
    // Both instances should be present (different keys)
    const fooEntries = [...snapshot.values()].filter((p) => p.name === 'foo');
    assert.equal(fooEntries.length, 2);
  });

  it('skips root package entry', async () => {
    const raw = await readFile(join(FIXTURES, 'lockfile-v3-before.json'), 'utf8');
    const lock = JSON.parse(raw);
    const snapshot = parseLockfile(lock);

    for (const [, pkg] of snapshot) {
      assert.notEqual(pkg.name, 'test-project');
    }
  });
});
