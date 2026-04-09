import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { writeFile, mkdir, unlink, rm } from 'node:fs/promises';
import { snapshotNpmrc, verifyNpmrc } from './npmrc.js';

describe('npmrc integrity', () => {
  it('detects no changes when npmrc is unchanged', async () => {
    const dir = join(tmpdir(), `safe-install-npmrc-${Date.now()}`);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, '.npmrc'), 'registry=https://registry.npmjs.org\n');

    // snapshotNpmrc checks project dir + homedir, we can only test project dir
    const before = { [join(dir, '.npmrc')]: null };
    // Manually snapshot just the project .npmrc
    const { createHash } = await import('node:crypto');
    before[join(dir, '.npmrc')] = createHash('sha256').update('registry=https://registry.npmjs.org\n').digest('hex');

    const changes = await verifyNpmrc(before);
    assert.equal(changes.length, 0);

    await rm(dir, { recursive: true });
  });

  it('detects modified npmrc', async () => {
    const dir = join(tmpdir(), `safe-install-npmrc-${Date.now()}`);
    await mkdir(dir, { recursive: true });
    const npmrcPath = join(dir, '.npmrc');
    await writeFile(npmrcPath, 'registry=https://registry.npmjs.org\n');

    const { createHash } = await import('node:crypto');
    const before = {
      [npmrcPath]: createHash('sha256').update('registry=https://registry.npmjs.org\n').digest('hex'),
    };

    // Modify the file
    await writeFile(npmrcPath, 'registry=https://evil.com\n');

    const changes = await verifyNpmrc(before);
    assert.equal(changes.length, 1);
    assert.equal(changes[0].type, 'modified');
    assert.equal(changes[0].path, npmrcPath);

    await rm(dir, { recursive: true });
  });

  it('detects created npmrc', async () => {
    const dir = join(tmpdir(), `safe-install-npmrc-${Date.now()}`);
    await mkdir(dir, { recursive: true });
    const npmrcPath = join(dir, '.npmrc');

    // Before: file doesn't exist
    const before = { [npmrcPath]: null };

    // Create the file
    await writeFile(npmrcPath, 'registry=https://evil.com\n');

    const changes = await verifyNpmrc(before);
    assert.equal(changes.length, 1);
    assert.equal(changes[0].type, 'created');

    await rm(dir, { recursive: true });
  });

  it('detects deleted npmrc', async () => {
    const dir = join(tmpdir(), `safe-install-npmrc-${Date.now()}`);
    await mkdir(dir, { recursive: true });
    const npmrcPath = join(dir, '.npmrc');
    await writeFile(npmrcPath, 'registry=https://registry.npmjs.org\n');

    const { createHash } = await import('node:crypto');
    const before = {
      [npmrcPath]: createHash('sha256').update('registry=https://registry.npmjs.org\n').digest('hex'),
    };

    await unlink(npmrcPath);

    const changes = await verifyNpmrc(before);
    assert.equal(changes.length, 1);
    assert.equal(changes[0].type, 'deleted');

    await rm(dir, { recursive: true });
  });
});
