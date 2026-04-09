import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFile, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { loadConfig, addToAllowlist, approveScripts, isScriptApproved } from './loader.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('loadConfig', () => {
  it('returns defaults when no config file exists', async () => {
    const config = await loadConfig(tmpdir());
    assert.deepEqual(config.allowlist, []);
    assert.deepEqual(config.rules, {});
    assert.equal(config.autoApprove, false);
  });

  it('loads config from .npm-safe.json', async () => {
    const dir = join(tmpdir(), `npm-safe-test-${Date.now()}`);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(dir, { recursive: true });

    const configPath = join(dir, '.npm-safe.json');
    await writeFile(configPath, JSON.stringify({
      allowlist: ['lodash@*'],
      rules: { 'no-repository': { enabled: false } },
    }));

    const config = await loadConfig(dir);
    assert.deepEqual(config.allowlist, ['lodash@*']);
    assert.equal(config.rules['no-repository'].enabled, false);

    await unlink(configPath);
  });

  it('loads config from npm-safe.json (no dot prefix)', async () => {
    const dir = join(tmpdir(), `npm-safe-test-${Date.now()}`);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(dir, { recursive: true });

    const configPath = join(dir, 'npm-safe.json');
    await writeFile(configPath, JSON.stringify({
      allowlist: ['express@*'],
      autoApprove: true,
    }));

    const config = await loadConfig(dir);
    assert.deepEqual(config.allowlist, ['express@*']);
    assert.equal(config.autoApprove, true);

    await unlink(configPath);
  });

  it('prefers .npm-safe.json over npm-safe.json', async () => {
    const dir = join(tmpdir(), `npm-safe-test-${Date.now()}`);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(dir, { recursive: true });

    await writeFile(join(dir, '.npm-safe.json'), JSON.stringify({ allowlist: ['dotfile'] }));
    await writeFile(join(dir, 'npm-safe.json'), JSON.stringify({ allowlist: ['nodot'] }));

    const config = await loadConfig(dir);
    assert.deepEqual(config.allowlist, ['dotfile']);

    await unlink(join(dir, '.npm-safe.json'));
    await unlink(join(dir, 'npm-safe.json'));
  });
});

describe('config validation', () => {
  it('rejects unknown top-level keys', async () => {
    const dir = join(tmpdir(), `npm-safe-test-${Date.now()}`);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(dir, { recursive: true });

    const configPath = join(dir, '.npm-safe.json');
    await writeFile(configPath, JSON.stringify({ alowlist: ['typo'] }));

    await assert.rejects(
      () => loadConfig(dir),
      (err) => err.message.includes('Unknown config key "alowlist"')
    );

    await unlink(configPath);
  });

  it('rejects allowlist that is not an array', async () => {
    const dir = join(tmpdir(), `npm-safe-test-${Date.now()}`);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(dir, { recursive: true });

    const configPath = join(dir, '.npm-safe.json');
    await writeFile(configPath, JSON.stringify({ allowlist: 'lodash' }));

    await assert.rejects(
      () => loadConfig(dir),
      (err) => err.message.includes('"allowlist" must be an array')
    );

    await unlink(configPath);
  });

  it('rejects unknown sandbox keys', async () => {
    const dir = join(tmpdir(), `npm-safe-test-${Date.now()}`);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(dir, { recursive: true });

    const configPath = join(dir, '.npm-safe.json');
    await writeFile(configPath, JSON.stringify({ sandbox: { enbled: true } }));

    await assert.rejects(
      () => loadConfig(dir),
      (err) => err.message.includes('Unknown sandbox config key "enbled"')
    );

    await unlink(configPath);
  });

  it('accepts valid config without errors', async () => {
    const dir = join(tmpdir(), `npm-safe-test-${Date.now()}`);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(dir, { recursive: true });

    const configPath = join(dir, '.npm-safe.json');
    await writeFile(configPath, JSON.stringify({
      allowlist: ['pkg@1.0.0'],
      rules: { 'no-repository': { enabled: false } },
      sandbox: { enabled: false, timeout: 30 },
    }));

    const config = await loadConfig(dir);
    assert.deepEqual(config.allowlist, ['pkg@1.0.0']);

    await unlink(configPath);
  });
});

describe('addToAllowlist', () => {
  it('adds package to allowlist and persists', async () => {
    const dir = join(tmpdir(), `npm-safe-test-${Date.now()}`);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(dir, { recursive: true });

    const configPath = join(dir, '.npm-safe.json');
    await writeFile(configPath, JSON.stringify({ allowlist: [] }));

    await addToAllowlist('express@4.18.0', dir);

    const config = await loadConfig(dir);
    assert.ok(config.allowlist.includes('express@4.18.0'));

    await unlink(configPath);
  });

  it('does not duplicate existing entries', async () => {
    const dir = join(tmpdir(), `npm-safe-test-${Date.now()}`);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(dir, { recursive: true });

    const configPath = join(dir, '.npm-safe.json');
    await writeFile(configPath, JSON.stringify({ allowlist: ['pkg@1.0.0'] }));

    await addToAllowlist('pkg@1.0.0', dir);
    const config = await loadConfig(dir);
    const count = config.allowlist.filter((e) => e === 'pkg@1.0.0').length;
    assert.equal(count, 1);

    await unlink(configPath);
  });
});

describe('approveScripts', () => {
  it('records script approval in config', async () => {
    const dir = join(tmpdir(), `npm-safe-test-${Date.now()}`);
    const { mkdir } = await import('node:fs/promises');
    await mkdir(dir, { recursive: true });

    const configPath = join(dir, '.npm-safe.json');
    await writeFile(configPath, JSON.stringify({ allowlist: [] }));

    await approveScripts('esbuild@0.19.0', dir);
    const config = await loadConfig(dir);
    assert.ok(config.scriptApprovals['esbuild@0.19.0']);
    assert.ok(config.scriptApprovals['esbuild@0.19.0'].approved);
    assert.ok(config.scriptApprovals['esbuild@0.19.0'].by);

    await unlink(configPath);
  });
});

describe('isScriptApproved', () => {
  it('returns true for exact match', () => {
    const config = { scriptApprovals: { 'pkg@1.0.0': { approved: '2024-01-01' } } };
    assert.equal(isScriptApproved('pkg@1.0.0', config), true);
  });

  it('returns true for wildcard match', () => {
    const config = { scriptApprovals: { 'pkg@*': { approved: '2024-01-01' } } };
    assert.equal(isScriptApproved('pkg@2.0.0', config), true);
  });

  it('returns false for no match', () => {
    const config = { scriptApprovals: { 'other@1.0.0': { approved: '2024-01-01' } } };
    assert.equal(isScriptApproved('pkg@1.0.0', config), false);
  });

  it('returns false when no scriptApprovals', () => {
    assert.equal(isScriptApproved('pkg@1.0.0', {}), false);
  });
});
