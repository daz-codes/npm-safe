import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { logInvocation, getLastAuditDate } from './logger.js';

describe('npx logger', () => {
  it('logs invocation to file', async () => {
    const dir = join(tmpdir(), `safe-npx-log-${Date.now()}`);
    await mkdir(dir, { recursive: true });

    await logInvocation(dir, {
      name: 'typescript',
      version: '5.0.0',
      blocked: false,
      skipped: false,
      results: [],
    });

    const raw = await readFile(join(dir, '.npm-safe-npx.log'), 'utf8');
    const entry = JSON.parse(raw.trim());
    assert.equal(entry.package, 'typescript');
    assert.equal(entry.version, '5.0.0');
    assert.equal(entry.result, 'allowed');
    assert.ok(entry.timestamp);

    await rm(dir, { recursive: true });
  });

  it('logs blocked result', async () => {
    const dir = join(tmpdir(), `safe-npx-log-${Date.now()}`);
    await mkdir(dir, { recursive: true });

    await logInvocation(dir, {
      name: 'bad-pkg',
      version: '1.0.0',
      blocked: true,
      results: [{ ruleId: 'no-install-scripts' }],
    });

    const raw = await readFile(join(dir, '.npm-safe-npx.log'), 'utf8');
    const entry = JSON.parse(raw.trim());
    assert.equal(entry.result, 'blocked');
    assert.equal(entry.violations, 1);

    await rm(dir, { recursive: true });
  });

  it('appends multiple entries', async () => {
    const dir = join(tmpdir(), `safe-npx-log-${Date.now()}`);
    await mkdir(dir, { recursive: true });

    await logInvocation(dir, { name: 'a', version: '1.0.0', blocked: false, results: [] });
    await logInvocation(dir, { name: 'b', version: '2.0.0', blocked: false, results: [] });

    const raw = await readFile(join(dir, '.npm-safe-npx.log'), 'utf8');
    const lines = raw.trim().split('\n');
    assert.equal(lines.length, 2);

    await rm(dir, { recursive: true });
  });

  it('retrieves last audit date for a package', async () => {
    const dir = join(tmpdir(), `safe-npx-log-${Date.now()}`);
    await mkdir(dir, { recursive: true });

    await logInvocation(dir, { name: 'pkg', version: '1.0.0', blocked: false, results: [] });

    const date = await getLastAuditDate(dir, 'pkg');
    assert.ok(date instanceof Date);
    assert.ok(Date.now() - date.getTime() < 5000);

    await rm(dir, { recursive: true });
  });

  it('returns null for unknown package', async () => {
    const dir = join(tmpdir(), `safe-npx-log-${Date.now()}`);
    await mkdir(dir, { recursive: true });

    const date = await getLastAuditDate(dir, 'nonexistent');
    assert.equal(date, null);

    await rm(dir, { recursive: true });
  });

  it('returns null when no log file exists', async () => {
    const dir = join(tmpdir(), `safe-npx-log-${Date.now()}`);
    const date = await getLastAuditDate(dir, 'pkg');
    assert.equal(date, null);
  });
});
