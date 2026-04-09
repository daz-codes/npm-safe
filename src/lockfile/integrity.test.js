import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyIntegrity } from './integrity.js';

describe('verifyIntegrity', () => {
  it('skips packages without resolved URL', async () => {
    const snapshot = new Map([
      ['pkg@1.0.0', { name: 'pkg', version: '1.0.0', resolved: null, integrity: null }],
    ]);
    const results = await verifyIntegrity(snapshot);
    assert.equal(results.length, 0);
  });

  it('skips packages without integrity hash', async () => {
    const snapshot = new Map([
      ['pkg@1.0.0', { name: 'pkg', version: '1.0.0', resolved: 'https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz', integrity: null }],
    ]);
    const results = await verifyIntegrity(snapshot);
    assert.equal(results.length, 0);
  });

  it('reports download failures as warnings, not mismatches', async () => {
    const snapshot = new Map([
      ['pkg@1.0.0', {
        name: 'pkg',
        version: '1.0.0',
        resolved: 'https://localhost:1/nonexistent.tgz',
        integrity: 'sha512-abc123',
      }],
    ]);
    const warnings = [];
    const results = await verifyIntegrity(snapshot, warnings);
    assert.equal(results.length, 0);
    assert.ok(warnings.length > 0);
  });
});
