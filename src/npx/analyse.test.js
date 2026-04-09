import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parsePackageSpec } from './analyse.js';

describe('parsePackageSpec', () => {
  it('parses bare package name', () => {
    assert.deepEqual(parsePackageSpec('lodash'), { name: 'lodash', version: null });
  });

  it('parses package@version', () => {
    assert.deepEqual(parsePackageSpec('lodash@4.17.21'), { name: 'lodash', version: '4.17.21' });
  });

  it('parses scoped package', () => {
    assert.deepEqual(parsePackageSpec('@angular/cli'), { name: '@angular/cli', version: null });
  });

  it('parses scoped package@version', () => {
    assert.deepEqual(parsePackageSpec('@angular/cli@17.0.0'), { name: '@angular/cli', version: '17.0.0' });
  });

  it('handles package with tag', () => {
    assert.deepEqual(parsePackageSpec('typescript@latest'), { name: 'typescript', version: 'latest' });
  });
});
