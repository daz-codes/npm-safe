import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { checkTyposquat } from './typosquat.js';

describe('checkTyposquat', () => {
  it('flags single-char typo of popular package', () => {
    const result = checkTyposquat('lodasj');
    assert.ok(result);
    assert.equal(result.similarTo, 'lodash');
  });

  it('flags delimiter variant', () => {
    const result = checkTyposquat('lod-ash');
    assert.ok(result);
    assert.equal(result.similarTo, 'lodash');
  });

  it('flags underscore variant', () => {
    const result = checkTyposquat('lod_ash');
    assert.ok(result);
    assert.equal(result.similarTo, 'lodash');
  });

  it('does not flag exact popular package name', () => {
    const result = checkTyposquat('lodash');
    assert.equal(result, null);
  });

  it('does not flag unrelated package', () => {
    const result = checkTyposquat('my-unique-project-name');
    assert.equal(result, null);
  });

  it('handles scoped packages', () => {
    const result = checkTyposquat('@evil/expresz');
    assert.ok(result);
    assert.equal(result.similarTo, 'express');
  });

  it('does not flag packages far from any popular name', () => {
    const result = checkTyposquat('completely-different-name');
    assert.equal(result, null);
  });
});
