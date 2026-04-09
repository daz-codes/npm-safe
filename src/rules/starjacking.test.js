import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { checkStarjacking } from './starjacking.js';

describe('checkStarjacking', () => {
  it('flags package claiming unrelated popular repo', () => {
    const result = checkStarjacking('malicious-pkg', {
      repository: { url: 'https://github.com/facebook/react.git' },
    });
    assert.ok(result);
    assert.equal(result.claimedRepo, 'facebook/react');
  });

  it('does not flag legitimate package matching repo name', () => {
    const result = checkStarjacking('react', {
      repository: { url: 'https://github.com/facebook/react.git' },
    });
    assert.equal(result, null);
  });

  it('does not flag scoped package from repo owner', () => {
    const result = checkStarjacking('@facebook/some-tool', {
      repository: { url: 'https://github.com/facebook/react.git' },
    });
    assert.equal(result, null);
  });

  it('does not flag non-popular repos', () => {
    const result = checkStarjacking('anything', {
      repository: { url: 'https://github.com/someuser/somerepo.git' },
    });
    assert.equal(result, null);
  });

  it('handles string repository field', () => {
    const result = checkStarjacking('evil-pkg', {
      repository: 'https://github.com/lodash/lodash',
    });
    assert.ok(result);
    assert.equal(result.claimedRepo, 'lodash/lodash');
  });

  it('handles git+ prefix URLs', () => {
    const result = checkStarjacking('faker', {
      repository: { url: 'git+https://github.com/expressjs/express.git' },
    });
    assert.ok(result);
  });

  it('returns null when no repository', () => {
    const result = checkStarjacking('pkg', {});
    assert.equal(result, null);
  });

  it('does not flag package whose name contains repo name', () => {
    const result = checkStarjacking('react-dom', {
      repository: { url: 'https://github.com/facebook/react.git' },
    });
    assert.equal(result, null);
  });
});
