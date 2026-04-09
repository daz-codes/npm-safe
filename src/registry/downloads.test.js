import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isDormantPackage } from './downloads.js';

describe('isDormantPackage', () => {
  it('returns true when gap exceeds 1 year', () => {
    const meta = {
      time: {
        created: '2020-01-01T00:00:00.000Z',
        '1.0.0': '2020-01-01T00:00:00.000Z',
        '1.0.1': '2020-06-01T00:00:00.000Z',
        '2.0.0': '2022-01-01T00:00:00.000Z',
      },
    };
    assert.equal(isDormantPackage(meta, '2.0.0'), true);
  });

  it('returns false when versions are close together', () => {
    const meta = {
      time: {
        created: '2024-01-01T00:00:00.000Z',
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '1.0.1': '2024-03-01T00:00:00.000Z',
      },
    };
    assert.equal(isDormantPackage(meta, '1.0.1'), false);
  });

  it('returns false for the first version (no previous)', () => {
    const meta = {
      time: {
        created: '2024-01-01T00:00:00.000Z',
        '1.0.0': '2024-01-01T00:00:00.000Z',
      },
    };
    assert.equal(isDormantPackage(meta, '1.0.0'), false);
  });

  it('returns false when meta has no time field', () => {
    assert.equal(isDormantPackage({}, '1.0.0'), false);
    assert.equal(isDormantPackage(null, '1.0.0'), false);
  });

  it('ignores created and modified keys when finding previous version', () => {
    const meta = {
      time: {
        created: '2020-01-01T00:00:00.000Z',
        modified: '2022-06-01T00:00:00.000Z',
        '1.0.0': '2020-01-01T00:00:00.000Z',
        '2.0.0': '2022-01-01T00:00:00.000Z',
      },
    };
    // Gap is 2020 -> 2022, over 1 year
    assert.equal(isDormantPackage(meta, '2.0.0'), true);
  });
});
