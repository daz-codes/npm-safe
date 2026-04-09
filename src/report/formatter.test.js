import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { getExitCode, formatJson, formatReport } from './formatter.js';

describe('getExitCode', () => {
  it('returns 1 when any evaluation has a block', () => {
    const evaluations = [
      { package: { name: 'a' }, results: [{ severity: 'warn' }] },
      { package: { name: 'b' }, results: [{ severity: 'block' }] },
    ];
    assert.equal(getExitCode(evaluations), 1);
  });

  it('returns 2 when warnings only', () => {
    const evaluations = [
      { package: { name: 'a' }, results: [{ severity: 'warn' }] },
      { package: { name: 'b' }, results: [] },
    ];
    assert.equal(getExitCode(evaluations), 2);
  });

  it('returns 1 when blocks and warnings both present', () => {
    const evaluations = [
      { package: { name: 'a' }, results: [{ severity: 'warn' }] },
      { package: { name: 'b' }, results: [{ severity: 'block' }] },
    ];
    assert.equal(getExitCode(evaluations), 1);
  });

  it('returns 0 when all clean', () => {
    const evaluations = [
      { package: { name: 'a' }, results: [] },
    ];
    assert.equal(getExitCode(evaluations), 0);
  });

  it('returns 0 for empty evaluations', () => {
    assert.equal(getExitCode([]), 0);
  });
});

describe('formatJson', () => {
  it('returns valid JSON with summary and packages', () => {
    const evaluations = [
      {
        package: { name: 'bad', version: '1.0.0', changeType: 'added' },
        results: [{ ruleId: 'no-install-scripts', severity: 'block', description: 'Has install scripts' }],
        skipped: false,
        profileDiff: null,
      },
      {
        package: { name: 'ok', version: '2.0.0', previousVersion: '1.0.0', changeType: 'updated' },
        results: [{ ruleId: 'no-repository', severity: 'warn', description: 'No repo' }],
        skipped: false,
        profileDiff: null,
      },
      {
        package: { name: 'safe', version: '3.0.0', changeType: 'added' },
        results: [],
        skipped: false,
        profileDiff: null,
      },
    ];

    const raw = formatJson(evaluations);
    const parsed = JSON.parse(raw);

    assert.equal(parsed.packages.length, 3);
    assert.equal(parsed.summary.blocked, 1);
    assert.equal(parsed.summary.warnings, 1);
    assert.equal(parsed.summary.clean, 1);
    assert.equal(parsed.summary.skipped, 0);
    assert.equal(parsed.exitCode, 1);
  });

  it('includes registry warnings', () => {
    const evaluations = [
      { package: { name: 'a', version: '1.0.0' }, results: [], skipped: false, profileDiff: null },
    ];
    const raw = formatJson(evaluations, ['Registry unavailable for foo']);
    const parsed = JSON.parse(raw);

    assert.equal(parsed.registryWarnings.length, 1);
    assert.equal(parsed.registryWarnings[0], 'Registry unavailable for foo');
  });

  it('separates skipped from clean in summary', () => {
    const evaluations = [
      { package: { name: 'allowed', version: '1.0.0' }, results: [], skipped: true, profileDiff: null },
      { package: { name: 'checked', version: '2.0.0' }, results: [], skipped: false, profileDiff: null },
    ];
    const raw = formatJson(evaluations);
    const parsed = JSON.parse(raw);

    assert.equal(parsed.packages[0].skipped, true);
    assert.equal(parsed.summary.skipped, 1);
    assert.equal(parsed.summary.clean, 1);
  });

  it('includes profileDiff when present', () => {
    const profileDiff = {
      hasChanges: true,
      newNetwork: [{ address: '1.2.3.4', port: 80 }],
      newFileWrites: [],
      newProcesses: [],
      sizeChange: null,
    };
    const evaluations = [
      {
        package: { name: 'pkg', version: '2.0.0', previousVersion: '1.0.0' },
        results: [],
        skipped: false,
        profileDiff,
      },
    ];
    const raw = formatJson(evaluations);
    const parsed = JSON.parse(raw);

    assert.deepEqual(parsed.packages[0].profileDiff, profileDiff);
  });
});

describe('formatReport', () => {
  it('includes summary table when more than 5 packages', () => {
    const evaluations = [];
    for (let i = 0; i < 7; i++) {
      evaluations.push({
        package: { name: `pkg-${i}`, version: '1.0.0', changeType: 'added' },
        results: [],
        skipped: false,
        profileDiff: null,
      });
    }

    const report = formatReport(evaluations);
    // Table header should contain "Package" and "Status"
    assert.ok(report.includes('Package'));
    assert.ok(report.includes('Status'));
    // Each package should appear in the table
    for (let i = 0; i < 7; i++) {
      assert.ok(report.includes(`pkg-${i}`));
    }
  });

  it('omits summary table when 5 or fewer packages', () => {
    const evaluations = [
      {
        package: { name: 'only-one', version: '1.0.0', changeType: 'added' },
        results: [],
        skipped: false,
        profileDiff: null,
      },
    ];

    const report = formatReport(evaluations);
    // Should NOT contain the table separator line
    assert.ok(!report.includes('───'));
  });
});
