import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseStraceLog } from './monitor.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, '..', '..', 'test', 'fixtures');

describe('parseStraceLog', () => {
  it('extracts network calls from malicious strace', async () => {
    const raw = await readFile(join(FIXTURES, 'strace-malicious.log'), 'utf8');
    const result = parseStraceLog(raw);

    assert.ok(result.network.length > 0, 'should detect network calls');
    const connectCall = result.network.find((n) => n.syscall === 'connect');
    assert.ok(connectCall);
    assert.equal(connectCall.address, '93.184.216.34');
    assert.equal(connectCall.port, 443);
  });

  it('extracts file writes outside node_modules', async () => {
    const raw = await readFile(join(FIXTURES, 'strace-malicious.log'), 'utf8');
    const result = parseStraceLog(raw);

    const paths = result.fileWrites.map((f) => f.path);
    assert.ok(paths.includes('/tmp/evil-payload'), 'should detect /tmp write');
    // /dev/null and /proc should be filtered out
    assert.ok(!paths.includes('/dev/null'));
    assert.ok(!paths.includes('/proc/self/status'));
  });

  it('extracts process spawns', async () => {
    const raw = await readFile(join(FIXTURES, 'strace-malicious.log'), 'utf8');
    const result = parseStraceLog(raw);

    const commands = result.processes.map((p) => p.command);
    assert.ok(commands.includes('curl'), 'should detect curl');
    assert.ok(commands.includes('sh'), 'should detect sh');
    assert.ok(commands.includes('node'), 'should detect node');
  });

  it('returns clean results for benign strace', async () => {
    const raw = await readFile(join(FIXTURES, 'strace-clean.log'), 'utf8');
    const result = parseStraceLog(raw);

    assert.equal(result.network.length, 0, 'no network calls expected');
    // Only writes inside /sandbox are expected
    for (const f of result.fileWrites) {
      assert.ok(f.path.startsWith('/sandbox/'), `unexpected write: ${f.path}`);
    }
  });

  it('deduplicates entries', async () => {
    const raw = await readFile(join(FIXTURES, 'strace-malicious.log'), 'utf8');
    const result = parseStraceLog(raw);

    // connect and sendto both hit 93.184.216.34:443 — should dedup
    const hits = result.network.filter((n) => n.address === '93.184.216.34' && n.port === 443);
    assert.equal(hits.length, 1, 'duplicate network entries should be deduped');
  });
});
