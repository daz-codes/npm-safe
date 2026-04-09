import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createHash } from 'node:crypto';

export async function snapshotNpmrc(projectDir = process.cwd()) {
  const paths = [
    join(projectDir, '.npmrc'),
    join(homedir(), '.npmrc'),
  ];

  const snapshots = {};
  for (const p of paths) {
    try {
      const content = await readFile(p, 'utf8');
      snapshots[p] = hashContent(content);
    } catch {
      snapshots[p] = null; // file doesn't exist
    }
  }
  return snapshots;
}

export async function verifyNpmrc(before) {
  const changes = [];
  for (const [path, prevHash] of Object.entries(before)) {
    let currentHash;
    try {
      const content = await readFile(path, 'utf8');
      currentHash = hashContent(content);
    } catch {
      currentHash = null;
    }

    if (prevHash !== currentHash) {
      if (prevHash === null && currentHash !== null) {
        changes.push({ path, type: 'created' });
      } else if (prevHash !== null && currentHash === null) {
        changes.push({ path, type: 'deleted' });
      } else {
        changes.push({ path, type: 'modified' });
      }
    }
  }
  return changes;
}

function hashContent(content) {
  return createHash('sha256').update(content).digest('hex');
}
