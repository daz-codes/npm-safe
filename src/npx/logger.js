import { appendFile, readFile, writeFile, stat } from 'node:fs/promises';
import { join } from 'node:path';

const LOG_FILE = '.npm-safe-npx.log';
const MAX_LOG_BYTES = 1024 * 1024; // 1 MB

export async function logInvocation(projectDir, entry) {
  const logPath = join(projectDir, LOG_FILE);
  const line = JSON.stringify({
    timestamp: new Date().toISOString(),
    package: entry.name,
    version: entry.version,
    result: entry.blocked ? 'blocked' : entry.skipped ? 'skipped' : 'allowed',
    violations: entry.results?.length || 0,
  }) + '\n';

  // Rotate if log exceeds max size: keep the most recent half
  try {
    const info = await stat(logPath);
    if (info.size > MAX_LOG_BYTES) {
      const raw = await readFile(logPath, 'utf8');
      const lines = raw.trim().split('\n');
      const keep = lines.slice(Math.floor(lines.length / 2));
      await writeFile(logPath, keep.join('\n') + '\n');
    }
  } catch {
    // File doesn't exist yet — will be created by appendFile
  }

  await appendFile(logPath, line);
}

export async function getLastAuditDate(projectDir, name) {
  const logPath = join(projectDir, LOG_FILE);
  let raw;
  try {
    raw = await readFile(logPath, 'utf8');
  } catch {
    return null;
  }

  const lines = raw.trim().split('\n').filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const entry = JSON.parse(lines[i]);
      if (entry.package === name) {
        return new Date(entry.timestamp);
      }
    } catch {
      continue;
    }
  }
  return null;
}
