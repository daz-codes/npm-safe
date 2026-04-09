import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export async function takeSnapshot(projectDir = process.cwd()) {
  const lockPath = join(projectDir, 'package-lock.json');
  const raw = await readFile(lockPath, 'utf8');
  const lock = JSON.parse(raw);
  return parseLockfile(lock);
}

export function parseLockfile(lock) {
  const packages = new Map();

  if (!lock.packages) {
    // v1 lockfiles use "dependencies" instead of "packages" — not supported
    if (lock.dependencies || lock.lockfileVersion === 1) {
      throw new Error(
        'Lockfile v1 format is not supported. Upgrade to npm 7+ (lockfileVersion 2 or 3) by running: npm i --package-lock-only'
      );
    }
    return packages;
  }

  // v2/v3 format uses "packages" keyed by path
  for (const [path, entry] of Object.entries(lock.packages)) {
    // Skip the root package (empty string key)
    if (path === '') continue;

    // Skip workspace/link entries that don't go through node_modules
    // (e.g. "packages/my-lib") — these are local references, not registry packages
    if (!path.includes('node_modules/')) continue;

    // Skip entries without a version (link: dependencies, workspace cross-refs)
    if (!entry.version) continue;

    const name = extractName(path);
    const depth = (path.match(/node_modules/g) || []).length;
    // Use path-based key to avoid collisions when the same package
    // appears at different nesting levels (e.g. hoisted vs nested)
    const key = depth > 1
      ? `${name}@${entry.version}:${path}`
      : `${name}@${entry.version}`;

    packages.set(key, {
      name,
      version: entry.version,
      resolved: entry.resolved || null,
      integrity: entry.integrity || null,
      dev: entry.dev || false,
      hasScripts: hasInstallScripts(entry),
      dependencies: entry.dependencies || {},
      optional: entry.optional || false,
    });
  }

  return packages;
}

function extractName(lockfilePath) {
  // "node_modules/@scope/pkg" → "@scope/pkg"
  // "node_modules/pkg" → "pkg"
  // "node_modules/a/node_modules/b" → "b"
  const parts = lockfilePath.split('node_modules/');
  return parts[parts.length - 1];
}

function hasInstallScripts(entry) {
  return Boolean(entry.hasInstallScript);
}
