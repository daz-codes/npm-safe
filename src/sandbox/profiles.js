import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';

function assertSafePath(base, target) {
  const resolvedBase = resolve(base);
  const resolvedTarget = resolve(target);
  if (!resolvedTarget.startsWith(resolvedBase + '/') && resolvedTarget !== resolvedBase) {
    throw new Error(`Path traversal blocked: ${target} escapes ${base}`);
  }
}

export function createProfileStore(profileDir = './profiles') {
  return { saveProfile, loadProfile, loadPreviousProfile };

  async function saveProfile(packageName, version, profile) {
    const dir = join(profileDir, packageName);
    assertSafePath(profileDir, dir);
    const filePath = join(dir, `${version}.json`);
    assertSafePath(profileDir, filePath);
    await mkdir(dir, { recursive: true });
    await writeFile(filePath, JSON.stringify(profile, null, 2) + '\n');
  }

  async function loadProfile(packageName, version) {
    const filePath = join(profileDir, packageName, `${version}.json`);
    assertSafePath(profileDir, filePath);
    try {
      const raw = await readFile(filePath, 'utf8');
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  async function loadPreviousProfile(packageName, currentVersion) {
    const dir = join(profileDir, packageName);
    assertSafePath(profileDir, dir);
    let entries;
    try {
      entries = await readdir(dir);
    } catch {
      return null;
    }

    const versions = entries
      .filter((f) => f.endsWith('.json'))
      .map((f) => f.replace('.json', ''))
      .filter((v) => v !== currentVersion && compareSemver(v, currentVersion) < 0)
      .sort(compareSemver);

    if (versions.length === 0) return null;

    // Return the highest version below the current one
    return loadProfile(packageName, versions[versions.length - 1]);
  }
}

function compareSemver(a, b) {
  // Split off pre-release at the first hyphen: "1.0.0-beta.1" → ["1.0.0", "beta.1"]
  // Use indexOf to preserve hyphens within the pre-release identifier
  const aHyphen = a.indexOf('-');
  const [aVer, aPre] = aHyphen === -1 ? [a, undefined] : [a.slice(0, aHyphen), a.slice(aHyphen + 1)];
  const bHyphen = b.indexOf('-');
  const [bVer, bPre] = bHyphen === -1 ? [b, undefined] : [b.slice(0, bHyphen), b.slice(bHyphen + 1)];

  const pa = aVer.split('.').map(Number);
  const pb = bVer.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na !== nb) return na - nb;
  }

  // Equal major.minor.patch — pre-release sorts before release
  if (aPre && !bPre) return -1;
  if (!aPre && bPre) return 1;
  if (aPre && bPre) return aPre < bPre ? -1 : aPre > bPre ? 1 : 0;
  return 0;
}

export function diffProfiles(prev, current) {
  if (!prev || !current) return null;

  const newNetwork = (current.network || []).filter(
    (n) => !(prev.network || []).some((p) => p.address === n.address && p.port === n.port)
  );

  const newFileWrites = (current.fileWrites || []).filter(
    (f) => !(prev.fileWrites || []).some((p) => p.path === f.path)
  );

  const newProcesses = (current.processes || []).filter(
    (p) => !(prev.processes || []).some((pp) => pp.command === p.command)
  );

  let sizeChange = null;
  if (prev.fileCount != null && current.fileCount != null && prev.fileCount > 0) {
    sizeChange = {
      before: prev.fileCount,
      after: current.fileCount,
      ratio: current.fileCount / prev.fileCount,
    };
  }

  const hasChanges = newNetwork.length > 0
    || newFileWrites.length > 0
    || newProcesses.length > 0
    || (sizeChange != null && (sizeChange.ratio > 2 || sizeChange.ratio < 0.5));

  return {
    hasChanges,
    newNetwork,
    newFileWrites,
    newProcesses,
    sizeChange,
  };
}
