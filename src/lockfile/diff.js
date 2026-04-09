export function diffSnapshots(before, after) {
  const added = new Map();
  const removed = new Map();
  const updated = new Map();
  const unchanged = new Map();

  // Index before snapshot by name for efficient lookup
  const beforeByName = buildNameIndex(before);
  const afterByName = buildNameIndex(after);

  // Track which before entries have been matched
  const matchedBefore = new Set();

  for (const [key, pkg] of after) {
    const candidates = beforeByName.get(pkg.name);

    if (!candidates || candidates.length === 0) {
      added.set(key, pkg);
      continue;
    }

    // Try to find exact match: same version, resolved URL, and integrity hash.
    // A same-version republish with different resolved/integrity is an update, not unchanged.
    const exact = candidates.find(
      (c) => c.version === pkg.version
        && c.resolved === pkg.resolved
        && c.integrity === pkg.integrity
    );
    if (exact) {
      unchanged.set(key, pkg);
      matchedBefore.add(exact.key);
      continue;
    }

    // No exact match — this is an update or a new entry.
    // Prefer unmatched candidates to avoid double-counting.
    const unmatched = candidates.find((c) => !matchedBefore.has(c.key));
    if (unmatched) {
      updated.set(key, { ...pkg, previousVersion: unmatched.version, previousResolved: unmatched.resolved || null });
      matchedBefore.add(unmatched.key);
    } else {
      // All candidates already matched — treat as added rather than
      // claiming a predecessor that's already used by another entry
      added.set(key, pkg);
    }
  }

  // Anything in before not matched is removed
  for (const [key, pkg] of before) {
    if (!matchedBefore.has(key)) {
      removed.set(key, pkg);
    }
  }

  return { added, removed, updated, unchanged };
}

function buildNameIndex(snapshot) {
  const index = new Map();
  for (const [key, pkg] of snapshot) {
    if (!index.has(pkg.name)) {
      index.set(pkg.name, []);
    }
    index.get(pkg.name).push({ key, ...pkg });
  }
  return index;
}

export function getChangedPackages(diff) {
  const changed = new Map();
  for (const [key, pkg] of diff.added) changed.set(key, { ...pkg, changeType: 'added' });
  for (const [key, pkg] of diff.updated) changed.set(key, { ...pkg, changeType: 'updated' });
  return changed;
}
