export const defaultRules = [
  {
    id: 'no-install-scripts',
    severity: 'block',
    description: 'Package defines lifecycle scripts (install/uninstall hooks)',
    check: (pkg, meta) => {
      const s = meta?.scripts;
      if (!s) return false;
      return 'preinstall' in s || 'install' in s || 'postinstall' in s ||
        'preuninstall' in s || 'uninstall' in s || 'postuninstall' in s;
    },
  },
  {
    id: 'no-repository',
    severity: 'warn',
    description: 'Package has no repository field in registry metadata',
    check: (pkg, meta) => meta != null && !meta.repository,
  },
  {
    id: 'new-transitive-dep',
    severity: 'warn',
    description: 'New transitive dependency introduced',
    check: (pkg, meta, prevMeta, context) =>
      context?.isTransitive && context?.isNew,
  },
  {
    id: 'maintainer-changed',
    severity: 'warn',
    description: 'Package maintainer changed between versions',
    check: (pkg, meta, prevMeta) => {
      if (!meta?.maintainers || !prevMeta?.maintainers) return false;
      const currentNames = new Set(meta.maintainers.map((m) => m.name));
      const prevNames = new Set(prevMeta.maintainers.map((m) => m.name));
      // Flag if any previous maintainer was removed
      for (const name of prevNames) {
        if (!currentNames.has(name)) return true;
      }
      return false;
    },
  },
  {
    id: 'sandbox-network-attempt',
    severity: 'block',
    description: 'Package attempted network access during install',
    check: (pkg, meta, prevMeta, context) =>
      context?.sandboxResult?.network?.length > 0,
  },
  {
    id: 'sandbox-unexpected-process',
    severity: 'warn',
    description: 'Package spawned unexpected process during install',
    check: (pkg, meta, prevMeta, context) => {
      const allowed = new Set(['node', 'npm', 'sh', 'bash', 'node-gyp', 'npx', 'corepack']);
      return context?.sandboxResult?.processes?.some(
        (p) => !allowed.has(p.command) && !allowed.has(p.executable?.split('/').pop())
      );
    },
  },
  {
    id: 'sandbox-file-write-outside-modules',
    severity: 'block',
    description: 'Package wrote files outside node_modules during install',
    check: (pkg, meta, prevMeta, context) => {
      return context?.sandboxResult?.fileWrites?.some(
        (f) => !f.path.startsWith('/sandbox/node_modules') && !f.path.startsWith('/sandbox/package')
      );
    },
  },
  {
    id: 'behaviour-diff-new-network',
    severity: 'block',
    description: 'New network endpoints detected compared to previous version',
    check: (pkg, meta, prevMeta, context) =>
      context?.profileDiff?.newNetwork?.length > 0,
  },
  {
    id: 'behaviour-diff-new-process',
    severity: 'warn',
    description: 'New processes spawned compared to previous version',
    check: (pkg, meta, prevMeta, context) =>
      context?.profileDiff?.newProcesses?.length > 0,
  },
  {
    id: 'behaviour-diff-new-file-write',
    severity: 'block',
    description: 'New file writes outside node_modules compared to previous version',
    check: (pkg, meta, prevMeta, context) =>
      context?.profileDiff?.newFileWrites?.some(
        (f) => !f.path.startsWith('/sandbox/node_modules') && !f.path.startsWith('/sandbox/package')
      ),
  },
  {
    id: 'behaviour-diff-size-change',
    severity: 'warn',
    description: 'Significant install size change compared to previous version',
    check: (pkg, meta, prevMeta, context) => {
      const diff = context?.profileDiff;
      if (!diff?.sizeChange) return false;
      // Flag if size changed by more than 2x or shrank by more than 50%
      return diff.sizeChange.ratio > 2 || diff.sizeChange.ratio < 0.5;
    },
  },
  // --- Phase 5: Dependency confusion ---
  {
    id: 'registry-source-changed',
    severity: 'block',
    description: 'Package resolved URL points to a different registry than before',
    check: (pkg, meta, prevMeta, context) => {
      if (!context?.resolved || !context?.previousResolved) return false;
      try {
        const currentHost = new URL(context.resolved).host;
        const previousHost = new URL(context.previousResolved).host;
        return currentHost !== previousHost;
      } catch {
        return false;
      }
    },
  },
  {
    id: 'unexpected-registry',
    severity: 'warn',
    description: 'Package resolves outside configured registries',
    check: (pkg, meta, prevMeta, context) => {
      const registries = context?.registries;
      if (!registries || registries.length === 0 || !context?.resolved) return false;
      try {
        const resolvedHost = new URL(context.resolved).host;
        const allowedHosts = registries.map((r) => new URL(r).host);
        return !allowedHosts.includes(resolvedHost);
      } catch {
        return false;
      }
    },
  },
  // --- Phase 5: Enhanced maintainer analysis ---
  {
    id: 'maintainer-added',
    severity: 'info',
    description: 'New maintainer added to package',
    check: (pkg, meta, prevMeta) => {
      if (!meta?.maintainers || !prevMeta?.maintainers) return false;
      const currentNames = new Set(meta.maintainers.map((m) => m.name));
      const prevNames = new Set(prevMeta.maintainers.map((m) => m.name));
      for (const name of currentNames) {
        if (!prevNames.has(name)) return true;
      }
      return false;
    },
  },
  // --- Phase 5: Publish pattern heuristics ---
  {
    id: 'rapid-publish',
    severity: 'warn',
    description: 'Multiple versions published within 24 hours',
    check: (pkg, meta, prevMeta) => {
      if (!meta?.time || !prevMeta?.time) return false;
      try {
        const currentTime = new Date(meta.time).getTime();
        const prevTime = new Date(prevMeta.time).getTime();
        const dayMs = 24 * 60 * 60 * 1000;
        return Math.abs(currentTime - prevTime) < dayMs;
      } catch {
        return false;
      }
    },
  },
  {
    id: 'version-gap',
    severity: 'warn',
    description: 'Unexpected version number jump',
    check: (pkg) => {
      if (!pkg.previousVersion || !pkg.version) return false;
      try {
        // Strip pre-release suffix before parsing (e.g. "1.0.0-beta.1" → "1.0.0")
        const prev = pkg.previousVersion.split('-')[0].split('.').map((s) => parseInt(s, 10));
        const curr = pkg.version.split('-')[0].split('.').map((s) => parseInt(s, 10));
        if (prev.some(Number.isNaN) || curr.some(Number.isNaN)) return false;
        // Flag if major jumps by more than 2, or minor jumps by more than 20
        const majorDiff = (curr[0] || 0) - (prev[0] || 0);
        const minorDiff = (curr[1] || 0) - (prev[1] || 0);
        return majorDiff > 2 || (majorDiff === 0 && minorDiff > 20);
      } catch {
        return false;
      }
    },
  },
  // --- Phase 5: npmrc sandbox detection ---
  {
    id: 'sandbox-npmrc-write',
    severity: 'block',
    description: 'Package attempted to write .npmrc during install',
    check: (pkg, meta, prevMeta, context) => {
      return context?.sandboxResult?.fileWrites?.some(
        (f) => f.path.endsWith('.npmrc') || f.path === '/sandbox/.npmrc'
      );
    },
  },
  // --- Phase 7: Lockfile integrity ---
  {
    id: 'integrity-mismatch',
    severity: 'block',
    description: 'Package tarball hash does not match lockfile integrity',
    check: (pkg, meta, prevMeta, context) =>
      context?.integrityMismatch === true,
  },
  // --- Phase 7: Typosquat detection ---
  {
    id: 'typosquat-suspect',
    severity: 'warn',
    description: 'Package name is suspiciously similar to a popular package',
    check: (pkg, meta, prevMeta, context) =>
      context?.typosquat != null,
  },
  // --- Phase 7: Provenance ---
  {
    id: 'no-provenance',
    severity: 'info',
    description: 'Package has no SLSA provenance attestation',
    check: (pkg, meta, prevMeta, context) =>
      context?.provenance?.hasProvenance === false,
  },
  // --- Phase 7: Starjacking ---
  {
    id: 'starjacking-suspect',
    severity: 'warn',
    description: 'Package claims a popular repository it may not belong to',
    check: (pkg, meta, prevMeta, context) =>
      context?.starjacking != null,
  },
  // --- License check ---
  {
    id: 'no-license',
    severity: 'warn',
    description: 'Package has no license declared',
    check: (pkg, meta) => {
      if (!meta) return false;
      const license = meta.license;
      if (!license) return true;
      if (typeof license === 'string') {
        const norm = license.trim().toUpperCase();
        // UNLICENSED is a deliberate "proprietary" declaration, not a missing license
        if (norm === '' || norm === 'NONE' || norm === 'SEE LICENSE IN LICENSE') return true;
      }
      return false;
    },
  },
  // --- Download anomaly detection ---
  {
    id: 'low-download-count',
    severity: 'warn',
    description: 'Newly added package has very low weekly download count',
    check: (pkg, meta, prevMeta, context) =>
      context?.isNew &&
      context?.weeklyDownloads != null &&
      context.weeklyDownloads < 100,
  },
  {
    id: 'dormant-package',
    severity: 'warn',
    description: 'Package had no new versions for over a year before this release',
    check: (pkg, meta, prevMeta, context) =>
      context?.dormant === true,
  },
  // --- Release age ---
  {
    id: 'recent-release',
    severity: 'warn',
    description: 'This version was published less than 7 days ago',
    check: (pkg, meta) => {
      if (!meta?.time) return false;
      try {
        const publishedAt = new Date(meta.time).getTime();
        if (Number.isNaN(publishedAt)) return false;
        const sevenDays = 7 * 24 * 60 * 60 * 1000;
        return (Date.now() - publishedAt) < sevenDays;
      } catch {
        return false;
      }
    },
  },
  // --- Scoped package awareness ---
  {
    id: 'scope-changed',
    severity: 'block',
    description: 'An unscoped package appeared where a scoped package was previously installed',
    check: (pkg, meta, prevMeta, context) =>
      context?.scopeChanged === true,
  },
];
