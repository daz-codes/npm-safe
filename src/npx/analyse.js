import { createRegistryClient } from '../registry/metadata.js';
import { createEngine } from '../rules/engine.js';
import { checkTyposquat } from '../rules/typosquat.js';
import { checkStarjacking } from '../rules/starjacking.js';
import { checkProvenance } from '../registry/provenance.js';
import { fetchWeeklyDownloads, isDormantPackage } from '../registry/downloads.js';

// Rules relevant to npx (no lockfile/sandbox context)
const NPX_RULE_IDS = new Set([
  'no-install-scripts',
  'no-repository',
  'typosquat-suspect',
  'no-provenance',
  'starjacking-suspect',
  'low-download-count',
  'dormant-package',
  'recent-release',
]);

export async function analysePackage(name, version, config = {}) {
  const registry = createRegistryClient();
  const engine = createEngine(config);

  // Resolve "latest" if no version specified
  let resolvedVersion = version;
  if (!resolvedVersion) {
    const full = await registry.fetchMetadata(name);
    if (!full) {
      return {
        name,
        version: null,
        error: `Package "${name}" not found in registry`,
        results: [],
        blocked: false,
        warnings: registry.warnings,
      };
    }
    resolvedVersion = full['dist-tags']?.latest;
    if (!resolvedVersion) {
      return {
        name,
        version: null,
        error: `No latest version found for "${name}"`,
        results: [],
        blocked: false,
        warnings: registry.warnings,
      };
    }
  }

  const meta = await registry.fetchVersionMetadata(name, resolvedVersion);
  if (!meta) {
    return {
      name,
      version: resolvedVersion,
      error: `Version "${resolvedVersion}" not found for "${name}"`,
      results: [],
      blocked: false,
      warnings: registry.warnings,
    };
  }

  const pkg = { name, version: resolvedVersion };

  // Compute additional context for npx-relevant rules
  const typosquat = checkTyposquat(name);
  const starjacking = checkStarjacking(name, meta);

  let provenance = null;
  try {
    provenance = await checkProvenance(name, resolvedVersion, registry.warnings);
  } catch {
    // Non-fatal
  }

  const weeklyDownloads = await fetchWeeklyDownloads(name, registry.warnings);

  let dormant = false;
  const fullMeta = await registry.fetchMetadata(name);
  if (fullMeta) dormant = isDormantPackage(fullMeta, resolvedVersion);

  const context = {
    isNew: true,
    isTransitive: false,
    typosquat,
    starjacking,
    provenance,
    weeklyDownloads,
    dormant,
  };

  const evaluation = engine.evaluate(pkg, meta, null, context);

  // Filter to only npx-relevant rules
  const relevant = evaluation.results.filter((r) => NPX_RULE_IDS.has(r.ruleId));
  const blocked = relevant.some((r) => r.severity === 'block');

  return {
    name,
    version: resolvedVersion,
    error: null,
    results: relevant,
    skipped: evaluation.skipped,
    blocked,
    warnings: registry.warnings,
  };
}

export function parsePackageSpec(spec) {
  // "pkg" → { name: "pkg", version: null }
  // "pkg@1.0.0" → { name: "pkg", version: "1.0.0" }
  // "@scope/pkg" → { name: "@scope/pkg", version: null }
  // "@scope/pkg@1.0.0" → { name: "@scope/pkg", version: "1.0.0" }
  if (spec.startsWith('@')) {
    // Scoped package
    const rest = spec.slice(1);
    const atIdx = rest.indexOf('@');
    if (atIdx === -1) return { name: spec, version: null };
    return { name: '@' + rest.slice(0, atIdx), version: rest.slice(atIdx + 1) };
  }
  const atIdx = spec.indexOf('@');
  if (atIdx === -1) return { name: spec, version: null };
  return { name: spec.slice(0, atIdx), version: spec.slice(atIdx + 1) };
}
