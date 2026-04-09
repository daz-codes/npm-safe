const REGISTRY_BASE = 'https://registry.npmjs.org';
const FETCH_TIMEOUT_MS = 15000;

export function createRegistryClient() {
  const cache = new Map();
  const warnings = [];

  return { fetchMetadata, fetchVersionMetadata, warnings };

  async function fetchMetadata(name) {
    const cacheKey = name;
    if (cache.has(cacheKey)) return cache.get(cacheKey);

    let res;
    try {
      const url = `${REGISTRY_BASE}/${encodeURIComponent(name).replace('%40', '@')}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      try {
        res = await fetch(url, { signal: controller.signal });
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      const msg = err.name === 'AbortError'
        ? `Registry timeout for ${name} (${FETCH_TIMEOUT_MS}ms)`
        : `Registry unavailable for ${name}: ${err.message}`;
      warnings.push(msg);
      return null;
    }

    if (!res.ok) {
      if (res.status === 404) {
        cache.set(cacheKey, null);
        return null;
      }
      warnings.push(`Registry fetch failed for ${name}: HTTP ${res.status}`);
      cache.set(cacheKey, null);
      return null;
    }

    let data;
    try {
      data = await res.json();
    } catch {
      warnings.push(`Registry returned invalid JSON for ${name}`);
      return null;
    }
    cache.set(cacheKey, data);
    return data;
  }

  async function fetchVersionMetadata(name, version) {
    const cacheKey = `${name}@${version}`;
    if (cache.has(cacheKey)) return cache.get(cacheKey);

    const full = await fetchMetadata(name);
    if (!full) return null;

    const versionData = full.versions?.[version];
    if (!versionData) return null;

    const extracted = {
      name: versionData.name,
      version: versionData.version,
      scripts: versionData.scripts || {},
      repository: versionData.repository || full.repository || null,
      maintainers: versionData.maintainers || full.maintainers || [],
      license: versionData.license || full.license || null,
      dist: versionData.dist || {},
      time: full.time?.[version] || null,
    };

    cache.set(cacheKey, extracted);
    return extracted;
  }
}
