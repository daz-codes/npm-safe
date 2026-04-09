const DOWNLOADS_BASE = 'https://api.npmjs.org/downloads/point/last-week';
const FETCH_TIMEOUT_MS = 10000;

export async function fetchWeeklyDownloads(name, warnings = []) {
  const url = `${DOWNLOADS_BASE}/${encodeURIComponent(name).replace('%40', '@')}`;

  let res;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      res = await fetch(url, { signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    const msg = err.name === 'AbortError'
      ? `Download count timeout for ${name}`
      : `Download count unavailable for ${name}: ${err.message}`;
    warnings.push(msg);
    return null;
  }

  if (!res.ok) return null;

  let data;
  try {
    data = await res.json();
  } catch {
    return null;
  }

  return typeof data.downloads === 'number' ? data.downloads : null;
}

export function isDormantPackage(fullMeta, currentVersion) {
  const times = fullMeta?.time;
  if (!times || !times[currentVersion]) return false;

  const currentTime = new Date(times[currentVersion]).getTime();
  if (Number.isNaN(currentTime)) return false;

  // Find the version published immediately before this one
  // Filter out versions published after currentVersion to avoid negative gaps
  const versions = Object.keys(times)
    .filter((k) => k !== 'created' && k !== 'modified' && k !== currentVersion)
    .map((v) => ({ version: v, time: new Date(times[v]).getTime() }))
    .filter((v) => !Number.isNaN(v.time) && v.time <= currentTime)
    .sort((a, b) => b.time - a.time);

  if (versions.length === 0) return false;

  // Most recent previous version
  const previousTime = versions[0].time;

  // Dormant if gap between current and previous exceeds 1 year
  const oneYear = 365 * 24 * 60 * 60 * 1000;
  return (currentTime - previousTime) > oneYear;
}
