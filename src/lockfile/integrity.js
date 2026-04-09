import { createHash } from 'node:crypto';

const FETCH_TIMEOUT_MS = 15000;

// Reject resolved URLs that could cause SSRF
function isAllowedUrl(urlStr) {
  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch {
    return false;
  }

  if (parsed.protocol !== 'https:') return false;

  const hostname = parsed.hostname.toLowerCase();

  // Reject localhost and common loopback names
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '[::1]') {
    return false;
  }

  // Reject private/reserved IPv4 ranges
  const ipv4 = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [, a, b] = ipv4.map(Number);
    if (a === 10) return false;                        // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return false; // 172.16.0.0/12
    if (a === 192 && b === 168) return false;           // 192.168.0.0/16
    if (a === 169 && b === 254) return false;           // 169.254.0.0/16 (link-local / cloud metadata)
    if (a === 127) return false;                        // 127.0.0.0/8
    if (a === 0) return false;                          // 0.0.0.0/8
  }

  return true;
}

export async function verifyIntegrity(snapshot, warnings = []) {
  const results = [];

  for (const [key, pkg] of snapshot) {
    if (!pkg.resolved || !pkg.integrity) continue;

    const verification = await verifyPackage(pkg, warnings);
    if (verification) {
      results.push(verification);
    }
  }

  return results;
}

async function verifyPackage(pkg, warnings) {
  const { name, version, resolved, integrity } = pkg;

  // Parse the integrity string, which may contain multiple space-separated hashes (SRI format).
  // Use the strongest available algorithm: sha512 > sha384 > sha256 > sha1.
  const hashes = integrity.split(' ')
    .map((h) => h.match(/^(sha(?:1|256|384|512))-([A-Za-z0-9+/=]+)$/))
    .filter(Boolean)
    .map(([, alg, hash]) => ({ algorithm: alg, expectedHash: hash }));

  if (hashes.length === 0) {
    warnings.push(`Integrity check: unsupported hash algorithm for ${name}@${version} (${integrity})`);
    return null;
  }

  const STRENGTH = { sha1: 0, sha256: 1, sha384: 2, sha512: 3 };
  hashes.sort((a, b) => (STRENGTH[b.algorithm] || 0) - (STRENGTH[a.algorithm] || 0));
  const { algorithm, expectedHash } = hashes[0];

  if (algorithm === 'sha1') {
    warnings.push(`Integrity check: ${name}@${version} uses only sha1 (weak) — consider upgrading lockfile`);
  }

  if (!isAllowedUrl(resolved)) {
    warnings.push(`Integrity check: blocked SSRF-risk URL for ${name}@${version}: ${resolved}`);
    return null;
  }

  let tarball;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(resolved, { signal: controller.signal });
      if (!res.ok) {
        warnings.push(`Integrity check: failed to download ${name}@${version} (HTTP ${res.status})`);
        return null;
      }
      tarball = Buffer.from(await res.arrayBuffer());
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    const msg = err.name === 'AbortError'
      ? `Integrity check: timeout downloading ${name}@${version}`
      : `Integrity check: failed to download ${name}@${version}: ${err.message}`;
    warnings.push(msg);
    return null;
  }

  const actualHash = createHash(algorithm).update(tarball).digest('base64');

  if (actualHash !== expectedHash) {
    return {
      name,
      version,
      resolved,
      expected: integrity,
      actual: `${algorithm}-${actualHash}`,
    };
  }

  return null;
}
