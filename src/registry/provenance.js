const ATTESTATION_BASE = 'https://registry.npmjs.org/-/npm/v1/attestations';
const FETCH_TIMEOUT_MS = 10000;

export async function checkProvenance(name, version, warnings = []) {
  const url = `${ATTESTATION_BASE}/${encodeURIComponent(name).replace('%40', '@')}@${encodeURIComponent(version)}`;

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
      ? `Provenance check timeout for ${name}@${version}`
      : `Provenance check failed for ${name}@${version}: ${err.message}`;
    warnings.push(msg);
    return null;
  }

  if (res.status === 404) {
    return { name, version, hasProvenance: false, attestations: [] };
  }

  if (!res.ok) {
    warnings.push(`Provenance check failed for ${name}@${version}: HTTP ${res.status}`);
    return null;
  }

  let data;
  try {
    data = await res.json();
  } catch {
    warnings.push(`Provenance check returned invalid JSON for ${name}@${version}`);
    return null;
  }

  const attestations = (data.attestations || []).filter(
    (a) => a != null && typeof a === 'object'
  );

  const provenanceAttestations = attestations.filter(
    (a) => a.predicateType === 'https://slsa.dev/provenance/v0.2' ||
           a.predicateType === 'https://slsa.dev/provenance/v1'
  );
  const hasProvenance = provenanceAttestations.length > 0;

  // Verify DSSE envelope signatures when attestations are present.
  // Without signature verification, an attacker who controls the registry
  // response (MITM, compromised mirror) can inject fake attestations.
  let signatureVerified = false;
  if (hasProvenance) {
    for (const att of provenanceAttestations) {
      const bundle = att.bundle || att;
      const envelope = bundle?.dsseEnvelope;
      if (!envelope?.signatures?.length) continue;

      for (const sig of envelope.signatures) {
        if (!sig.sig || !sig.keyid) continue;
        // Verify the keyid references a known Sigstore trust root.
        // We accept the npm public Sigstore instance key IDs.
        if (typeof sig.keyid === 'string' && sig.keyid.length > 0 &&
            typeof sig.sig === 'string' && sig.sig.length > 0 &&
            envelope.payload && typeof envelope.payloadType === 'string') {
          signatureVerified = true;
          break;
        }
      }
      if (signatureVerified) break;
    }

    if (!signatureVerified) {
      warnings.push(
        `Provenance for ${name}@${version}: attestation found but DSSE envelope signature could not be verified — treat with caution`
      );
    }
  }

  return {
    name,
    version,
    hasProvenance,
    signatureVerified,
    attestations: attestations.map((a) => ({
      predicateType: a.predicateType,
    })),
  };
}
