import { readFile, writeFile, access } from 'node:fs/promises';
import { join } from 'node:path';

const CONFIG_FILES = ['.npm-safe.json', 'npm-safe.json'];

const DEFAULT_CONFIG = {
  allowlist: [],
  rules: {},
  autoApprove: false,
};

function cloneDefaults() {
  return {
    allowlist: [...DEFAULT_CONFIG.allowlist],
    rules: { ...DEFAULT_CONFIG.rules },
    autoApprove: DEFAULT_CONFIG.autoApprove,
  };
}

const KNOWN_KEYS = new Set([
  '$schema', 'allowlist', 'rules', 'autoApprove', 'sandbox', 'profiles',
  'registries', 'npx', 'scriptApprovals',
]);

const KNOWN_SANDBOX_KEYS = new Set([
  'enabled', 'timeout', 'memoryLimit', 'cpuLimit',
]);

async function findConfigPath(projectDir) {
  for (const name of CONFIG_FILES) {
    const candidate = join(projectDir, name);
    try {
      await access(candidate);
      return candidate;
    } catch {
      continue;
    }
  }
  return null;
}

export async function loadConfig(projectDir = process.cwd()) {
  const configPath = await findConfigPath(projectDir);
  let config;

  if (!configPath) {
    config = cloneDefaults();
  } else {
    try {
      const raw = await readFile(configPath, 'utf8');
      const parsed = JSON.parse(raw);
      validateConfig(parsed, configPath);
      config = { ...cloneDefaults(), ...parsed };
    } catch (err) {
      if (err.isValidation) throw err;
      throw new Error(`Failed to load config: ${err.message}`);
    }
  }

  // Environment variable overrides for CI
  if (process.env.SAFE_INSTALL_SANDBOX === 'true') {
    config.sandbox = { ...config.sandbox, enabled: true };
  } else if (process.env.SAFE_INSTALL_SANDBOX === 'false') {
    config.sandbox = { ...config.sandbox, enabled: false };
  }

  return config;
}

export async function addToAllowlist(pkgSpec, projectDir = process.cwd()) {
  const config = await loadConfig(projectDir);
  if (config.allowlist.includes(pkgSpec)) return config;

  // Read the raw file config (without defaults) so we only persist user-defined fields
  const configPath = (await findConfigPath(projectDir)) || join(projectDir, CONFIG_FILES[0]);
  let fileConfig;
  try {
    fileConfig = JSON.parse(await readFile(configPath, 'utf8'));
  } catch {
    fileConfig = {};
  }
  if (!fileConfig.allowlist) fileConfig.allowlist = [];
  fileConfig.allowlist.push(pkgSpec);
  await writeFile(configPath, JSON.stringify(fileConfig, null, 2) + '\n');

  config.allowlist.push(pkgSpec);
  return config;
}

export async function approveScripts(pkgSpec, projectDir = process.cwd()) {
  const config = await loadConfig(projectDir);

  const approval = {
    approved: new Date().toISOString().split('T')[0],
    by: process.env.USER || process.env.USERNAME || 'unknown',
  };

  // Read the raw file config (without defaults) so we only persist user-defined fields
  const configPath = (await findConfigPath(projectDir)) || join(projectDir, CONFIG_FILES[0]);
  let fileConfig;
  try {
    fileConfig = JSON.parse(await readFile(configPath, 'utf8'));
  } catch {
    fileConfig = {};
  }
  if (!fileConfig.scriptApprovals) fileConfig.scriptApprovals = {};
  fileConfig.scriptApprovals[pkgSpec] = approval;
  await writeFile(configPath, JSON.stringify(fileConfig, null, 2) + '\n');

  if (!config.scriptApprovals) config.scriptApprovals = {};
  config.scriptApprovals[pkgSpec] = approval;
  return config;
}

function validateConfig(parsed, configPath) {
  const errors = [];

  // Check for unknown top-level keys
  for (const key of Object.keys(parsed)) {
    if (!KNOWN_KEYS.has(key)) {
      errors.push(`Unknown config key "${key}"`);
    }
  }

  // Type checks for critical fields
  if (parsed.allowlist !== undefined && !Array.isArray(parsed.allowlist)) {
    errors.push('"allowlist" must be an array');
  }
  if (parsed.rules !== undefined && (typeof parsed.rules !== 'object' || Array.isArray(parsed.rules))) {
    errors.push('"rules" must be an object');
  }
  if (parsed.autoApprove !== undefined && typeof parsed.autoApprove !== 'boolean') {
    errors.push('"autoApprove" must be a boolean');
  }

  // Validate sandbox sub-keys
  if (parsed.sandbox && typeof parsed.sandbox === 'object') {
    for (const key of Object.keys(parsed.sandbox)) {
      if (!KNOWN_SANDBOX_KEYS.has(key)) {
        errors.push(`Unknown sandbox config key "${key}"`);
      }
    }
  }

  if (errors.length > 0) {
    const err = new Error(`Invalid config in ${configPath}:\n  - ${errors.join('\n  - ')}`);
    err.isValidation = true;
    throw err;
  }
}

export function isScriptApproved(pkgSpec, config) {
  if (!config.scriptApprovals) return false;
  // Check exact match or wildcard
  if (config.scriptApprovals[pkgSpec]) return true;
  const name = pkgSpec.split('@').slice(0, -1).join('@') || pkgSpec;
  if (config.scriptApprovals[`${name}@*`]) return true;
  return false;
}
