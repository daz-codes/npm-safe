import { defaultRules } from './defaults.js';

const VALID_SEVERITIES = new Set(['block', 'warn', 'info']);

export function createEngine(config = {}) {
  const ruleOverrides = config.rules || {};
  const allowlist = config.allowlist || [];

  const rules = defaultRules
    .map((rule) => {
      const override = ruleOverrides[rule.id];
      if (!override) return rule;
      if (override.enabled === false) return null;
      const severity = override.severity || rule.severity;
      if (override.severity && !VALID_SEVERITIES.has(override.severity)) {
        throw new Error(
          `Invalid severity "${override.severity}" for rule "${rule.id}". Must be one of: block, warn, info`
        );
      }
      return { ...rule, severity };
    })
    .filter(Boolean);

  return { evaluate, rules };

  function evaluate(pkg, meta, prevMeta, context) {
    // Check allowlist
    if (isAllowlisted(pkg, allowlist)) {
      return { package: pkg, results: [], skipped: true, profileDiff: null };
    }

    const results = [];
    for (const rule of rules) {
      try {
        const triggered = rule.check(pkg, meta, prevMeta, context);
        if (triggered) {
          results.push({
            ruleId: rule.id,
            severity: rule.severity,
            description: rule.description,
          });
        }
      } catch (err) {
        results.push({
          ruleId: rule.id,
          severity: 'warn',
          description: `Rule "${rule.id}" threw an error: ${err.message}`,
        });
      }
    }

    return { package: pkg, results, skipped: false, profileDiff: context?.profileDiff || null };
  }
}

function isAllowlisted(pkg, allowlist) {
  for (const entry of allowlist) {
    if (entry === `${pkg.name}@${pkg.version}`) return true;
    // Wildcard version: "pkg@*"
    if (entry === `${pkg.name}@*`) return true;
    if (entry === pkg.name) return true;
  }
  return false;
}
