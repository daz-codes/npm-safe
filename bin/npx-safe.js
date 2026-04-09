#!/usr/bin/env node

import chalk from 'chalk';
import { loadConfig } from '../src/config/loader.js';
import { analysePackage, parsePackageSpec } from '../src/npx/analyse.js';
import { logInvocation, getLastAuditDate } from '../src/npx/logger.js';

const args = process.argv.slice(2);

if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
  console.log(`Usage: npx-safe <package[@version]> [args...]

Secure npx wrapper — analyses packages before execution.

Options:
  --help, -h    Show this help
  --force       Skip analysis and execute directly
  --json        Output analysis as JSON instead of text`);
  process.exit(0);
}

const forceIdx = args.indexOf('--force');
const force = forceIdx !== -1;
if (force) args.splice(forceIdx, 1);

const jsonIdx = args.indexOf('--json');
const jsonOutput = jsonIdx !== -1;
if (jsonOutput) args.splice(jsonIdx, 1);

const pkgArg = args[0];
const passthrough = args.slice(1);

const { name, version } = parsePackageSpec(pkgArg);
const cwd = process.cwd();

try {
  const config = await loadConfig(cwd);
  const npxConfig = config.npx || {};
  const npxAllowlist = npxConfig.allowlist || [];
  const blockUnknown = npxConfig.blockUnknown || false;

  // Check npx allowlist first (fast path)
  const isAllowlisted = npxAllowlist.some((entry) => {
    if (entry === name || entry === `${name}@*`) return true;
    if (version && entry === `${name}@${version}`) return true;
    return false;
  });

  if (isAllowlisted || force) {
    await logInvocation(cwd, { name, version, skipped: true, blocked: false, results: [] });
    await runNpx();
    process.exit(process.exitCode ?? 0);
  }

  // Run analysis
  const result = await analysePackage(name, version, config);

  if (result.error) {
    if (jsonOutput) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.error(chalk.red(`Error: ${result.error}`));
    }
    if (blockUnknown) {
      await logInvocation(cwd, { ...result, blocked: true });
      process.exit(1);
    }
    // If not blocking unknown, proceed anyway
    await logInvocation(cwd, result);
    await runNpx();
    process.exit(process.exitCode ?? 0);
  }

  // Check stale audit warning
  const lastAudit = await getLastAuditDate(cwd, name);
  const staleMs = (npxConfig.staleDays || 30) * 24 * 60 * 60 * 1000;
  const isStale = lastAudit && (Date.now() - lastAudit.getTime() > staleMs);

  await logInvocation(cwd, result);

  if (result.blocked) {
    if (jsonOutput) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.error('');
      console.error(chalk.red.bold('npx-safe: blocked'));
      console.error(`  ${chalk.bold(result.name)}@${result.version}`);
      for (const r of result.results) {
        const tag = r.severity === 'block' ? chalk.red.bold('BLOCK') : chalk.yellow.bold(' WARN');
        console.error(`    ${tag} ${r.description}`);
      }
      console.error('');
      console.error(chalk.dim(`To approve: npm-safe approve ${result.name}@${result.version}`));
    }
    process.exit(1);
  }

  if (blockUnknown && !isAllowlisted) {
    if (jsonOutput) {
      console.log(JSON.stringify({ ...result, blocked: true, reason: 'blockUnknown' }, null, 2));
    } else {
      console.error(chalk.yellow(`npx-safe: "${name}" is not in the npx allowlist and blockUnknown is enabled.`));
      console.error(chalk.dim(`Add to npx.allowlist in .npm-safe.json, or use --force`));
    }
    process.exit(1);
  }

  // Warnings — print but proceed
  if (result.results.length > 0 && !jsonOutput) {
    console.error(chalk.yellow.bold('npx-safe: warnings'));
    console.error(`  ${chalk.bold(result.name)}@${result.version}`);
    for (const r of result.results) {
      console.error(`    ${chalk.yellow.bold(' WARN')} ${r.description}`);
    }
    console.error('');
  }

  if (isStale && !jsonOutput) {
    console.error(chalk.dim(`Note: "${name}" was last audited ${Math.floor((Date.now() - lastAudit.getTime()) / 86400000)} days ago`));
  }

  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  }

  await runNpx();
} catch (err) {
  console.error(chalk.red(`npx-safe error: ${err.message}`));
  process.exit(2);
}

async function runNpx() {
  const { spawn } = await import('node:child_process');
  const proc = spawn('npx', ['--yes', pkgArg, ...passthrough], {
    cwd,
    stdio: 'inherit',
  });

  return new Promise((resolve, reject) => {
    proc.on('close', (code) => {
      process.exitCode = code;
      resolve();
    });
    proc.on('error', reject);
  });
}
