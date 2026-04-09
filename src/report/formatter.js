import chalk from 'chalk';

const SEVERITY_ORDER = { block: 0, warn: 1, info: 2 };

const SEVERITY_STYLE = {
  block: chalk.red.bold('🚫 BLOCK'),
  warn: chalk.yellow.bold('⚠️  WARN'),
  info: chalk.blue.bold('ℹ️  INFO'),
};

export function formatReport(evaluations, registryWarnings = []) {
  const lines = [];
  const blocks = [];
  const warns = [];
  const infos = [];
  const clean = [];

  for (const evaluation of evaluations) {
    if (evaluation.skipped) {
      clean.push(evaluation);
      continue;
    }

    const hasBlock = evaluation.results.some((r) => r.severity === 'block');
    const hasWarn = evaluation.results.some((r) => r.severity === 'warn');
    const hasInfo = evaluation.results.some((r) => r.severity === 'info');

    if (hasBlock) blocks.push(evaluation);
    else if (hasWarn) warns.push(evaluation);
    else if (hasInfo) infos.push(evaluation);
    else clean.push(evaluation);
  }

  lines.push('');
  lines.push(chalk.bold.underline('🔒 npm-safe report'));
  lines.push('');

  // Compact summary table when many packages are involved
  const totalPkgs = blocks.length + warns.length + infos.length + clean.length;
  if (totalPkgs > 5) {
    lines.push(formatTable(evaluations));
    lines.push('');
  }

  if (blocks.length > 0) {
    lines.push(chalk.red.bold('🚫 BLOCKED'));
    for (const ev of blocks) {
      lines.push(formatEvaluation(ev));
    }
    lines.push('');
  }

  if (warns.length > 0) {
    lines.push(chalk.yellow.bold('⚠️  WARNINGS'));
    for (const ev of warns) {
      lines.push(formatEvaluation(ev));
    }
    lines.push('');
  }

  if (infos.length > 0) {
    lines.push(chalk.blue.bold('ℹ️  INFO'));
    for (const ev of infos) {
      lines.push(formatEvaluation(ev));
    }
    lines.push('');
  }

  if (clean.length > 0) {
    lines.push(chalk.green.bold(`✅ ${clean.length} package(s) clean`));
    lines.push('');
  }

  if (registryWarnings.length > 0) {
    lines.push(chalk.dim('📡 Registry issues (metadata rules skipped for these)'));
    for (const w of registryWarnings) {
      lines.push(chalk.dim(`   ${w}`));
    }
    lines.push('');
  }

  lines.push(formatSummary(blocks.length, warns.length, infos.length, clean.length));
  lines.push('');

  return lines.join('\n');
}

function formatEvaluation(evaluation) {
  const pkg = evaluation.package;
  const version = pkg.previousVersion
    ? `${pkg.previousVersion} → ${pkg.version}`
    : pkg.version;

  const lines = [`  ${chalk.bold(pkg.name)} ${chalk.dim(version)}`];

  const sorted = [...evaluation.results].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );

  for (const result of sorted) {
    const tag = SEVERITY_STYLE[result.severity];
    lines.push(`    ${tag} ${result.description}`);
  }

  // Behaviour diff details
  const diff = evaluation.profileDiff;
  if (diff?.hasChanges) {
    lines.push(`    ${chalk.cyan('🔬 Behaviour diff:')}`);
    for (const n of diff.newNetwork) {
      lines.push(`      ${chalk.red('🌐')} + network: ${n.address}:${n.port}`);
    }
    for (const f of diff.newFileWrites) {
      lines.push(`      ${chalk.red('📝')} + file write: ${f.path}`);
    }
    for (const p of diff.newProcesses) {
      lines.push(`      ${chalk.yellow('⚙️')}  + process: ${p.command}`);
    }
    if (diff.sizeChange) {
      const pct = ((diff.sizeChange.ratio - 1) * 100).toFixed(0);
      const label = diff.sizeChange.ratio > 1 ? `+${pct}%` : `${pct}%`;
      lines.push(`      ${chalk.yellow('📦')} ~ size: ${diff.sizeChange.before} → ${diff.sizeChange.after} files (${label})`);
    }
  }

  return lines.join('\n');
}

function formatTable(evaluations) {
  const rows = [];
  const nameWidth = Math.min(
    40,
    Math.max(7, ...evaluations.map((ev) => ev.package.name.length))
  );
  const header = `  ${chalk.dim('Package'.padEnd(nameWidth))}  ${chalk.dim('Version'.padEnd(12))}  ${chalk.dim('Status')}`;
  rows.push(header);
  rows.push(chalk.dim('  ' + '─'.repeat(nameWidth + 2 + 12 + 2 + 10)));

  for (const ev of evaluations) {
    const name = ev.package.name.length > nameWidth
      ? ev.package.name.slice(0, nameWidth - 1) + '…'
      : ev.package.name.padEnd(nameWidth);
    const version = (ev.package.version || '').padEnd(12);

    let status;
    if (ev.skipped) {
      status = chalk.green('✅ skip');
    } else if (ev.results.some((r) => r.severity === 'block')) {
      status = chalk.red.bold('🚫 BLOCK');
    } else if (ev.results.some((r) => r.severity === 'warn')) {
      status = chalk.yellow('⚠️  warn');
    } else if (ev.results.some((r) => r.severity === 'info')) {
      status = chalk.blue('ℹ️  info');
    } else {
      status = chalk.green('✅ ok');
    }

    rows.push(`  ${name}  ${version}  ${status}`);
  }

  return rows.join('\n');
}

function formatSummary(blockCount, warnCount, infoCount, cleanCount) {
  const parts = [];
  if (blockCount > 0) parts.push(chalk.red(`🚫 ${blockCount} blocked`));
  if (warnCount > 0) parts.push(chalk.yellow(`⚠️  ${warnCount} warnings`));
  if (infoCount > 0) parts.push(chalk.blue(`ℹ️  ${infoCount} info`));
  if (cleanCount > 0) parts.push(chalk.green(`✅ ${cleanCount} clean`));
  return parts.join('  ');
}

export function formatJson(evaluations, registryWarnings = []) {
  const packages = evaluations.map((ev) => {
    const pkg = ev.package;
    return {
      name: pkg.name,
      version: pkg.version,
      previousVersion: pkg.previousVersion || null,
      changeType: pkg.changeType || null,
      skipped: ev.skipped || false,
      violations: ev.results.map((r) => ({
        ruleId: r.ruleId,
        severity: r.severity,
        description: r.description,
      })),
      profileDiff: ev.profileDiff || null,
    };
  });

  const summary = {
    blocked: packages.filter((p) => p.violations.some((v) => v.severity === 'block')).length,
    warnings: packages.filter((p) => !p.violations.some((v) => v.severity === 'block') && p.violations.some((v) => v.severity === 'warn')).length,
    clean: packages.filter((p) => p.violations.length === 0 && !p.skipped).length,
    skipped: packages.filter((p) => p.skipped).length,
  };

  return JSON.stringify({
    packages,
    summary,
    registryWarnings,
    exitCode: getExitCode(evaluations),
  }, null, 2);
}

export function getExitCode(evaluations) {
  let hasWarning = false;
  for (const ev of evaluations) {
    if (ev.results?.some((r) => r.severity === 'block')) return 1;
    if (ev.results?.some((r) => r.severity === 'warn')) hasWarning = true;
  }
  return hasWarning ? 2 : 0;
}
