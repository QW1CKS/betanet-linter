#!/usr/bin/env node
/*
 * Task 21: Lint & Type Hygiene Hardening
 * Generates a structured JSON report of ESLint findings and exits non‑zero on any error‑level issues.
 * Usage: node scripts/lint-report.js [--format json] [--out report-lint.json]
 */
const { ESLint } = require('eslint');
const fs = require('fs');
const path = require('path');
(async () => {
  const args = process.argv.slice(2);
  const outIdx = args.indexOf('--out');
  const out = outIdx !== -1 ? args[outIdx + 1] : 'lint-report.json';
  const eslint = new ESLint({
    extensions: ['.ts'],
    cwd: path.resolve(__dirname, '..'),
    errorOnUnmatchedPattern: false,
    useEslintrc: true
  });
  const results = await eslint.lintFiles(['src/**/*.ts']);
  const formatter = await eslint.loadFormatter('stylish');
  const text = formatter.format(results);
  const summary = {
    meta: {
      generatedAt: new Date().toISOString(),
      gitSha: process.env.GITHUB_SHA || null,
      node: process.version
    },
    totals: results.reduce((acc, r) => {
      acc.errorCount += r.errorCount;
      acc.warningCount += r.warningCount;
      acc.fixableErrorCount += r.fixableErrorCount;
      acc.fixableWarningCount += r.fixableWarningCount;
      return acc;
    }, { errorCount: 0, warningCount: 0, fixableErrorCount: 0, fixableWarningCount: 0 }),
    files: results.map(r => ({
      filePath: path.relative(process.cwd(), r.filePath),
      errorCount: r.errorCount,
      warningCount: r.warningCount,
      messages: r.messages.map(m => ({ ruleId: m.ruleId, severity: m.severity, line: m.line, column: m.column, message: m.message, endLine: m.endLine, endColumn: m.endColumn }))
    }))
  };
  fs.writeFileSync(out, JSON.stringify(summary, null, 2));
  console.log(text.trim());
  console.log(`\nLint summary: errors=${summary.totals.errorCount} warnings=${summary.totals.warningCount} -> ${out}`);
  if (summary.totals.errorCount > 0) process.exit(2);
})();
