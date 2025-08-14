#!/usr/bin/env node
/**
 * Task 30: Documentation & Spec Mapping Automation
 * Parses betanet1.1.md for normative clauses (lines containing MUST/MUST NOT/SHALL/PROHIBITED)
 * and produces a JSON mapping linking each clause line to related check IDs (heuristic association
 * by keyword heuristics) plus coverage status derived from current check registry.
 *
 * Output:
 *  - dist/spec-mapping.json (machine-readable)
 *  - prints a markdown table snippet (for README insertion under a Spec Mapping section)
 */
const fs = require('fs');
const path = require('path');

const SPEC_FILE = path.join(__dirname, '..', 'betanet1.1.md');
const CHECK_REGISTRY_FILE = path.join(__dirname, '..', 'src', 'check-registry.ts');
const OUT_JSON = path.join(__dirname, '..', 'dist', 'spec-mapping.json');

function loadChecks() {
  const text = fs.readFileSync(CHECK_REGISTRY_FILE, 'utf8');
  // very lightweight parse: match objects with id: <num>, key: '<key>'
  const regex = /id:\s*(\d+)\s*,\s*\n\s*key:\s*'([^']+)'/g;
  const checks = [];
  let m;
  while ((m = regex.exec(text))) {
    checks.push({ id: parseInt(m[1], 10), key: m[2] });
  }
  return checks;
}

function deriveAssociations(line) {
  const L = line.toLowerCase();
  const ids = new Set();
  // heuristic keyword → check id mapping (extend as needed)
  const map = [
    [/tls|alpn|extension order|ech|clienthello/, [1,12,22,32]],
    [/access ticket|ticket|carrier/, [2,30]],
    [/noise|rekey|key_update|kyber|pq/, [13,19,10,38]],
    [/http\/2|http\/3|ping cadence|padding|priority/, [20,28,26,37]],
    [/scion|path switch|control stream|probe back-off|back off/, [4,33,23]],
    [/bootstrap|rendezvous|pow|rate-limit|rate limit/, [6,36,24]],
    [/mixnode|mixnet|hop set|diversity|beaconset|vrf/, [11,17,27]],
    [/alias ledger|finality|emergency advance|quorum/, [7,16]],
    [/voucher|frost|cashu|payment/, [8,14,29,31,36]],
    [/governance|partition|quorum|vote weight/, [15,16]],
    [/fallback|udp|cover connection|anti-correlation|retry/, [25,18]],
    [/reproducible|provenance|slsa|signature|attestation/, [9,35]],
    [/algorithm agility|registry/, [34]],
    [/jitter|randomness|entropy test/, [26,37]],
    [/forbidden|deny-list|negative assertion|legacy header/, [23,39]],
    [/sandbox|cpu budget|memory budget|fs write|network deny/, [43]],
    [/quic/, [40]],
    [/runtime calibration|path switch latency|probe backoff/, [42,33]],
  ];
  for (const [re, cids] of map) {
    if (re.test(L)) cids.forEach(id => ids.add(id));
  }
  return [...ids];
}

function main() {
  const spec = fs.readFileSync(SPEC_FILE, 'utf8').split(/\r?\n/);
  const checks = loadChecks();
  const checkSet = new Set(checks.map(c=>c.id));
  const rows = [];
  const normativeRe = /(MUST NOT|MUST|SHALL|PROHIBITED)/; // order matters to avoid MUST substring issues
  spec.forEach((line, idx)=>{
    if (normativeRe.test(line)) {
      const assoc = deriveAssociations(line);
      const coverage = assoc.length ? 'Mapped' : 'Unmapped';
      rows.push({ line: idx+1, text: line.trim(), checks: assoc, coverage });
    }
  });
  const summary = {
    generated: new Date().toISOString(),
    specFile: path.basename(SPEC_FILE),
    totalNormativeClauses: rows.length,
    mappedClauses: rows.filter(r=>r.checks.length).length,
    unmappedClauses: rows.filter(r=>!r.checks.length).length,
    coveragePct: rows.length ? +(rows.filter(r=>r.checks.length).length / rows.length * 100).toFixed(2) : 0,
    rows
  };
  fs.mkdirSync(path.dirname(OUT_JSON), { recursive: true });
  fs.writeFileSync(OUT_JSON, JSON.stringify(summary, null, 2));

  // markdown table snippet
  const tableHeader = '| Line | Clause (truncated) | Checks | Status |\n|------|----------------------|--------|--------|';
  const tableRows = rows.slice(0, 50).map(r=>`| ${r.line} | ${r.text.slice(0,60).replace(/\|/g,'\\|')} | ${r.checks.join(',')} | ${r.coverage} |`);
  const md = [
    '### Automated Spec Mapping (Top 50 Normative Clauses)',
    '',
    `Coverage: ${summary.mappedClauses}/${summary.totalNormativeClauses} (${summary.coveragePct}%) mapped via heuristic associations.`,
    '',
    tableHeader,
    ...tableRows,
    '',
    '> Full JSON: dist/spec-mapping.json'
  ].join('\n');
  console.log(md);
}

if (require.main === module) {
  main();
}
