#!/usr/bin/env node
// Task 28: Re-audit GitHub Actions workflow pinned SHAs
// Scans .github/workflows (or github-action dir) for 'uses: owner/repo@ref' lines
// Warns when ref is not a full 40-char commit SHA. Exits non-zero if any unpinned actions.
const fs = require('fs');
const path = require('path');

function scanDir(dir, findings){
  if (!fs.existsSync(dir)) return;
  const entries = fs.readdirSync(dir);
  for (const e of entries){
    const full = path.join(dir,e);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) { scanDir(full, findings); continue; }
    if (!/\.ya?ml$/i.test(e)) continue;
    const content = fs.readFileSync(full,'utf8');
    const lines = content.split(/\r?\n/);
    lines.forEach((l,i)=>{
      const m = l.match(/uses:\s*([A-Za-z0-9_.\-\/]+)@([^\s#]+)/);
      if (m){
        const ref = m[2];
        if (!/^[a-f0-9]{40}$/i.test(ref)){
          findings.push({ file: full, line: i+1, ref});
        }
      }
    });
  }
}

function main(){
  const targets = [path.join(process.cwd(), '.github','workflows'), path.join(process.cwd(),'github-action')];
  const findings = [];
  targets.forEach(t => scanDir(t, findings));
  if (findings.length){
    console.error('Unpinned GitHub Actions references detected:');
    findings.forEach(f => console.error(`${f.file}:${f.line} ref=${f.ref}`));
    process.exitCode = 2;
  } else {
    console.log('All GitHub Actions workflow references pinned to commit SHAs.');
  }
}

if (require.main === module) main();
