#!/usr/bin/env node
// Simple reproducibility verification script (Phase 5)
// 1. Ensures initial build present (npm run build if missing dist)
// 2. Hashes primary output file(s)
// 3. Performs clean rebuild in temporary copy and compares hashes
// Exits non-zero on mismatch.

const { execSync } = require('child_process');
const { createHash } = require('crypto');
const fs = require('fs');
const path = require('path');

function hashFile(p) {
  const buf = fs.readFileSync(p);
  return createHash('sha256').update(buf).digest('hex');
}

function sh(cmd, opts={}) {
  return execSync(cmd, { stdio: 'inherit', ...opts });
}

(async () => {
  const projectRoot = path.resolve(__dirname, '..');
  const distDir = path.join(projectRoot, 'dist');
  if (!fs.existsSync(distDir) || !fs.existsSync(path.join(distDir, 'index.js'))) {
    sh('npm run build');
  }
  const targets = [path.join(distDir, 'index.js')].filter(f => fs.existsSync(f));
  if (!targets.length) {
    console.error('No build artifacts found to hash (expected dist/index.js).');
    process.exit(2);
  }
  const baseline = {};
  for (const t of targets) baseline[t] = hashFile(t);
  // Create temp working copy (exclude node_modules for speed by copying only src, tsconfig, package files)
  const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'repro-'));
  const copyList = ['src','tsconfig.json','package.json','package-lock.json','bin'];
  for (const item of copyList) {
    const srcPath = path.join(projectRoot, item);
    if (!fs.existsSync(srcPath)) continue;
    const destPath = path.join(tmp, item);
    const stat = fs.statSync(srcPath);
    if (stat.isDirectory()) {
      fs.mkdirSync(destPath, { recursive: true });
      // shallow copy
      const stack = [srcPath];
      while (stack.length) {
        const cur = stack.pop();
        const rel = path.relative(srcPath, cur);
        const outDir = path.join(destPath, rel);
        if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
        for (const f of fs.readdirSync(cur)) {
          const fp = path.join(cur, f);
          const st = fs.statSync(fp);
            const relFile = path.relative(srcPath, fp);
            const outFile = path.join(destPath, relFile);
            if (st.isDirectory()) stack.push(fp); else fs.copyFileSync(fp, outFile);
        }
      }
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
  // Install & build in temp
  sh('npm ci', { cwd: tmp });
  sh('npm run build', { cwd: tmp });
  const rebuiltDist = path.join(tmp, 'dist');
  const mismatches = [];
  for (const t of targets) {
    const rel = path.relative(projectRoot, t);
    const rebuiltPath = path.join(rebuiltDist, path.basename(t));
    if (!fs.existsSync(rebuiltPath)) {
      mismatches.push(`${rel}: missing in rebuilt`);
      continue;
    }
    const h2 = hashFile(rebuiltPath);
    if (h2 !== baseline[t]) mismatches.push(`${rel}: ${baseline[t]} != ${h2}`);
  }
  if (mismatches.length) {
    console.error('Rebuild digest mismatch detected:\n' + mismatches.join('\n'));
    process.exit(1);
  }
  console.log('Rebuild verification passed (hashes match).');
})();
