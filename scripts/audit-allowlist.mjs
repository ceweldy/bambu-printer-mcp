// npm audit gate with an explicit advisory allowlist (approved by Connor, 2026-10-12).
// basic-ftp (GHSA-c475-qrg2-pj4r): no upstream fix. braces (GHSA-vfj7-8cjw-p6xm): via patch-package.
import { execSync } from 'node:child_process';
const ALLOW = new Set(['GHSA-c475-qrg2-pj4r', 'GHSA-vfj7-8cjw-p6xm']);
let out;
try { out = execSync('npm audit --omit=dev --json', { encoding: 'utf8' }); } catch (e) { out = e.stdout; }
const vulns = JSON.parse(out).vulnerabilities || {};
const ok = new Set();
let changed = true;
while (changed) {
  changed = false;
  for (const [name, v] of Object.entries(vulns)) {
    if (ok.has(name)) continue;
    const allAllowed = v.via.every(x => typeof x === 'string' ? ok.has(x) : ALLOW.has((x.url || '').split('/').pop()));
    if (allAllowed) { ok.add(name); changed = true; }
  }
}
const bad = Object.keys(vulns).filter(n => !ok.has(n));
for (const n of ok) console.log(`allowlisted: ${n} (${vulns[n].severity})`);
if (bad.length) { console.error(`Non-allowlisted vulnerabilities: ${bad.join(', ')}`); process.exit(1); }
console.log('npm audit: no non-allowlisted vulnerabilities');
