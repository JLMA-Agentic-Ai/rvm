// Generates tests/fixtures/poincare_parity_ts.json from the REAL substrate-core poincareDistance.
// Usage (from rvm/): node crates/rvm-agentlaw/tests/fixtures/gen_poincare_parity.mjs crates/rvm-agentlaw/tests/fixtures/poincare_parity_ts.json
import { poincareDistance } from '../../../../../substrate-core/packages/substrate-core/dist/index.js';
import { writeFileSync } from 'node:fs';
let seed = 0x9e3779b9;
const rnd = () => { seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed / 4294967296; };
const vec = (d, r) => { const v = Array.from({ length: d }, () => rnd() * 2 - 1); const n = Math.hypot(...v) || 1; return v.map(x => Number((x / n * r).toPrecision(12))); };
const cases = [];
const push = (tag, u, v, eps) => cases.push({ tag, u, v, eps, ts: poincareDistance(u, v, eps) });
for (const eps of [1e-5, 1e-4]) {
  for (let i = 0; i < 120; i++) { const d = 2 + Math.floor(rnd() * 31); push('random', vec(d, rnd() * 0.95), vec(d, rnd() * 0.95), eps); }
  for (let i = 0; i < 40; i++) { const d = 4 + Math.floor(rnd() * 28); push('near_rim', vec(d, 0.99999 + rnd() * 9e-6), vec(d, 0.9999 + rnd() * 9e-5), eps); }
  for (let i = 0; i < 40; i++) { const d = 4 + Math.floor(rnd() * 28); push('outside_ball', vec(d, 1 + rnd() * 5), vec(d, rnd()), eps); }
  for (let i = 0; i < 40; i++) { const d = 4 + Math.floor(rnd() * 28); const u = vec(d, rnd() * 0.9); const v = u.map(x => x + (rnd() - 0.5) * 1e-9).map(x => Number(x.toPrecision(15))); push('tiny_diff', u, v, eps); }
  for (let i = 0; i < 20; i++) { const u = vec(8, rnd() * 0.9); push('identical', u, u.slice(), eps); }
}
push('agentlaw_script_origin', [0, 0, 0, 0], [0.12, 0.15, 0.05, 0.08], 1e-5);
writeFileSync(process.argv[2], JSON.stringify({ generator: 'substrate-core dist/prediction-bridge.js poincareDistance', count: cases.length, cases }));
console.log('cases', cases.length, 'nonfinite', cases.filter(c => !Number.isFinite(c.ts)).length);
// Edge-case behaviour (not in fixture, documented)
console.log('TS empty ->', poincareDistance([], []), '| TS len-mismatch ->', poincareDistance([0.1, 0.2], [0.1]));
