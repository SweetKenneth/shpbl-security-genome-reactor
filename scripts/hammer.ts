import assert from "node:assert/strict";
import { buildTrialPlan, evolveGeneration, inferPhenotypes, mutateGenome, scoreFitness, seedGenomes } from "../src";
import type { HostSecurityRecord } from "../src";
let seed = Number(process.env.HAMMER_SEED ?? 0x73737373) >>> 0;
function rnd() { seed = (Math.imul(seed, 1103515245) + 12345) >>> 0; return seed / 0x100000000; }
const CASES = Number(process.env.HAMMER_CASES ?? 30000); let checks=0;
for (let c=0;c<CASES;c++) {
  const n=4+Math.floor(rnd()*6); const rs:HostSecurityRecord[]=[];
  for(let i=0;i<n;i++) { const hi=i<n/2; const findings= hi ? [{signature:`a${c%5}`,severity:5+rnd()*3},{signature:"common-a",severity:4+rnd()*2}] : [{signature:`b${c%7}`,severity:7+rnd()*3},{signature:"common-b",severity:7+rnd()*2}]; rs.push({hostId:`h${i}`,findings,complianceFailed:hi?1:4,complianceTotal:5,cloudTags:{declared:i%2?"x":"y"}}); }
  const before=JSON.stringify(rs); const ps=inferPhenotypes(rs,.62); assert.equal(JSON.stringify(rs),before); checks++; assert.ok(ps.length>=1); checks++;
  for(const p of ps){ const gs=seedGenomes(p); assert.equal(gs.length,3); checks++; const plan=buildTrialPlan(gs[0]!,p); assert.deepEqual(plan.targetHostIds,p.hostIds); checks++; const m=mutateGenome(gs[0]!,c); assert.ok(m.depth>=1&&m.depth<=5); checks++; const ev=evolveGeneration(p,gs); assert.equal(ev.ranked.length,3); checks++; assert.ok(ev.population.some(g=>g.generation>0)); checks++; const s=scoreFitness({riskReduction:rnd(),coverage:rnd(),stability:rnd(),falsePositiveRate:rnd(),changeCost:rnd()}); assert.ok(s>=0&&s<=1); checks++; }
}
console.log(JSON.stringify({hammer:"PASS",cases:CASES,checks,seed}));
