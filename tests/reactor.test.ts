import test from "node:test";
import assert from "node:assert/strict";
import { buildTrialPlan, crossoverGenomes, evolveGeneration, featureVector, inferPhenotypes, lineage, mutateGenome, rehearseGenome, scoreFitness, seedGenomes } from "../src";
import type { HostSecurityRecord, SecurityGenome } from "../src";

const records: HostSecurityRecord[] = [
  { hostId: "web-a", findings: [{ signature: "tls-old", severity: 7 }, { signature: "weak-cipher", severity: 8 }], complianceFailed: 2, complianceTotal: 10, cloudTags: { app: "blue" } },
  { hostId: "web-b", findings: [{ signature: "tls-old", severity: 7 }, { signature: "weak-cipher", severity: 8 }], complianceFailed: 2, complianceTotal: 10, cloudTags: { app: "red" } },
  { hostId: "db-a", findings: [{ signature: "db-auth", severity: 9 }, { signature: "audit-fail", severity: 9 }, { signature: "privilege", severity: 8 }], complianceFailed: 8, complianceTotal: 10, cloudTags: { app: "blue" } },
  { hostId: "db-b", findings: [{ signature: "db-auth", severity: 8 }, { signature: "audit-fail", severity: 9 }, { signature: "privilege", severity: 8 }], complianceFailed: 8, complianceTotal: 10, cloudTags: { app: "green" } },
];

test("feature vector is normalized", () => { const v = featureVector(records[0]!); assert.ok(v.severityMean >= 0 && v.severityMean <= 1); assert.equal(v.complianceFailureRate, .2); assert.ok(v.findingDensity >= 0 && v.findingDensity <= 1); });
test("invalid compliance counts rejected", () => assert.throws(() => featureVector({ hostId: "x", findings: [], complianceFailed: 2, complianceTotal: 1 }), /compliance/));
test("invalid finding rejected", () => assert.throws(() => featureVector({ hostId: "x", findings: [{ signature: "bad", severity: 12 }], complianceFailed: 0, complianceTotal: 1 }), /finding/));

test("phenotypes follow security behavior rather than cloud tags", () => { const ps = inferPhenotypes(records, .65); const web = ps.find((p) => p.hostIds.includes("web-a"))!; assert.ok(web.hostIds.includes("web-b")); assert.ok(!web.hostIds.includes("db-a")); });
test("same cloud tag can split into different security phenotypes", () => { const ps = inferPhenotypes(records, .65); const a = ps.find((p) => p.hostIds.includes("web-a"))!; const b = ps.find((p) => p.hostIds.includes("db-a"))!; assert.notEqual(a.id, b.id); });
test("phenotype inference deterministic independent of input order", () => assert.deepEqual(inferPhenotypes(records, .65), inferPhenotypes([...records].reverse(), .65)));
test("phenotype inference does not mutate records", () => { const before = JSON.stringify(records); inferPhenotypes(records, .65); assert.equal(JSON.stringify(records), before); });
test("invalid phenotype threshold rejected", () => assert.throws(() => inferPhenotypes(records, 0), /threshold/));

test("seeding creates three distinct genomes", () => { const p = inferPhenotypes(records, .65)[0]!; const gs = seedGenomes(p); assert.equal(gs.length, 3); assert.equal(new Set(gs.map((g) => g.id)).size, 3); });
test("seed genomes target same phenotype", () => { const p = inferPhenotypes(records, .65)[0]!; assert.ok(seedGenomes(p).every((g) => g.phenotypeId === p.id)); });
test("mutation records parent and increments generation", () => { const p = inferPhenotypes(records, .65)[0]!; const g = seedGenomes(p)[0]!; const m = mutateGenome(g, 7); assert.deepEqual(m.parentIds, [g.id]); assert.equal(m.generation, g.generation + 1); assert.ok(m.mutationHistory.length > 0); });
test("mutation deterministic for seed", () => { const p = inferPhenotypes(records, .65)[0]!; const g = seedGenomes(p)[0]!; assert.deepEqual(mutateGenome(g, 17), mutateGenome(g, 17)); });
test("mutation never exceeds depth bounds", () => { const p = inferPhenotypes(records, .65)[0]!; let g = seedGenomes(p)[2]!; for (let i = 0; i < 20; i++) g = mutateGenome(g, 1); assert.ok(g.depth >= 1 && g.depth <= 5); });

test("crossover combines lineage and increments generation", () => { const p = inferPhenotypes(records, .65)[0]!; const [a,b] = seedGenomes(p); const c = crossoverGenomes(a!, b!); assert.deepEqual(c.parentIds, [a!.id,b!.id].sort()); assert.equal(c.generation, 1); });
test("crossover self rejected", () => { const p = inferPhenotypes(records, .65)[0]!; const g = seedGenomes(p)[0]!; assert.throws(() => crossoverGenomes(g, g), /distinct/); });
test("crossover across phenotypes rejected", () => { const ps = inferPhenotypes(records, .65); assert.ok(ps.length >= 2); const a = seedGenomes(ps[0]!)[0]!; const b = seedGenomes(ps[1]!)[0]!; assert.throws(() => crossoverGenomes(a,b), /same phenotype/); });

test("trial plan maps phenotype hosts exactly", () => { const p = inferPhenotypes(records, .65)[0]!; const g = seedGenomes(p)[0]!; const plan = buildTrialPlan(g,p); assert.deepEqual(plan.targetHostIds, p.hostIds); assert.deepEqual(plan.policySequence, g.curriculum); });
test("trial plan mismatch rejected", () => { const ps = inferPhenotypes(records, .65); assert.ok(ps.length >= 2); assert.throws(() => buildTrialPlan(seedGenomes(ps[0]!)[0]!, ps[1]!), /mismatch/); });

test("fitness is bounded and favors better measured outcomes", () => { const good = scoreFitness({ riskReduction:.9, coverage:.9, stability:.9, falsePositiveRate:.05, changeCost:.2 }); const bad = scoreFitness({ riskReduction:.1, coverage:.2, stability:.2, falsePositiveRate:.8, changeCost:.9 }); assert.ok(good > bad); assert.ok(good <= 1 && bad >= 0); });
test("fitness rejects out of range measurements", () => assert.throws(() => scoreFitness({ riskReduction:2, coverage:1, stability:1, falsePositiveRate:0, changeCost:0 }), /\[0,1\]/));
test("rehearsal is deterministic simulation", () => { const p = inferPhenotypes(records, .65)[0]!; const g = seedGenomes(p)[0]!; assert.deepEqual(rehearseGenome(g,p), rehearseGenome(g,p)); });
test("rehearsal mismatch rejected", () => { const ps = inferPhenotypes(records, .65); if (ps.length >= 2) assert.throws(() => rehearseGenome(seedGenomes(ps[0]!)[0]!, ps[1]!), /mismatch/); });

test("evolution ranks population and creates next generation", () => { const p = inferPhenotypes(records, .65)[0]!; const gs = seedGenomes(p); const out = evolveGeneration(p, gs); assert.equal(out.ranked.length, gs.length); assert.equal(out.population.length, 5); assert.ok(out.population.some((g) => g.generation > 0)); });
test("evolution can use caller supplied measured evaluator", () => { const p = inferPhenotypes(records, .65)[0]!; const gs = seedGenomes(p); const out = evolveGeneration(p, gs, (g) => ({ riskReduction: g.id === gs[1]!.id ? 1 : .1, coverage:.8, stability:.8, falsePositiveRate:.1, changeCost:.2 })); assert.equal(out.promoted.id, gs[1]!.id); });
test("evolution requires at least two genomes", () => { const p = inferPhenotypes(records, .65)[0]!; assert.throws(() => evolveGeneration(p, [seedGenomes(p)[0]!]), /at least two/); });

test("lineage is ancestry ordered before child", () => { const p = inferPhenotypes(records, .65)[0]!; const [a,b] = seedGenomes(p); const c = crossoverGenomes(a!,b!); const d = mutateGenome(c,3); const line = lineage(d.id,[a!,b!,c,d]); assert.equal(line.at(-1), d.id); assert.ok(line.indexOf(c.id) < line.indexOf(d.id)); });
test("lineage ignores unknown parent records instead of inventing them", () => { const fake: SecurityGenome = { ...seedGenomes(inferPhenotypes(records,.65)[0]!)[0]!, id:"child", parentIds:["missing"] }; assert.deepEqual(lineage("child",[fake]), ["child"]); });
