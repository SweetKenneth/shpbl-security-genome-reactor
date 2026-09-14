import test from "node:test";
import assert from "node:assert/strict";
import { crossoverGenomes, evolveGeneration, inferPhenotypes, lineage, seedGenomes } from "../src";
import { handleRequest } from "../src/mcp-server";
import type { FitnessObservation, HostSecurityRecord, SecurityGenome } from "../src";

const records: HostSecurityRecord[] = [
  { hostId:"a", findings:[{signature:"x",severity:5},{signature:"y",severity:6}], complianceFailed:1, complianceTotal:5 },
  { hostId:"b", findings:[{signature:"x",severity:5},{signature:"y",severity:6}], complianceFailed:1, complianceTotal:5 },
];

test("phenotype threshold rejects NaN instead of silently accepting it", () => assert.throws(() => inferPhenotypes(records, Number.NaN), /threshold/));
test("duplicate host ids are rejected", () => assert.throws(() => inferPhenotypes([...records, { ...records[0]! }]), /duplicate hostId/));
test("duplicate finding signatures on one host are rejected", () => assert.throws(() => inferPhenotypes([{ hostId:"a", findings:[{signature:"x",severity:1},{signature:"x",severity:2}], complianceFailed:0, complianceTotal:1 }]), /duplicate finding/));

test("crossover is commutative and deterministic", () => {
  const p=inferPhenotypes(records,.6)[0]!; const [a,b]=seedGenomes(p);
  assert.deepEqual(crossoverGenomes(a!,b!), crossoverGenomes(b!,a!));
});

test("evolution returns deep-cloned genomes rather than caller aliases", () => {
  const p=inferPhenotypes(records,.6)[0]!; const gs=seedGenomes(p); const out=evolveGeneration(p,gs);
  out.promoted.curriculum.push("poison"); out.ranked[0]!.genome.curriculum.push("poison2");
  assert.ok(!gs.some((g)=>g.curriculum.includes("poison")||g.curriculum.includes("poison2")));
});

test("lineage rejects cycles", () => {
  const p=inferPhenotypes(records,.6)[0]!; const [a,b]=seedGenomes(p); const ga:SecurityGenome={...a!,parentIds:[b!.id]}; const gb:SecurityGenome={...b!,parentIds:[a!.id]};
  assert.throws(()=>lineage(ga.id,[ga,gb]),/cycle/);
});

test("MCP initialize advertises protocol and five tools", () => {
  const init=handleRequest({jsonrpc:"2.0",id:1,method:"initialize",params:{}}); assert.equal(init.protocolVersion,"2025-06-18");
  const list=handleRequest({jsonrpc:"2.0",id:2,method:"tools/list"}); assert.equal(list.tools.length,5);
});

test("MCP measured fitness changes promotion rather than being ignored", () => {
  const p=inferPhenotypes(records,.6)[0]!; const gs=seedGenomes(p);
  const good:FitnessObservation={riskReduction:1,coverage:1,stability:1,falsePositiveRate:0,changeCost:0};
  const bad:FitnessObservation={riskReduction:0,coverage:0,stability:0,falsePositiveRate:1,changeCost:1};
  const fit:Record<string,FitnessObservation>={}; for(const g of gs) fit[g.id]=g.id===gs[2]!.id?good:bad;
  const res=handleRequest({jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"genome_evolve",arguments:{phenotype:p,population:gs,fitnessByGenomeId:fit}}});
  assert.equal(res.structuredContent.result.promoted.id,gs[2]!.id);
});

test("MCP measured evolution fails closed if any genome observation is missing", () => {
  const p=inferPhenotypes(records,.6)[0]!; const gs=seedGenomes(p); const fit:Record<string,FitnessObservation>={[gs[0]!.id]:{riskReduction:1,coverage:1,stability:1,falsePositiveRate:0,changeCost:0}};
  assert.throws(()=>handleRequest({jsonrpc:"2.0",id:4,method:"tools/call",params:{name:"genome_evolve",arguments:{phenotype:p,population:gs,fitnessByGenomeId:fit}}}),/missing measured fitness/);
});

test("MCP lineage exposes ancestry graph", () => {
  const p=inferPhenotypes(records,.6)[0]!; const [a,b]=seedGenomes(p); const c=crossoverGenomes(a!,b!);
  const res=handleRequest({jsonrpc:"2.0",id:5,method:"tools/call",params:{name:"genome_lineage",arguments:{genomeId:c.id,genomes:[a,b,c]}}});
  assert.equal(res.structuredContent.result.at(-1),c.id);
});

test("MCP unknown tools use invalid-params class",()=>assert.throws(()=>handleRequest({jsonrpc:"2.0",id:6,method:"tools/call",params:{name:"nope",arguments:{}}}),(e:any)=>e.code===-32602));
