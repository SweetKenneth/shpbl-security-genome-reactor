import { evolveGeneration, inferPhenotypes, lineage, seedGenomes } from "../src";
const records = [
  { hostId: "web-a", findings: [{ signature: "tls-old", severity: 7 }, { signature: "weak-cipher", severity: 8 }], complianceFailed: 1, complianceTotal: 10, cloudTags: { app: "same-label" } },
  { hostId: "web-b", findings: [{ signature: "tls-old", severity: 7 }, { signature: "weak-cipher", severity: 8 }], complianceFailed: 1, complianceTotal: 10, cloudTags: { app: "other-label" } },
  { hostId: "db-a", findings: [{ signature: "db-auth", severity: 9 }, { signature: "privilege", severity: 9 }], complianceFailed: 8, complianceTotal: 10, cloudTags: { app: "same-label" } },
  { hostId: "db-b", findings: [{ signature: "db-auth", severity: 9 }, { signature: "privilege", severity: 8 }], complianceFailed: 8, complianceTotal: 10, cloudTags: { app: "third-label" } },
];
const phenotype = inferPhenotypes(records, .65)[0]!; let all = seedGenomes(phenotype); let population = all;
for (let i = 0; i < 3; i += 1) { const next = evolveGeneration(phenotype, population); all = [...all, ...next.population]; population = next.population; }
const final = evolveGeneration(phenotype, population); const winner = final.promoted;
console.log(JSON.stringify({ phenotype, winner, lineage: lineage(winner.id, all), score: final.ranked[0]!.score }, null, 2));
