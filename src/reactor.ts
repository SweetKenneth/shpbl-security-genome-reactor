import type { EvolutionResult, FitnessObservation, GenomeScore, HostSecurityRecord, PhenotypeVector, ProfileMode, SecurityGenome, SecurityPhenotype, TrialPlan } from "./types";

const clamp01 = (n: number) => Math.max(0, Math.min(1, n));
const uniq = (xs: string[]) => [...new Set(xs)].sort();
const isProb = (n: number) => Number.isFinite(n) && n >= 0 && n <= 1;

function stableId(prefix: string, parts: string[]): string {
  let h = 0x811c9dc5 >>> 0;
  for (const ch of parts.join("|")) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619) >>> 0; }
  return `${prefix}-${h.toString(16).padStart(8, "0")}`;
}

function clonePhenotype(p: SecurityPhenotype): SecurityPhenotype {
  return { ...p, hostIds: [...p.hostIds], dominantSignatures: [...p.dominantSignatures], centroid: { ...p.centroid } };
}

function cloneGenome(g: SecurityGenome): SecurityGenome {
  return { ...g, parentIds: [...g.parentIds], curriculum: [...g.curriculum], mutationHistory: [...g.mutationHistory] };
}

function cloneObservation(o: FitnessObservation): FitnessObservation { return { ...o }; }

function validateRecord(r: HostSecurityRecord): void {
  if (!r || typeof r !== "object" || typeof r.hostId !== "string" || !r.hostId.trim()) throw new Error("hostId is required");
  if (!Array.isArray(r.findings)) throw new Error("findings must be an array");
  if (!Number.isInteger(r.complianceFailed) || !Number.isInteger(r.complianceTotal) || r.complianceFailed < 0 || r.complianceTotal < 0 || r.complianceFailed > r.complianceTotal) throw new Error("invalid compliance counts");
  const signatures = new Set<string>();
  for (const f of r.findings) {
    if (!f || typeof f.signature !== "string" || !f.signature.trim() || !Number.isFinite(f.severity) || f.severity < 0 || f.severity > 10) throw new Error("invalid finding");
    if (signatures.has(f.signature)) throw new Error(`duplicate finding signature on host ${r.hostId}: ${f.signature}`);
    signatures.add(f.signature);
  }
  if (r.cloudTags !== undefined) {
    if (!r.cloudTags || typeof r.cloudTags !== "object" || Array.isArray(r.cloudTags)) throw new Error("cloudTags must be a string map");
    for (const [k, v] of Object.entries(r.cloudTags)) if (!k.trim() || typeof v !== "string") throw new Error("cloudTags must contain non-empty string keys and string values");
  }
}

function validatePhenotype(p: SecurityPhenotype): void {
  if (!p || typeof p !== "object" || typeof p.id !== "string" || !p.id.trim()) throw new Error("phenotype id is required");
  if (!Array.isArray(p.hostIds) || p.hostIds.length === 0 || p.hostIds.some((x) => typeof x !== "string" || !x.trim()) || new Set(p.hostIds).size !== p.hostIds.length) throw new Error("phenotype hostIds must be unique non-empty strings");
  if (!Array.isArray(p.dominantSignatures) || p.dominantSignatures.some((x) => typeof x !== "string" || !x.trim())) throw new Error("phenotype dominantSignatures must be strings");
  const c = p.centroid;
  if (!c || !isProb(c.severityMean) || !isProb(c.complianceFailureRate) || !isProb(c.findingDensity)) throw new Error("phenotype centroid fields must be in [0,1]");
}

function validateGenome(g: SecurityGenome): void {
  if (!g || typeof g !== "object" || typeof g.id !== "string" || !g.id.trim() || typeof g.phenotypeId !== "string" || !g.phenotypeId.trim()) throw new Error("genome id and phenotypeId are required");
  if (!Number.isInteger(g.generation) || g.generation < 0) throw new Error("genome generation must be a non-negative integer");
  if (!Array.isArray(g.parentIds) || g.parentIds.some((x) => typeof x !== "string" || !x.trim())) throw new Error("genome parentIds must be strings");
  if (!Array.isArray(g.curriculum) || g.curriculum.length === 0 || g.curriculum.some((x) => typeof x !== "string" || !x.trim())) throw new Error("genome curriculum must be non-empty strings");
  if (!Number.isFinite(g.cadenceHours) || g.cadenceHours <= 0) throw new Error("genome cadenceHours must be finite and > 0");
  if (!Number.isInteger(g.depth) || g.depth < 1 || g.depth > 5) throw new Error("genome depth must be an integer in [1,5]");
  const modes: ProfileMode[] = ["observe", "balanced", "strict"];
  if (!modes.includes(g.profileMode)) throw new Error("invalid genome profileMode");
  if (!Array.isArray(g.mutationHistory) || g.mutationHistory.some((x) => typeof x !== "string" || !x.trim())) throw new Error("genome mutationHistory must be strings");
}

export function featureVector(record: HostSecurityRecord): PhenotypeVector {
  validateRecord(record);
  const severityMean = record.findings.length ? record.findings.reduce((n, f) => n + f.severity, 0) / record.findings.length / 10 : 0;
  const complianceFailureRate = record.complianceTotal ? record.complianceFailed / record.complianceTotal : 0;
  const findingDensity = clamp01(record.findings.length / 20);
  return { severityMean, complianceFailureRate, findingDensity };
}

function vectorDistance(a: PhenotypeVector, b: PhenotypeVector): number {
  return Math.sqrt((a.severityMean - b.severityMean) ** 2 + (a.complianceFailureRate - b.complianceFailureRate) ** 2 + (a.findingDensity - b.findingDensity) ** 2) / Math.sqrt(3);
}

function signatureSimilarity(a: string[], b: string[]): number {
  const A = new Set(a); const B = new Set(b); const U = new Set([...A, ...B]); if (!U.size) return 1;
  let hit = 0; for (const s of A) if (B.has(s)) hit += 1; return hit / U.size;
}

function dominantSignatures(records: HostSecurityRecord[], limit = 5): string[] {
  const freq = new Map<string, number>(); for (const r of records) for (const f of r.findings) freq.set(f.signature, (freq.get(f.signature) ?? 0) + 1);
  return [...freq].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, limit).map(([s]) => s);
}

function centroid(records: HostSecurityRecord[]): PhenotypeVector {
  const vectors = records.map(featureVector); const n = Math.max(1, vectors.length);
  return {
    severityMean: vectors.reduce((x, v) => x + v.severityMean, 0) / n,
    complianceFailureRate: vectors.reduce((x, v) => x + v.complianceFailureRate, 0) / n,
    findingDensity: vectors.reduce((x, v) => x + v.findingDensity, 0) / n,
  };
}

export function inferPhenotypes(records: HostSecurityRecord[], threshold = 0.68): SecurityPhenotype[] {
  if (!Array.isArray(records)) throw new Error("records must be an array");
  if (!Number.isFinite(threshold) || threshold <= 0 || threshold > 1) throw new Error("threshold must be finite and in (0,1]");
  const hostIds = new Set<string>();
  records.forEach((r) => { validateRecord(r); if (hostIds.has(r.hostId)) throw new Error(`duplicate hostId: ${r.hostId}`); hostIds.add(r.hostId); });
  const ordered = [...records].sort((a, b) => a.hostId.localeCompare(b.hostId));
  const clusters: HostSecurityRecord[][] = [];
  for (const record of ordered) {
    const vector = featureVector(record); const sigs = uniq(record.findings.map((f) => f.signature));
    let best = -1; let bestScore = -1;
    for (let i = 0; i < clusters.length; i += 1) {
      const c = clusters[i]!; const cv = centroid(c); const cs = dominantSignatures(c);
      const score = (1 - vectorDistance(vector, cv)) * 0.55 + signatureSimilarity(sigs, cs) * 0.45;
      if (score >= threshold && score > bestScore) { best = i; bestScore = score; }
    }
    if (best >= 0) clusters[best]!.push(record); else clusters.push([record]);
  }
  return clusters.map((cluster) => {
    const ids = cluster.map((r) => r.hostId).sort(); const sigs = dominantSignatures(cluster); const c = centroid(cluster);
    return { id: stableId("phenotype", [...ids, ...sigs]), hostIds: ids, centroid: c, dominantSignatures: sigs };
  }).sort((a, b) => a.id.localeCompare(b.id));
}

export function seedGenomes(phenotype: SecurityPhenotype): SecurityGenome[] {
  validatePhenotype(phenotype);
  const basePolicies = phenotype.dominantSignatures.length ? phenotype.dominantSignatures.map((s) => `probe:${s}`) : ["probe:baseline"];
  const variants: Array<[number, number, ProfileMode, string[]]> = [
    [24, 2, "observe", basePolicies.slice(0, 2)],
    [12, 3, "balanced", basePolicies.slice(0, 3)],
    [6, 4, "strict", basePolicies.slice(0, 4)],
  ];
  return variants.map(([cadenceHours, depth, profileMode, curriculum], i) => ({
    id: stableId("genome", [phenotype.id, "seed", String(i), ...curriculum]), phenotypeId: phenotype.id, generation: 0,
    parentIds: [], curriculum: uniq(curriculum), cadenceHours, depth, profileMode, mutationHistory: [],
  }));
}

export function mutateGenome(genome: SecurityGenome, mutationSeed: number): SecurityGenome {
  validateGenome(genome);
  if (!Number.isInteger(mutationSeed)) throw new Error("mutationSeed must be an integer");
  const mode = ((mutationSeed % 4) + 4) % 4; let cadenceHours = genome.cadenceHours; let depth = genome.depth; let profileMode = genome.profileMode; let curriculum = [...genome.curriculum]; let mutation = "";
  if (mode === 0) { cadenceHours = Math.max(1, Math.round(genome.cadenceHours * 0.75)); mutation = "cadence-faster"; }
  else if (mode === 1) { depth = Math.min(5, genome.depth + 1); mutation = "depth-plus-one"; }
  else if (mode === 2) { profileMode = genome.profileMode === "observe" ? "balanced" : genome.profileMode === "balanced" ? "strict" : "balanced"; mutation = `profile-${profileMode}`; }
  else { curriculum = uniq([...curriculum, `probe:mutation-${Math.abs(mutationSeed) % 17}`]); mutation = "curriculum-add"; }
  return {
    ...cloneGenome(genome), id: stableId("genome", [genome.id, "mut", String(mutationSeed)]), generation: genome.generation + 1,
    parentIds: [genome.id], curriculum, cadenceHours, depth, profileMode, mutationHistory: [...genome.mutationHistory, mutation],
  };
}

export function crossoverGenomes(a: SecurityGenome, b: SecurityGenome): SecurityGenome {
  validateGenome(a); validateGenome(b);
  if (a.id === b.id) throw new Error("crossover requires two distinct genomes");
  if (a.phenotypeId !== b.phenotypeId) throw new Error("crossover parents must target the same phenotype");
  const parents = [a, b].sort((x, y) => x.id.localeCompare(y.id));
  const [left, right] = parents as [SecurityGenome, SecurityGenome];
  const curriculum = uniq([...left.curriculum.slice(0, Math.ceil(left.curriculum.length / 2)), ...right.curriculum.slice(Math.floor(right.curriculum.length / 2))]);
  const profileOrder: ProfileMode[] = ["observe", "balanced", "strict"];
  const ai = profileOrder.indexOf(left.profileMode); const bi = profileOrder.indexOf(right.profileMode); const profileMode = profileOrder[Math.round((ai + bi) / 2)]!;
  return {
    id: stableId("genome", [left.id, right.id, "cross"]), phenotypeId: left.phenotypeId, generation: Math.max(left.generation, right.generation) + 1,
    parentIds: [left.id, right.id], curriculum, cadenceHours: Math.max(1, Math.round((left.cadenceHours + right.cadenceHours) / 2)),
    depth: Math.max(1, Math.min(5, Math.round((left.depth + right.depth) / 2))), profileMode,
    mutationHistory: uniq([...left.mutationHistory, ...right.mutationHistory, "crossover"]),
  };
}

export function buildTrialPlan(genome: SecurityGenome, phenotype: SecurityPhenotype): TrialPlan {
  validateGenome(genome); validatePhenotype(phenotype);
  if (genome.phenotypeId !== phenotype.id) throw new Error("genome/phenotype mismatch");
  return { genomeId: genome.id, phenotypeId: phenotype.id, targetHostIds: [...phenotype.hostIds], policySequence: [...genome.curriculum], cadenceHours: genome.cadenceHours, depth: genome.depth, profileSuggestion: genome.profileMode };
}

export function scoreFitness(observation: FitnessObservation): number {
  const xs = [observation.riskReduction, observation.coverage, observation.stability, observation.falsePositiveRate, observation.changeCost];
  if (xs.some((x) => !isProb(x))) throw new Error("fitness observations must be in [0,1]");
  return clamp01(observation.riskReduction * .40 + observation.coverage * .25 + observation.stability * .15 + (1 - observation.falsePositiveRate) * .10 + (1 - observation.changeCost) * .10);
}

export function rehearseGenome(genome: SecurityGenome, phenotype: SecurityPhenotype): FitnessObservation {
  validateGenome(genome); validatePhenotype(phenotype);
  if (genome.phenotypeId !== phenotype.id) throw new Error("genome/phenotype mismatch");
  const severity = phenotype.centroid.severityMean; const fail = phenotype.centroid.complianceFailureRate; const density = phenotype.centroid.findingDensity;
  const coverage = clamp01(.25 + genome.depth * .11 + genome.curriculum.length * .08);
  const strictness = genome.profileMode === "strict" ? 1 : genome.profileMode === "balanced" ? .72 : .45;
  const cadenceFactor = clamp01(24 / Math.max(1, genome.cadenceHours) / 4);
  const riskReduction = clamp01((severity * .45 + fail * .35 + density * .20) * coverage * (.7 + strictness * .3));
  const stability = clamp01(1 - cadenceFactor * .25 - Math.max(0, genome.depth - 3) * .08);
  const falsePositiveRate = clamp01(.04 + genome.depth * .025 + strictness * .04);
  const changeCost = clamp01(.08 + cadenceFactor * .22 + genome.curriculum.length * .035 + strictness * .08);
  return { riskReduction, coverage, stability, falsePositiveRate, changeCost };
}

export function evolveGeneration(
  phenotype: SecurityPhenotype,
  population: SecurityGenome[],
  evaluator: (genome: SecurityGenome, phenotype: SecurityPhenotype) => FitnessObservation = rehearseGenome,
): EvolutionResult {
  validatePhenotype(phenotype);
  if (!Array.isArray(population) || population.length < 2) throw new Error("population must contain at least two genomes");
  const ids = new Set<string>();
  for (const g of population) {
    validateGenome(g);
    if (g.phenotypeId !== phenotype.id) throw new Error("population contains a different phenotype");
    if (ids.has(g.id)) throw new Error(`population contains duplicate genome id: ${g.id}`);
    ids.add(g.id);
  }
  const frozenPhenotype = clonePhenotype(phenotype);
  const ranked: GenomeScore[] = population.map((genome) => {
    const safeGenome = cloneGenome(genome);
    const observation = cloneObservation(evaluator(safeGenome, clonePhenotype(frozenPhenotype)));
    return { genome: cloneGenome(genome), observation, score: scoreFitness(observation) };
  }).sort((a, b) => b.score - a.score || a.genome.id.localeCompare(b.genome.id));
  const eliteA = ranked[0]!.genome; const eliteB = ranked[1]!.genome; const child = crossoverGenomes(eliteA, eliteB); const next: SecurityGenome[] = [
    cloneGenome(eliteA), cloneGenome(eliteB), mutateGenome(child, ranked.length + child.generation), mutateGenome(eliteA, 17 + eliteA.generation), mutateGenome(eliteB, 29 + eliteB.generation),
  ];
  return {
    generation: Math.max(...next.map((g) => g.generation)),
    ranked: ranked.map((x) => ({ genome: cloneGenome(x.genome), observation: cloneObservation(x.observation), score: x.score })),
    population: next.map(cloneGenome),
    promoted: cloneGenome(ranked[0]!.genome),
  };
}

export function lineage(genomeId: string, genomes: SecurityGenome[]): string[] {
  if (typeof genomeId !== "string" || !genomeId.trim()) throw new Error("genomeId is required");
  if (!Array.isArray(genomes)) throw new Error("genomes must be an array");
  const map = new Map<string, SecurityGenome>();
  for (const g of genomes) { validateGenome(g); const existing = map.get(g.id); if (existing) { if (JSON.stringify(existing) !== JSON.stringify(g)) throw new Error(`conflicting duplicate genome id: ${g.id}`); continue; } map.set(g.id, cloneGenome(g)); }
  const out: string[] = []; const done = new Set<string>(); const visiting = new Set<string>();
  function visit(id: string): void {
    if (done.has(id)) return;
    const g = map.get(id); if (!g) return;
    if (visiting.has(id)) throw new Error("lineage cycle detected");
    visiting.add(id); for (const p of g.parentIds) visit(p); visiting.delete(id); done.add(id); out.push(id);
  }
  visit(genomeId); return out;
}
