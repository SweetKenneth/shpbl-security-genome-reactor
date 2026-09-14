import * as readline from "node:readline";
import { buildTrialPlan, evolveGeneration, inferPhenotypes, lineage, seedGenomes } from "./reactor";
import type { FitnessObservation, SecurityGenome } from "./types";

const findingSchema = { type: "object", required: ["signature", "severity"], additionalProperties: false, properties: { signature: { type: "string", minLength: 1 }, severity: { type: "number", minimum: 0, maximum: 10 } } };
const recordSchema = { type: "object", required: ["hostId", "findings", "complianceFailed", "complianceTotal"], additionalProperties: false, properties: { hostId: { type: "string", minLength: 1 }, findings: { type: "array", items: findingSchema }, complianceFailed: { type: "integer", minimum: 0 }, complianceTotal: { type: "integer", minimum: 0 }, cloudTags: { type: "object", additionalProperties: { type: "string" } } } };
const phenotypeSchema = { type: "object", required: ["id", "hostIds", "centroid", "dominantSignatures"], additionalProperties: false, properties: { id: { type: "string", minLength: 1 }, hostIds: { type: "array", minItems: 1, items: { type: "string", minLength: 1 } }, centroid: { type: "object", required: ["severityMean", "complianceFailureRate", "findingDensity"], additionalProperties: false, properties: { severityMean: { type: "number", minimum: 0, maximum: 1 }, complianceFailureRate: { type: "number", minimum: 0, maximum: 1 }, findingDensity: { type: "number", minimum: 0, maximum: 1 } } }, dominantSignatures: { type: "array", items: { type: "string", minLength: 1 } } } };
const genomeSchema = { type: "object", required: ["id", "phenotypeId", "generation", "parentIds", "curriculum", "cadenceHours", "depth", "profileMode", "mutationHistory"], additionalProperties: false, properties: { id: { type: "string", minLength: 1 }, phenotypeId: { type: "string", minLength: 1 }, generation: { type: "integer", minimum: 0 }, parentIds: { type: "array", items: { type: "string", minLength: 1 } }, curriculum: { type: "array", minItems: 1, items: { type: "string", minLength: 1 } }, cadenceHours: { type: "number", exclusiveMinimum: 0 }, depth: { type: "integer", minimum: 1, maximum: 5 }, profileMode: { enum: ["observe", "balanced", "strict"] }, mutationHistory: { type: "array", items: { type: "string", minLength: 1 } } } };
const fitnessSchema = { type: "object", required: ["riskReduction", "coverage", "stability", "falsePositiveRate", "changeCost"], additionalProperties: false, properties: { riskReduction: { type: "number", minimum: 0, maximum: 1 }, coverage: { type: "number", minimum: 0, maximum: 1 }, stability: { type: "number", minimum: 0, maximum: 1 }, falsePositiveRate: { type: "number", minimum: 0, maximum: 1 }, changeCost: { type: "number", minimum: 0, maximum: 1 } } };

export const tools = [
  { name: "genome_infer_phenotypes", description: "Infer latent security phenotypes from observed findings and compliance behavior, ignoring cloud labels as ground truth.", inputSchema: { type: "object", required: ["records"], additionalProperties: false, properties: { records: { type: "array", items: recordSchema }, threshold: { type: "number", exclusiveMinimum: 0, maximum: 1 } } } },
  { name: "genome_seed", description: "Seed multiple candidate security genomes for one phenotype.", inputSchema: { type: "object", required: ["phenotype"], additionalProperties: false, properties: { phenotype: phenotypeSchema } } },
  { name: "genome_evolve", description: "Run one deterministic evolutionary generation using rehearsal by default or caller-supplied measured fitness keyed by genome id.", inputSchema: { type: "object", required: ["phenotype", "population"], additionalProperties: false, properties: { phenotype: phenotypeSchema, population: { type: "array", minItems: 2, items: genomeSchema }, fitnessByGenomeId: { type: "object", additionalProperties: fitnessSchema } } } },
  { name: "genome_trial_plan", description: "Translate a genome into a bounded target/policy/profile trial plan.", inputSchema: { type: "object", required: ["genome", "phenotype"], additionalProperties: false, properties: { genome: genomeSchema, phenotype: phenotypeSchema } } },
  { name: "genome_lineage", description: "Return ancestry in parent-before-child order for a genome from a supplied population/history.", inputSchema: { type: "object", required: ["genomeId", "genomes"], additionalProperties: false, properties: { genomeId: { type: "string", minLength: 1 }, genomes: { type: "array", items: genomeSchema } } } },
] as const;

function toolResult(value: unknown): any { return { content: [{ type: "text", text: JSON.stringify(value) }], structuredContent: { result: value } }; }

export function handleRequest(req: any): any {
  if (!req || req.jsonrpc !== "2.0" || typeof req.method !== "string") throw Object.assign(new Error("Invalid Request"), { code: -32600 });
  if (req.method === "initialize") return { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "@shpbl/security-genome-reactor", version: "1.0.0" } };
  if (req.method === "notifications/initialized") return undefined;
  if (req.method === "tools/list") return { tools };
  if (req.method !== "tools/call") throw Object.assign(new Error("Method not found"), { code: -32601 });
  const name = req.params?.name; const a = req.params?.arguments ?? {};
  if (name === "genome_infer_phenotypes") return toolResult(inferPhenotypes(a.records ?? [], a.threshold ?? .68));
  if (name === "genome_seed") return toolResult(seedGenomes(a.phenotype));
  if (name === "genome_evolve") {
    const measured = a.fitnessByGenomeId as Record<string, FitnessObservation> | undefined;
    const evaluator = measured ? (g: SecurityGenome): FitnessObservation => {
      const observation = measured[g.id];
      if (!observation) throw new Error(`missing measured fitness for genome ${g.id}`);
      return observation;
    } : undefined;
    return toolResult(evaluator ? evolveGeneration(a.phenotype, a.population ?? [], evaluator) : evolveGeneration(a.phenotype, a.population ?? []));
  }
  if (name === "genome_trial_plan") return toolResult(buildTrialPlan(a.genome, a.phenotype));
  if (name === "genome_lineage") return toolResult(lineage(a.genomeId, a.genomes ?? []));
  throw Object.assign(new Error(`unknown tool: ${String(name)}`), { code: -32602 });
}

export async function serve(): Promise<void> {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let req: any;
    try { req = JSON.parse(line); }
    catch { process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }) + "\n"); continue; }
    try {
      const result = handleRequest(req);
      if (req.method === "notifications/initialized") continue;
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: req.id ?? null, result }) + "\n");
    } catch (e: any) {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: req.id ?? null, error: { code: Number(e?.code) || -32000, message: String(e?.message ?? e) } }) + "\n");
    }
  }
}
if (require.main === module) void serve();
