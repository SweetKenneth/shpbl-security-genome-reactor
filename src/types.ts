export interface HostFinding {
  signature: string;
  severity: number;
}

export interface HostSecurityRecord {
  hostId: string;
  findings: HostFinding[];
  complianceFailed: number;
  complianceTotal: number;
  cloudTags?: Record<string, string>;
}

export interface PhenotypeVector {
  severityMean: number;
  complianceFailureRate: number;
  findingDensity: number;
}

export interface SecurityPhenotype {
  id: string;
  hostIds: string[];
  centroid: PhenotypeVector;
  dominantSignatures: string[];
}

export type ProfileMode = "observe" | "balanced" | "strict";

export interface SecurityGenome {
  id: string;
  phenotypeId: string;
  generation: number;
  parentIds: string[];
  curriculum: string[];
  cadenceHours: number;
  depth: number;
  profileMode: ProfileMode;
  mutationHistory: string[];
}

export interface TrialPlan {
  genomeId: string;
  phenotypeId: string;
  targetHostIds: string[];
  policySequence: string[];
  cadenceHours: number;
  depth: number;
  profileSuggestion: ProfileMode;
}

export interface FitnessObservation {
  riskReduction: number;
  coverage: number;
  stability: number;
  falsePositiveRate: number;
  changeCost: number;
}

export interface GenomeScore {
  genome: SecurityGenome;
  score: number;
  observation: FitnessObservation;
}

export interface EvolutionResult {
  generation: number;
  ranked: GenomeScore[];
  population: SecurityGenome[];
  promoted: SecurityGenome;
}
