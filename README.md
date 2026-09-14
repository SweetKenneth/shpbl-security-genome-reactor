# Security Genome Reactor

**Evolve scan and policy configurations against the fleet's measured phenotype instead of its labels.**

Infers latent security phenotypes from observed findings rather than operator labels, seeds competing scan/policy genomes per phenotype, evolves them under measured fitness, and keeps an explicit parent-before-child ancestry graph for every configuration in production.

It is an analysis and decision surface, not an actuator: it has no network client, touches no files, spawns no processes, and reads no environment variables.

## Why a practitioner would install this

- **Tags lie; behaviour does not.** Phenotypes are inferred from observed findings and compliance behaviour, so a mislabelled asset group stops driving the scan policy.
- **Configurations compete instead of accumulating.** Each phenotype gets several candidate genomes that are scored, not one inherited profile nobody dares change.
- **Fitness can be measured, not asserted.** Callers may supply real measured fitness per genome; rehearsal is the fallback, never a substitute presented as measurement.
- **Every configuration has parents.** Ancestry is returned in parent-before-child order, so 'why is this profile like this' has an answer.
- **A genome becomes a bounded trial.** The reactor emits an explicit target/policy/profile trial plan rather than mutating anything.

## Behavioural contract

1. `genome_infer_phenotypes` infers phenotypes from records above an explicit threshold and ignores cloud labels as ground truth.
2. `genome_seed` seeds multiple competing genomes for one phenotype.
3. `genome_evolve` runs one deterministic generation using caller-supplied measured fitness keyed by genome id, or rehearsal when none is supplied.
4. `genome_trial_plan` translates one genome into a bounded target/policy/profile trial plan.
5. `genome_lineage` returns ancestry in parent-before-child order and rejects cycles.
6. Populations below two genomes, unknown ids and invalid thresholds fail closed.

## Prerequisites

- Node.js 20 or newer (`node --version`). Zero runtime dependencies.
- An MCP client that speaks stdio (Claude Code, Claude Desktop, Cursor), or direct library use from TypeScript.
- No API key, account, network access or Tenable product is required.

## Install and run

```bash
git clone https://github.com/SweetKenneth/shpbl-security-genome-reactor.git
cd shpbl-security-genome-reactor
npm install      # devDependencies only: typescript
npm run build    # compiles to dist/
npm test         # 39 behavioural, boundary and fail-closed tests
npm start        # starts the MCP server on stdio
```

MCP client configuration:

```json
{
  "mcpServers": {
    "security-genome-reactor": {
      "command": "node",
      "args": ["/absolute/path/to/shpbl-security-genome-reactor/dist/src/mcp-server.js"]
    }
  }
}
```

## Tools exposed

- `genome_infer_phenotypes` — Infer latent security phenotypes from observed findings and compliance behavior, ignoring cloud labels as ground truth.
- `genome_seed` — Seed multiple candidate security genomes for one phenotype.
- `genome_evolve` — Run one deterministic evolutionary generation using rehearsal by default or caller-supplied measured fitness keyed by genome id.
- `genome_trial_plan` — Translate a genome into a bounded target/policy/profile trial plan.
- `genome_lineage` — Return ancestry in parent-before-child order for a genome from a supplied population/history.

## What it outputs

Inferred phenotypes with supporting evidence, competing genome populations, per-generation fitness and selection results, bounded trial plans, and ordered ancestry graphs.

## Verification

Reproduce all of it from a clean clone with `npm run check`:

- Strict TypeScript compile and `--noEmit` typecheck: **PASS**
- Behavioural tests: **39/39 PASS**
- Randomised invariant hammer: **30,000 cases / 420,000 invariant checks PASS**
- Static scan for network, filesystem, process and dynamic-eval surfaces in `src/`: **PASS (0 findings)**
- Worked example runs end to end: **PASS**
- Runtime dependencies: **0**

## Known limitations

- No scanner or cloud client is embedded; records, fitness and execution are supplied by the caller.
- Rehearsal fitness is an explicit fallback and is labelled as such — it is not a measurement of your fleet.
- Phenotype inference is a deterministic clustering of supplied observations, not a claim about intent or ownership.
- The reactor proposes trials. It never changes a scan, policy or profile.

## Provenance and lineage

This product exists because two things were put together, and both are credited.

**Upstream capability inspiration — [`conard0-git/targeted-nessus-scan`](https://github.com/conard0-git/targeted-nessus-scan)**, by Isaac Conard (conard0-git), MIT licensed. Its observed behaviour was studied as a capability surface: what a practitioner in that domain actually needs to do. The exact paths and lines that were read are recorded in [`PROVENANCE.json`](./PROVENANCE.json). **No line of upstream implementation code is used in this package.** The upstream licence text is preserved under `THIRD_PARTY_NOTICES/` as provenance; it does not license this implementation.

**SHPBL capability library — [shpbl.com](https://shpbl.com).** SHPBL ([shpbl.com](https://shpbl.com)) is a governed library of reusable software capabilities and a method for composing them: it reads a target repository, identifies what capability it demonstrates, matches that against owned capability records, and writes new software where neither side had it before. The capability parents used here are listed by identifier in `PROVENANCE.json`. **No harvested capability body is embedded in this package.**

**The implementation in this repository was written fresh** from the approved capability contract for this run. The literal composition is 0% upstream code, 0% copied SHPBL capability bodies, 100% new implementation. That is an exact-line and byte-level statement about this source tree, not a legal opinion.

Author and copyright: **Kenneth E. Sweet Jr.**, MIT licensed.

Attribution does not imply endorsement by Isaac Conard (conard0-git), Tenable, or any other party.

## Tenable status

Submitted to the Tenable CyberAgents Exchange for review. Submission does not imply review, approval, certification, validation, endorsement or acceptance by Tenable.

## Files

- `src/` — implementation and the stdio MCP server.
- `tests/` — behavioural, fail-closed and MCP integration tests.
- `scripts/` — randomised invariant hammer and the static security scan.
- `examples/worked-example.ts` — an end-to-end run you can execute.
- `SECURITY.md` — threat boundary and forbidden behaviour.
- `PROVENANCE.json` — upstream and SHPBL capability lineage.
- `MANIFEST.json` / `CHECKSUMS.sha256` — released file inventory and hashes.
- `LICENSE` — MIT.

## License

MIT © 2026 Kenneth E. Sweet Jr.. See [`LICENSE`](./LICENSE).
