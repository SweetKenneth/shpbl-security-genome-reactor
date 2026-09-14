# Security boundary — Security Genome Reactor

This package is a local deterministic reasoning component. It contains no network client, cloud credential loader, Nessus credential handling, shell/process execution, filesystem write path, or live remediation transport. Its MCP surface communicates only over stdin/stdout.

The source project describes real Nessus/AWS integration behavior; this artifact deliberately does **not** copy or embed those clients. Production execution must be supplied by an authorized integration at the explicit adapter/plan boundary.

- Genetic language is metaphorical. The package evolves configuration strategies, not biological material.
- The built-in rehearsal function is a deterministic simulation for pre-trial comparison; production fitness should be supplied from measured scan/profile outcomes.
- No scan or profile mutation is executed by this package; trial plans must be handed to an authorized integration.

## Reporting

To report a vulnerability in this package, open a GitHub issue on this repository, or contact the author through https://shpbl.com. There is no embedded network, filesystem or process surface to exploit remotely; the highest-value reports are logic flaws that let a gate pass without its evidence.
