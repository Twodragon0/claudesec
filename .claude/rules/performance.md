# Performance Rules

## Model Selection Strategy

**Haiku** (90% of Sonnet capability, 3x cost savings):
- Lightweight agents with frequent invocation
- Code generation and exploration
- Worker agents in multi-agent systems

**Sonnet** (Best coding model):
- Main development work
- Orchestrating multi-agent workflows
- Complex coding tasks

**Opus** (Deepest reasoning):
- Complex architectural decisions
- Maximum reasoning requirements
- Research and analysis tasks

## Context Window Management

Avoid last 20% of context window for:
- Large-scale refactoring
- Feature implementation spanning multiple files
- Debugging complex interactions

## Algorithm Efficiency

Before implementing:
- [ ] Consider time complexity
- [ ] Avoid O(n^2) when O(n log n) possible
- [ ] Use appropriate data structures
- [ ] Cache expensive computations

## ClaudeSec-Specific Performance

There is no production runtime to tune — performance here means fast, reliable
CI and a scanner that does not hang.

### Tests must not hang

- Set `CLAUDESEC_DASHBOARD_OFFLINE=1` for any test touching the dashboard
  generator. Un-gated GitHub API calls were the root cause of multi-minute test
  hangs (#190): with the guard, a kcov dashboard test dropped from 120s → ~3.7s.
- Per-test timeout cap in the kcov job is 30s — a test exceeding it is a bug,
  not a budget to raise.

### Scanner efficiency

- Prefer a single pass over the file tree; avoid re-walking per check.
- Cache expensive lookups (API responses, parsed configs) within a run.
- Network calls belong behind an offline guard so coverage runs stay hermetic.

### CI cost control

- Path-gate heavy jobs (scanner, docker, lighthouse) so unrelated docs PRs skip
  them — see [Git Workflow](./git-workflow.md).
- For agent work, route read-only exploration to `haiku`; reserve `opus` for
  architecture and security review.
