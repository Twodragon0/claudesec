# AGENTS.md — scanner/

<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 -->

## Purpose

Zero-dependency bash security scanner CLI. Runs ~120+ checks across 11 categories and outputs findings to stdout or JSON. The main entrypoint is `scanner/claudesec`.

## Directory Structure

```
scanner/
├── claudesec          # Main CLI entrypoint (bash, ~1029 lines)
├── checks/            # Check modules by category
│   ├── access-control/  # .env files, password hashing, JWT, sessions
│   ├── ai/              # LLM API keys, prompt injection, RAG, agent tools
│   ├── cicd/            # GitHub Actions permissions, SHA pinning, secrets
│   ├── cloud/           # AWS, GCP, Azure IAM, logging, storage
│   ├── code/            # SQL/command/XSS injection, SSRF, XXE, crypto (24 checks)
│   ├── infra/           # Docker, Kubernetes, IaC (Terraform/Helm)
│   ├── macos/           # CIS Benchmark v4.0 macOS hardening (20 checks)
│   ├── network/         # TLS, CORS, headers, Trivy, optional Nmap/SSLScan
│   ├── prowler/         # Prowler OCSF integration (16 cloud providers)
│   ├── saas/            # SaaS API scanning: GitHub, Datadog, Okta, Slack, ...
│   └── windows/         # KISA W-series Windows checks (20 checks)
├── lib/
│   ├── checks.sh              # Core check functions (~906 lines)
│   ├── output.sh              # log_info / log_warn / log_fail formatters
│   ├── dashboard-gen.py       # HTML dashboard generator
│   ├── dashboard-template.html
│   ├── compliance-map.py      # ISMS-P / ISO / NIST / SOC 2 mapping
│   ├── audit-points-scan.py   # Audit evidence collector
│   ├── diagram-gen.py         # Architecture diagram generator
│   ├── dashboard_api_client.py
│   ├── dashboard_auth.py
│   ├── dashboard_data_loader.py
│   ├── dashboard_mapping.py
│   ├── dashboard_utils.py
│   ├── csp_utils.py
│   └── zscaler-api.py
└── tests/                     # bash + pytest test suite
```

## For AI Agents

### Adding a New Check

1. Identify the correct category directory under `checks/`.
2. Follow the existing check function pattern in `lib/checks.sh` — use `log_info`, `log_warn`, `log_fail` from `lib/output.sh`. No raw `echo`.
3. Register the check in the category's entrypoint file.
4. Add a corresponding test in `tests/` (bash or pytest depending on check type).
5. Map the check to compliance frameworks in `lib/compliance-map.py`.

### Testing

```bash
# Run all scanner tests
python3 -m pytest scanner/tests/ -v --tb=short

# Specific bash test
bash scanner/tests/test_check_cicd_pipeline.sh
bash scanner/tests/test_output_functions.sh
bash scanner/tests/test_check_infra_docker.sh

# Specific pytest
python3 -m pytest scanner/tests/test_compliance_map.py -v
python3 -m pytest scanner/tests/test_dashboard_gen_smoke.py -v
```

### Running the Scanner

```bash
./scanner/claudesec scan
./scanner/claudesec scan --category code
./scanner/claudesec scan --severity high,critical
./scanner/claudesec scan --format json
./scanner/claudesec report --output report.json
```

### Conventions

- Bash: match style in `lib/checks.sh` — 2-space indent, `local` variables, quoted expansions.
- Check IDs follow `CATEGORY-NNN` format (e.g., `SECRETS-002`, `CICD-005`).
- Allowlist paths for noise reduction: `templates/`, `examples/`, `docs/`, `scanner/tests/`.
- Python helpers: PEP 8, type hints encouraged, no third-party deps unless in `requirements-ci.txt`.
