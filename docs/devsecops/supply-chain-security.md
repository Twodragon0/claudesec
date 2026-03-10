---
title: Software Supply Chain Security
description: SLSA, SBOM, Sigstore, and OpenSSF practices for supply chain integrity
tags: [supply-chain, slsa, sbom, sigstore, openssf, sca]
---

# Software Supply Chain Security

Supply chain attacks (SolarWinds, Log4Shell, xz-utils, 2025 Bybit hack) demonstrate that securing your own code is insufficient — you must secure everything that builds, tests, and deploys it.

## Framework Overview

```
┌─────────────────────────────────────────────────┐
│              Supply Chain Security                │
├────────────┬────────────┬────────────┬───────────┤
│   SLSA     │   SBOM     │  Sigstore  │  OpenSSF  │
│ Build      │ Inventory  │ Signing    │ Health    │
│ Integrity  │ & Audit    │ & Verify   │ Scoring   │
└────────────┴────────────┴────────────┴───────────┘
```

---

## SLSA (Supply-chain Levels for Software Artifacts)

[slsa.dev](https://slsa.dev/) — Currently v1.2, maintained by OpenSSF.

### Levels

| Level | Requirements | Protection |
|-------|-------------|------------|
| **Level 1** | Provenance documentation exists | Awareness of build process |
| **Level 2** | Hosted build service generates signed provenance | Prevents tampering after build |
| **Level 3** | Hardened build platform, isolated builds | Prevents tampering during build |
| **Level 4** | Two-party review, hermetic builds | Prevents insider threats |

### Three Domains

| Domain | What It Secures | Example Controls |
|--------|----------------|-----------------|
| **Source** | Code integrity | Branch protection, signed commits, review requirements |
| **Build** | Build reproducibility | Hosted CI, build provenance, hermetic builds |
| **Dependencies** | Component reliability | Lock files, vulnerability scanning, SBOM |

### GitHub Actions SLSA Implementation

```yaml
# Generate SLSA provenance for container images
name: SLSA Build
on:
  push:
    tags: ['v*']

permissions:
  contents: read
  packages: write
  id-token: write  # Required for signing

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: docker/build-push-action@v5
        id: build
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}

      # Generate SLSA provenance
      - uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
        with:
          image: ghcr.io/${{ github.repository }}
          digest: ${{ steps.build.outputs.digest }}
```

---

## SBOM (Software Bill of Materials)

An SBOM is a machine-readable inventory of all software components, dependencies, and their relationships.

### Formats

| Format | Maintainer | Strength |
|--------|-----------|----------|
| **SPDX** (ISO/IEC 5962) | Linux Foundation | License compliance focus |
| **CycloneDX** | OWASP | Security and vulnerability focus |

### Generation Tools

| Tool | Languages | Output Formats |
|------|-----------|---------------|
| **Syft** (Anchore) | Multi-language | SPDX, CycloneDX |
| **Trivy** (Aqua) | Multi-language | SPDX, CycloneDX + vuln scan |
| **cdxgen** | JS/Java/Python | CycloneDX |
| **docker buildx** | Container | SPDX (native `--sbom`) |

### CI Integration

```yaml
# Generate SBOM + scan vulnerabilities
- name: Generate SBOM
  run: |
    # Install Syft
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s

    # Generate CycloneDX SBOM
    syft . -o cyclonedx-json > sbom.cdx.json

    # Also generate SPDX format
    syft . -o spdx-json > sbom.spdx.json

- name: Scan SBOM for vulnerabilities
  run: |
    # Grype scans SBOMs for known CVEs
    grype sbom:sbom.cdx.json --fail-on high

- name: Upload SBOM as artifact
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.*.json

# Track dependencies with Dependency-Track
- name: Upload to Dependency-Track
  run: |
    curl -X POST "$DTRACK_URL/api/v1/bom" \
      -H "X-Api-Key: ${{ secrets.DTRACK_API_KEY }}" \
      -F "project=$PROJECT_UUID" \
      -F "bom=@sbom.cdx.json"
```

---

## Sigstore — Keyless Artifact Signing

[sigstore.dev](https://www.sigstore.dev/) eliminates the need for key management by using ephemeral keys backed by OIDC identity.

### Components

| Component | Purpose |
|-----------|---------|
| **Cosign** | Sign/verify container images and blobs |
| **Rekor** | Immutable transparency log (tamper-evident) |
| **Fulcio** | Ephemeral certificate authority |

### Usage

```bash
# Sign a container image (keyless)
cosign sign --yes ghcr.io/myorg/myapp:v1.0.0

# Verify a signature
cosign verify \
  --certificate-identity="user@example.com" \
  --certificate-oidc-issuer="https://github.com/login/oauth" \
  ghcr.io/myorg/myapp:v1.0.0

# Sign a generic artifact (e.g., SBOM)
cosign sign-blob --yes sbom.cdx.json --bundle sbom.cdx.json.bundle

# Verify artifact signature
cosign verify-blob \
  --bundle sbom.cdx.json.bundle \
  --certificate-identity="..." \
  --certificate-oidc-issuer="..." \
  sbom.cdx.json
```

### Admission Control — Enforce Signed Images

```yaml
# Kyverno policy — reject unsigned images
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-signature
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - imageReferences: ["ghcr.io/myorg/*"]
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/myorg/*"
                    issuer: "https://token.actions.githubusercontent.com"
```

---

## OpenSSF Scorecard

[scorecard.dev](https://scorecard.dev/) — Automated security health checks for open source repositories.

### 18+ Checks

| Check | What It Measures |
|-------|-----------------|
| Binary-Artifacts | No compiled binaries in repo |
| Branch-Protection | Branch protection enabled |
| CI-Tests | CI runs tests on PRs |
| Code-Review | Changes require review |
| Dangerous-Workflow | No dangerous CI patterns |
| Dependency-Update-Tool | Dependabot/Renovate configured |
| License | License file exists |
| Maintained | Recent commits and activity |
| Pinned-Dependencies | Dependencies pinned by hash |
| SAST | Static analysis configured |
| Security-Policy | SECURITY.md exists |
| Signed-Releases | Releases are signed |
| Token-Permissions | CI tokens use least privilege |
| Vulnerabilities | No known vulnerabilities (OSV) |

### CI Integration

```yaml
# .github/workflows/scorecard.yml
name: OpenSSF Scorecard
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'

permissions:
  security-events: write
  id-token: write

jobs:
  analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: ossf/scorecard-action@v2
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Dependency Management Strategy

### Pinning Strategy by Risk

| Dependency Type | Strategy | Example |
|-----------------|----------|---------|
| GitHub Actions | **Pin SHA** | `actions/checkout@b4ffde65...` |
| Production deps | **Lock exact** | `package-lock.json` |
| Container base images | **Pin digest** | `node@sha256:abc123...` |
| Dev dependencies | **Lock minor** | `^1.2.0` with lock file |

### Automated Scanning Pipeline

```
On every PR:
  ├── npm audit / pip-audit / cargo audit
  ├── Trivy vulnerability scan
  ├── License compliance check
  └── Dependency-Review Action (block high/critical)

Weekly:
  ├── Dependabot PRs (grouped by type)
  ├── OpenSSF Scorecard
  └── Full SBOM regeneration

On release:
  ├── SBOM attached to release
  ├── Artifact signed with Cosign
  └── SLSA provenance generated
```

---

## Supply Chain Security Maturity

| Level | Practice | Tools |
|-------|----------|-------|
| **Basic** | Lock files + `npm audit` | Dependabot |
| **Intermediate** | SBOM + vulnerability scanning | Syft, Grype, Trivy |
| **Advanced** | Artifact signing + SLSA Level 2 | Cosign, SLSA generator |
| **Expert** | Hermetic builds + admission control | Kyverno, in-toto, GUAC |

## References

- [SLSA Official — slsa.dev](https://slsa.dev/)
- [Sigstore — sigstore.dev](https://www.sigstore.dev/)
- [OpenSSF Scorecard — scorecard.dev](https://scorecard.dev/)
- [OWASP CycloneDX](https://cyclonedx.org/)
- [SPDX Specification](https://spdx.dev/)
- [Anchore Syft](https://github.com/anchore/syft)
- [Anchore Grype](https://github.com/anchore/grype)
- [CISA SBOM Resources](https://www.cisa.gov/sbom)
- [in-toto Framework](https://in-toto.io/)
- [GUAC — Graph for Understanding Artifact Composition](https://guac.sh/)
