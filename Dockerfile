# ClaudeSec Docker image
# - Includes claudesec scanner + dashboard
# - Adds kubectl and prowler CLI so prowler/Kubernetes categories can run inside the container
# - Multi-stage build: gcc/musl-dev only in builder stage to reduce final image size
# - Optimized: removes unused cloud provider SDKs (~700MB savings)

# ── Stage 1: build prowler wheels ────────────────────────────────────────────
# Base image pinned by digest for reproducible, supply-chain-safe builds.
# Dependabot (docker ecosystem) bumps the digest when alpine:3.20 is rebuilt.
#
# DO NOT bump the alpine MINOR version. The boundary is NOT "every minor changes
# Python" — measured 2026-08-24 by installing `python3` in each image:
#
#     alpine:3.20 -> Python 3.12.13     alpine:3.23 -> Python 3.12.14
#     alpine:3.21 -> Python 3.12.14     alpine:3.24 -> Python 3.14.7
#     alpine:3.22 -> Python 3.12.14
#
# alpine skips py3.13 entirely and jumps 3.12 -> 3.14 at the 3.23/3.24 boundary.
# prowler 5.39.1 requires `<3.14,>=3.10`, so **3.24 is still out of range** and
# the freeze still earns its keep. 3.21-3.23 happen to be safe (same py3.12
# line), but Dependabot cannot tell a safe minor from the one that crosses the
# boundary, so minor/major stay ignored in .github/dependabot.yml.
#
# NOTE ON ISSUE #295: the `prowler-python-watch` action fired correctly when
# prowler's ceiling moved `<3.13` -> `<3.14`, but that does NOT unblock alpine —
# there is no alpine minor shipping py3.13 to move to, and the next one ships
# py3.14. Bumping to 3.24 on the strength of that alert would reintroduce exactly
# the runtime crash the freeze exists to prevent (#220).
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS builder

RUN apk add --no-cache \
    gcc \
    musl-dev \
    python3 \
    python3-dev \
    py3-pip \
    libffi-dev

# Pin prowler explicitly for reproducible builds. UNPINNED installs are resolved
# against the base image's Python, and on an out-of-range Python pip silently
# BACKTRACKS to an ancient release that still accepts it (3.11.3, pydantic v1,
# crashes at runtime) instead of failing fast — that is the #237 defect, and it is
# why this is a pin and not a floor.
#
# prowler's requirement is now `>=3.10,<3.14` (it was `<3.13` when this file was
# written; prowler-cloud/prowler#6737). py3.12 is comfortably inside it.
#
# Verified for 5.39.1 on this exact base, 2026-08-24:
#   alpine:3.20 -> Python 3.12.13
#   pip install prowler==5.39.1 -> ok
#   prowler --version -> "Prowler 5.39.1"   (runs, not just installs)
#   pydantic 2.12.5   (v2 — the pydantic-v1 hazard belongs to the 3.11.3
#                      backtrack target, not to a current release)
ARG PROWLER_VERSION=5.39.1
RUN pip install --no-cache-dir --no-compile --break-system-packages --prefix=/install "prowler==${PROWLER_VERSION}" \
    # Resolve site-packages without hardcoding the Python minor version, so an
    # alpine base bump does not break the build. The old example here said
    # "3.24/py3.13", which is wrong in a way worth correcting rather than
    # deleting: alpine 3.24 ships py3.14, not py3.13 (see the measured table
    # above), and py3.14 is outside prowler's range. The version-agnostic glob is
    # still the right mechanism; only the example was misleading.
    && SITE="$(find /install/lib -maxdepth 1 -type d -name 'python3.*' | sort | head -n1)/site-packages" \
    && find /install -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true \
    && find /install -type d -name 'tests' -exec rm -rf {} + 2>/dev/null || true \
    && find /install -name '*.dist-info' -type d -exec sh -c 'rm -rf "$1"/top_level.txt "$1"/RECORD' _ {} \; 2>/dev/null || true \
    # Remove unused cloud provider SDKs (OCI, Azure, GCP, Alibaba, Cloudflare).
    # scanner/checks/prowler/integration.sh detects absent provider dirs at runtime
    # and emits an accurate skip message instead of a misleading auth warning.
    && rm -rf \
       "${SITE}"/oci* \
       "${SITE}"/azure* \
       "${SITE}"/msgraph* \
       "${SITE}"/msal* \
       "${SITE}"/microsoft* \
       "${SITE}"/googleapiclient* \
       "${SITE}"/google/cloud* \
       "${SITE}"/google_cloud* \
       "${SITE}"/googleapis* \
       "${SITE}"/cloudflare* \
       "${SITE}"/alibabacloud* \
       "${SITE}"/openstacksdk* \
       "${SITE}"/openstack* \
       "${SITE}"/plotly* \
       "${SITE}"/pandas* \
       "${SITE}"/numpy* \
       "${SITE}"/iamdata* \
       "${SITE}"/pip* \
       "${SITE}"/prowler/providers/alibabacloud \
       "${SITE}"/prowler/providers/azure \
       "${SITE}"/prowler/providers/cloudflare \
       "${SITE}"/prowler/providers/gcp \
       "${SITE}"/prowler/providers/googleworkspace \
       "${SITE}"/prowler/providers/llm \
       "${SITE}"/prowler/providers/m365 \
       "${SITE}"/prowler/providers/mongodbatlas \
       "${SITE}"/prowler/providers/nhn \
       "${SITE}"/prowler/providers/openstack \
       "${SITE}"/prowler/providers/oraclecloud \
       "${SITE}"/prowler/providers/image \
       2>/dev/null || true \
    # Patch prowler to skip removed provider imports (guard: skip if entrypoint moved)
    && MAIN="${SITE}/prowler/__main__.py" \
    && if [ -f "$MAIN" ]; then \
         for p in alibabacloud azure gcp googleworkspace llm m365 mongodbatlas nhn cloudflare openstack oraclecloud image; do \
           sed -i "s|^from prowler\.providers\.${p}|# removed: ${p} #|" "$MAIN"; \
         done; \
       else \
         echo "WARNING: $MAIN not found; skipping provider-import patch" >&2; \
       fi

# ── Stage 2: runtime image ──────────────────────────────────────────────────
# Pinned by digest (same alpine:3.20 release as the builder stage).
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache \
    bash \
    ca-certificates \
    curl \
    git \
    jq \
    nmap \
    python3 \
    py3-pip \
    kubectl

ARG TRIVY_VERSION=0.72.0
# Trivy vulnerability scanner (used by ClaudeSec network checks)
# Install by downloading the prebuilt Linux binary asset with checksum verification.
RUN set -eux; \
  arch="$(uname -m)"; \
  case "$arch" in \
    x86_64) asset_arch="Linux-64bit" ;; \
    aarch64) asset_arch="Linux-ARM64" ;; \
    *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
  esac; \
  trivy_file="trivy_${TRIVY_VERSION}_${asset_arch}.tar.gz"; \
  curl -fsSL -o "/tmp/${trivy_file}" \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${trivy_file}"; \
  curl -fsSL -o /tmp/trivy_checksums.txt \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"; \
  cd /tmp && grep "${trivy_file}" trivy_checksums.txt | sha256sum -c -; \
  tar -xzf "/tmp/${trivy_file}" -C /usr/local/bin/ trivy; \
  chmod +x /usr/local/bin/trivy; \
  rm -f "/tmp/${trivy_file}" /tmp/trivy_checksums.txt

# Copy pre-built prowler from builder (unused providers stripped)
COPY --from=builder /install /usr

WORKDIR /opt/claudesec

COPY scanner ./scanner
COPY scripts ./scripts

RUN chmod -R a+rX /opt/claudesec/scanner/ \
    && chmod -R a+rX /opt/claudesec/scripts/ \
    && adduser -D -u 1000 claudesec

USER claudesec

ENTRYPOINT ["/opt/claudesec/scanner/claudesec"]
CMD ["help"]
