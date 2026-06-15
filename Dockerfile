# ClaudeSec Docker image
# - Includes claudesec scanner + dashboard
# - Adds kubectl and prowler CLI so prowler/Kubernetes categories can run inside the container
# - Multi-stage build: gcc/musl-dev only in builder stage to reduce final image size
# - Optimized: removes unused cloud provider SDKs (~700MB savings)

# ── Stage 1: build prowler wheels ────────────────────────────────────────────
# Base image pinned by digest for reproducible, supply-chain-safe builds.
# Dependabot (docker ecosystem) bumps the digest when alpine:3.20 is rebuilt.
FROM alpine:3.24@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4 AS builder

RUN apk add --no-cache \
    gcc \
    musl-dev \
    python3 \
    python3-dev \
    py3-pip \
    libffi-dev

RUN pip install --no-cache-dir --no-compile --break-system-packages --prefix=/install prowler \
    # Resolve site-packages without hardcoding the Python minor version, so an
    # alpine base bump (e.g. 3.20/py3.12 -> 3.24/py3.13) does not break the build.
    && SITE="$(find /install/lib -maxdepth 1 -type d -name 'python3.*' | sort | head -n1)/site-packages" \
    && find /install -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true \
    && find /install -type d -name 'tests' -exec rm -rf {} + 2>/dev/null || true \
    && find /install -name '*.dist-info' -type d -exec sh -c 'rm -rf "$1"/top_level.txt "$1"/RECORD' _ {} \; 2>/dev/null || true \
    # Remove unused cloud provider SDKs (OCI, Azure, GCP, Alibaba, Cloudflare)
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
FROM alpine:3.24@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4

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

ARG TRIVY_VERSION=0.69.3
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
