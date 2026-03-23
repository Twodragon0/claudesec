# ClaudeSec Docker image
# - Includes claudesec scanner + dashboard
# - Adds kubectl and prowler CLI so prowler/Kubernetes categories can run inside the container
# - Multi-stage build: gcc/musl-dev only in builder stage to reduce final image size
# - Optimized: removes unused cloud provider SDKs (~700MB savings)

# ── Stage 1: build prowler wheels ────────────────────────────────────────────
FROM alpine:3.20 AS builder

RUN apk add --no-cache \
    gcc \
    musl-dev \
    python3 \
    python3-dev \
    py3-pip \
    libffi-dev

RUN pip install --no-cache-dir --no-compile --break-system-packages --prefix=/install prowler \
    && find /install -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true \
    && find /install -type d -name 'tests' -exec rm -rf {} + 2>/dev/null || true \
    && find /install -name '*.dist-info' -type d -exec sh -c 'rm -rf "$1"/top_level.txt "$1"/RECORD' _ {} \; 2>/dev/null || true \
    # Remove unused cloud provider SDKs (OCI, Azure, GCP, Alibaba, Cloudflare)
    && rm -rf \
       /install/lib/python3.12/site-packages/oci* \
       /install/lib/python3.12/site-packages/azure* \
       /install/lib/python3.12/site-packages/msgraph* \
       /install/lib/python3.12/site-packages/msal* \
       /install/lib/python3.12/site-packages/microsoft* \
       /install/lib/python3.12/site-packages/googleapiclient* \
       /install/lib/python3.12/site-packages/google/cloud* \
       /install/lib/python3.12/site-packages/google_cloud* \
       /install/lib/python3.12/site-packages/googleapis* \
       /install/lib/python3.12/site-packages/cloudflare* \
       /install/lib/python3.12/site-packages/alibabacloud* \
       /install/lib/python3.12/site-packages/openstacksdk* \
       /install/lib/python3.12/site-packages/openstack* \
       /install/lib/python3.12/site-packages/plotly* \
       /install/lib/python3.12/site-packages/pandas* \
       /install/lib/python3.12/site-packages/numpy* \
       /install/lib/python3.12/site-packages/iamdata* \
       /install/lib/python3.12/site-packages/pip* \
       /install/lib/python3.12/site-packages/prowler/providers/alibabacloud \
       /install/lib/python3.12/site-packages/prowler/providers/azure \
       /install/lib/python3.12/site-packages/prowler/providers/cloudflare \
       /install/lib/python3.12/site-packages/prowler/providers/gcp \
       /install/lib/python3.12/site-packages/prowler/providers/googleworkspace \
       /install/lib/python3.12/site-packages/prowler/providers/llm \
       /install/lib/python3.12/site-packages/prowler/providers/m365 \
       /install/lib/python3.12/site-packages/prowler/providers/mongodbatlas \
       /install/lib/python3.12/site-packages/prowler/providers/nhn \
       /install/lib/python3.12/site-packages/prowler/providers/openstack \
       /install/lib/python3.12/site-packages/prowler/providers/oraclecloud \
       /install/lib/python3.12/site-packages/prowler/providers/image \
       2>/dev/null || true \
    # Patch prowler to skip removed provider imports
    && MAIN=/install/lib/python3.12/site-packages/prowler/__main__.py \
    && for p in alibabacloud azure gcp googleworkspace llm m365 mongodbatlas nhn cloudflare openstack oraclecloud image; do \
         sed -i "s|^from prowler\.providers\.${p}|# removed: ${p} #|" "$MAIN"; \
       done

# ── Stage 2: runtime image ──────────────────────────────────────────────────
FROM alpine:3.20

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

RUN chmod +x /opt/claudesec/scanner/claudesec \
    && chmod +x /opt/claudesec/scripts/*.sh \
    && adduser -D -u 1000 claudesec

USER claudesec

ENTRYPOINT ["/opt/claudesec/scanner/claudesec"]
CMD ["help"]
