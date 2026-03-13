# ClaudeSec Docker image
# - Includes claudesec scanner + dashboard
# - Adds kubectl and prowler CLI so prowler/Kubernetes categories can run inside the container
# - Multi-stage build: gcc/musl-dev only in builder stage to reduce final image size

# ── Stage 1: build prowler wheels ────────────────────────────────────────────
FROM alpine:3.20 AS builder

RUN apk add --no-cache \
    gcc \
    musl-dev \
    python3 \
    python3-dev \
    py3-pip

RUN pip install --no-cache-dir --break-system-packages --prefix=/install prowler

# ── Stage 2: runtime image ──────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    ca-certificates \
    curl \
    git \
    jq \
    lsof \
    procps \
    python3 \
    py3-pip \
    kubectl

# Copy pre-built prowler from builder
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
