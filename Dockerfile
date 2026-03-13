# ClaudeSec Docker image
# - Includes claudesec scanner + dashboard
# - Adds kubectl and prowler CLI so prowler/Kubernetes categories can run inside the container
FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    ca-certificates \
    curl \
    git \
    gcc \
    jq \
    lsof \
    musl-dev \
    procps \
    python3 \
    python3-dev \
    py3-pip \
    kubectl

WORKDIR /opt/claudesec

COPY scanner ./scanner
COPY scripts ./scripts

RUN chmod +x /opt/claudesec/scanner/claudesec \
    && chmod +x /opt/claudesec/scripts/*.sh \
    && pip install --no-cache-dir --break-system-packages prowler \
    && adduser -D -u 1000 claudesec

USER claudesec

ENTRYPOINT ["/opt/claudesec/scanner/claudesec"]
CMD ["help"]
