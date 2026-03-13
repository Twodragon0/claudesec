# Lightweight image for local/code/infra/access-control scans.
# Prowler and kubectl are not included; use host or a custom image for -c prowler / Kubernetes.
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
    py3-pip

WORKDIR /opt/claudesec

COPY scanner ./scanner
COPY scripts ./scripts

RUN chmod +x /opt/claudesec/scanner/claudesec \
    && chmod +x /opt/claudesec/scripts/*.sh

ENTRYPOINT ["/opt/claudesec/scanner/claudesec"]
CMD ["help"]
