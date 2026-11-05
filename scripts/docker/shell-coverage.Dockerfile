# Local kcov shell-coverage verification image.
#
# Mirrors the `scanner-shell-coverage` CI job (lint.yml): ubuntu + kcov v42 built
# from source (jammy/noble apt kcov is v38, which reports 0% for sourced bash).
# Lets macOS developers pre-verify the bash coverage floor locally — kcov is a
# Linux/ptrace tool and does not function on macOS hosts.
#
# Build once (kcov compile is cached as a layer):
#   docker build -f scripts/docker/shell-coverage.Dockerfile -t claudesec-kcov .
# Then run via scripts/verify-shell-coverage-docker.sh
FROM ubuntu:24.04

ARG KCOV_VERSION=42
# Re-verify with the source URL below and shasum -a 256; keep in sync with CI.
ARG KCOV_SHA256=2c47d75397af248bc387f60cdd79180763e1f88f3dd71c94bb52478f8e74a1f8
ENV DEBIAN_FRONTEND=noninteractive

# Runtime + build deps for kcov, plus python3/jq/shellcheck/git for the tests.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl \
      libdw1 libcurl4 libssl3 zlib1g binutils \
      binutils-dev libcurl4-openssl-dev libdw-dev libiberty-dev \
      libssl-dev zlib1g-dev cmake build-essential pkg-config \
      python3 python3-pip jq shellcheck git \
    && rm -rf /var/lib/apt/lists/*

# Build kcov v42 from source (matches the CI pin).
# CMake 4 rejects kcov v42's 2.8.12 policy floor; match the CI workaround.
RUN set -eux; \
    TMP="$(mktemp -d)"; cd "$TMP"; \
    curl -fsSL --retry 3 -o kcov.tar.gz "https://github.com/SimonKagstrom/kcov/archive/refs/tags/v${KCOV_VERSION}.tar.gz"; \
    echo "${KCOV_SHA256}  kcov.tar.gz" | sha256sum -c -; \
    tar xzf kcov.tar.gz; \
    cd "kcov-${KCOV_VERSION}"; mkdir build && cd build; \
    cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_INSTALL_PREFIX=/usr/local ..; \
    make -j"$(nproc)"; \
    make install; \
    cd /; rm -rf "$TMP"; \
    kcov --version

WORKDIR /repo
