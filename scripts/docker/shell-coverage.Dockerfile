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
RUN set -eux; \
    TMP="$(mktemp -d)"; cd "$TMP"; \
    curl -fsSL "https://github.com/SimonKagstrom/kcov/archive/refs/tags/v${KCOV_VERSION}.tar.gz" | tar xz; \
    cd "kcov-${KCOV_VERSION}"; mkdir build && cd build; \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..; \
    make -j"$(nproc)"; \
    make install; \
    cd /; rm -rf "$TMP"; \
    kcov --version

WORKDIR /repo
