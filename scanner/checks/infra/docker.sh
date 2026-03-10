#!/usr/bin/env bash
# ClaudeSec — Infrastructure: Docker Security Checks

# INFRA-001: Dockerfile exists and uses non-root user
if has_file "Dockerfile" || files_contain "Dockerfile*" "FROM"; then
  if files_contain "Dockerfile*" "^USER\s+[^r]"; then
    pass "INFRA-001" "Dockerfile uses non-root user"
  elif files_contain "Dockerfile*" "USER root"; then
    fail "INFRA-001" "Dockerfile runs as root" "high" \
      "Container running as root increases attack surface" \
      "Add 'USER nonroot' or 'USER 65534' to Dockerfile"
  else
    fail "INFRA-001" "Dockerfile missing USER directive" "high" \
      "No USER directive found — container will run as root by default" \
      "Add 'USER nonroot' to Dockerfile"
  fi
else
  skip "INFRA-001" "Dockerfile non-root user" "No Dockerfile found"
fi

# INFRA-002: No latest tag in FROM
if has_file "Dockerfile" || files_contain "Dockerfile*" "FROM"; then
  if files_contain "Dockerfile*" "FROM.*:latest"; then
    fail "INFRA-002" "Dockerfile uses :latest tag" "medium" \
      "Using :latest prevents reproducible builds" \
      "Pin to specific version or SHA digest"
  else
    pass "INFRA-002" "Dockerfile uses pinned image versions"
  fi
else
  skip "INFRA-002" "Docker image pinning" "No Dockerfile found"
fi

# INFRA-003: No secrets in Dockerfile
if has_file "Dockerfile" || files_contain "Dockerfile*" "FROM"; then
  if files_contain "Dockerfile*" "(ENV|ARG).*(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)"; then
    fail "INFRA-003" "Secrets found in Dockerfile" "critical" \
      "Hardcoded secrets in Dockerfile are exposed in image layers" \
      "Use build secrets (--secret) or runtime env vars"
  else
    pass "INFRA-003" "No hardcoded secrets in Dockerfile"
  fi
else
  skip "INFRA-003" "Docker secrets check" "No Dockerfile found"
fi

# INFRA-004: Docker Compose security
if has_file "docker-compose.yml" || has_file "docker-compose.yaml" || has_file "compose.yml"; then
  if files_contain "docker-compose*" "privileged:\s*true"; then
    fail "INFRA-004" "Docker Compose uses privileged mode" "critical" \
      "Privileged containers have full host access" \
      "Remove 'privileged: true' and use specific capabilities"
  else
    pass "INFRA-004" "Docker Compose has no privileged containers"
  fi
else
  skip "INFRA-004" "Docker Compose security" "No docker-compose file found"
fi

# INFRA-005: .dockerignore exists
if has_file "Dockerfile"; then
  if has_file ".dockerignore"; then
    pass "INFRA-005" ".dockerignore file exists"
  else
    warn "INFRA-005" "Missing .dockerignore" \
      "Without .dockerignore, sensitive files may be included in the image"
  fi
else
  skip "INFRA-005" "Docker ignore file" "No Dockerfile found"
fi
