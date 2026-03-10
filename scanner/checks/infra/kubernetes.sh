#!/usr/bin/env bash
# ClaudeSec — Infrastructure: Kubernetes Security Checks

local k8s_files
k8s_files=$(count_files "*.yaml" 2>/dev/null)
local has_k8s=false

# Detect Kubernetes manifests
if files_contain "*.yaml" "kind:\s*(Deployment|Pod|StatefulSet|DaemonSet)" 2>/dev/null || \
   files_contain "*.yml" "kind:\s*(Deployment|Pod|StatefulSet|DaemonSet)" 2>/dev/null; then
  has_k8s=true
fi

if [[ "$has_k8s" == "true" ]]; then
  # INFRA-010: Pod Security — runAsNonRoot
  if files_contain "*.yaml" "runAsNonRoot:\s*true" || files_contain "*.yml" "runAsNonRoot:\s*true"; then
    pass "INFRA-010" "Kubernetes pods configured to run as non-root"
  else
    fail "INFRA-010" "Kubernetes pods missing runAsNonRoot" "high" \
      "Pods without runAsNonRoot may run as root" \
      "Add 'securityContext.runAsNonRoot: true' to pod spec"
  fi

  # INFRA-011: Drop all capabilities
  if files_contain "*.yaml" "drop:.*ALL" || files_contain "*.yml" "drop:.*ALL"; then
    pass "INFRA-011" "Containers drop all capabilities"
  else
    warn "INFRA-011" "Containers may have unnecessary capabilities" \
      "Add 'capabilities: { drop: [ALL] }' and add back only what's needed"
  fi

  # INFRA-012: Resource limits
  if files_contain "*.yaml" "limits:" || files_contain "*.yml" "limits:"; then
    pass "INFRA-012" "Resource limits defined for containers"
  else
    fail "INFRA-012" "Missing resource limits" "medium" \
      "Without limits, a container can consume all node resources" \
      "Add resources.limits for cpu and memory"
  fi

  # INFRA-013: Read-only root filesystem
  if files_contain "*.yaml" "readOnlyRootFilesystem:\s*true" || \
     files_contain "*.yml" "readOnlyRootFilesystem:\s*true"; then
    pass "INFRA-013" "Read-only root filesystem enabled"
  else
    warn "INFRA-013" "Read-only root filesystem not set" \
      "Set 'readOnlyRootFilesystem: true' to prevent filesystem modifications"
  fi

  # INFRA-014: NetworkPolicy exists
  if files_contain "*.yaml" "kind:\s*NetworkPolicy" || files_contain "*.yml" "kind:\s*NetworkPolicy"; then
    pass "INFRA-014" "NetworkPolicy defined"
  else
    fail "INFRA-014" "No NetworkPolicy found" "high" \
      "Without NetworkPolicy, all pod-to-pod traffic is allowed" \
      "Create a default-deny NetworkPolicy for each namespace"
  fi

  # INFRA-015: No automountServiceAccountToken
  if files_contain "*.yaml" "automountServiceAccountToken:\s*false" || \
     files_contain "*.yml" "automountServiceAccountToken:\s*false"; then
    pass "INFRA-015" "Service account token auto-mount disabled"
  else
    warn "INFRA-015" "Service account tokens may be auto-mounted" \
      "Set 'automountServiceAccountToken: false' unless SA token is needed"
  fi
else
  skip "INFRA-010" "K8s pod security" "No Kubernetes manifests found"
  skip "INFRA-011" "K8s capabilities" "No Kubernetes manifests found"
  skip "INFRA-012" "K8s resource limits" "No Kubernetes manifests found"
  skip "INFRA-013" "K8s read-only fs" "No Kubernetes manifests found"
  skip "INFRA-014" "K8s NetworkPolicy" "No Kubernetes manifests found"
  skip "INFRA-015" "K8s SA token" "No Kubernetes manifests found"
fi

# INFRA-016: Kubernetes cluster — live check
if has_kubectl_access 2>/dev/null; then
  # Check for pods running as root
  local root_pods
  root_pods=$(kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.spec.securityContext.runAsNonRoot}{"\n"}{end}' 2>/dev/null | grep -c "false" || echo "0")
  if [[ "$root_pods" -gt 0 ]]; then
    fail "INFRA-016" "$root_pods pod(s) running without runAsNonRoot" "high" \
      "Live cluster has pods that may run as root" \
      "Update pod security context or enforce Pod Security Standards"
  else
    pass "INFRA-016" "No pods running as root in cluster"
  fi
else
  skip "INFRA-016" "K8s live cluster check" "kubectl not available or not connected"
fi
