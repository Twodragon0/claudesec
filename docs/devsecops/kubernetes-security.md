---
title: Kubernetes Security Best Practices
description: Comprehensive guide to securing Kubernetes clusters and workloads
tags: [kubernetes, k8s, container-security, pod-security, runtime]
---

# Kubernetes Security Best Practices

## Security Layers

```
┌─────────────────────────────────────────┐
│           Supply Chain                   │
│  Image scanning, signing, base images   │
├─────────────────────────────────────────┤
│           Control Plane                  │
│  API server, etcd, admission control    │
├─────────────────────────────────────────┤
│           Workload                       │
│  Pod security, RBAC, service accounts   │
├─────────────────────────────────────────┤
│           Network                        │
│  NetworkPolicy, mTLS, service mesh      │
├─────────────────────────────────────────┤
│           Runtime                        │
│  Falco, seccomp, AppArmor, eBPF        │
├─────────────────────────────────────────┤
│           Data                           │
│  Secrets management, encryption at rest │
└─────────────────────────────────────────┘
```

---

## 1. Image Security

### Build Secure Images

```dockerfile
# Use minimal base images
FROM cgr.dev/chainguard/node:latest AS build
# Or Google distroless
# FROM gcr.io/distroless/nodejs22-debian12

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

# Non-root user
USER nonroot

ENTRYPOINT ["node", "server.js"]
```

### Scan & Sign

```yaml
# CI pipeline
- name: Scan image
  run: trivy image --severity HIGH,CRITICAL --exit-code 1 myapp:${{ github.sha }}

- name: Sign image
  run: cosign sign --yes ghcr.io/myorg/myapp:${{ github.sha }}
```

### Image Policy

| Practice | Implementation |
|----------|----------------|
| Minimal base images | Chainguard, distroless, Alpine |
| No `latest` tag | Pin specific versions or digests |
| Multi-stage builds | Separate build and runtime stages |
| Non-root user | `USER nonroot` in Dockerfile |
| Read-only filesystem | `readOnlyRootFilesystem: true` |
| No package managers in prod | Remove apt/apk in final stage |

---

## 2. Control Plane Hardening

### API Server

```yaml
# Audit policy — log all auth and sensitive operations
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all authentication events
  - level: RequestResponse
    resources:
      - group: "authentication.k8s.io"
  # Log secret access
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets"]
  # Log RBAC changes
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
  # Default: log metadata for everything else
  - level: Metadata
```

### etcd Security

- Enable TLS for all etcd communication
- Restrict network access to etcd (control plane only)
- Enable encryption at rest for secrets
- Regular etcd backups with encryption

### Admission Controllers

```yaml
# Enable essential admission controllers
--enable-admission-plugins=\
  NodeRestriction,\
  PodSecurity,\
  ResourceQuota,\
  LimitRanger,\
  ServiceAccount
```

---

## 3. Workload Security

### Pod Security Standards (PSS)

PSS replaces deprecated PodSecurityPolicies. Three profiles:

| Profile | Use Case | Key Restrictions |
|---------|----------|-----------------|
| **Privileged** | System workloads | No restrictions |
| **Baseline** | Most workloads | Blocks known privilege escalations |
| **Restricted** | Security-sensitive | Non-root, read-only FS, drop all caps |

```yaml
# Enforce restricted profile on namespace
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### Secure Pod Spec

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  automountServiceAccountToken: false  # Don't mount SA token unless needed
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: ghcr.io/myorg/app@sha256:abc123...  # Pin by digest
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
        # Add back only what's needed:
        # add: ["NET_BIND_SERVICE"]
      resources:
        requests:
          memory: "128Mi"
          cpu: "100m"
        limits:
          memory: "256Mi"
          cpu: "500m"
      livenessProbe:
        httpGet:
          path: /healthz
          port: 8080
```

### RBAC

```yaml
# Least-privilege Role — only what the app needs
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: app-reader
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config"]  # Specific resource only
    verbs: ["get"]
---
# Bind to a dedicated service account
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: production
  name: app-reader-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: app-reader
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: production
```

### RBAC Anti-Patterns

```yaml
# NEVER do this in production:
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]          # God mode — violates least privilege

# AVOID cluster-admin bindings:
roleRef:
  kind: ClusterRole
  name: cluster-admin     # Too broad for any application
```

---

## 4. Network Security

### Default-Deny NetworkPolicy

```yaml
# Deny all ingress and egress by default
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: production
spec:
  podSelector: {}  # Applies to all pods
  policyTypes:
    - Ingress
    - Egress
---
# Then explicitly allow required traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-traffic
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web-api
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - port: 8080
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - port: 5432
    - to:  # Allow DNS
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
```

### Service Mesh (mTLS)

```yaml
# Istio — enforce mTLS across namespace
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: strict-mtls
  namespace: production
spec:
  mtls:
    mode: STRICT
```

---

## 5. Runtime Security

### Falco — Syscall Monitoring

```yaml
# Detect common runtime attacks
- rule: Terminal shell in container
  desc: A shell was spawned in a container
  condition: >
    spawned_process and container and
    proc.name in (bash, sh, zsh, dash)
  output: >
    Shell spawned in container
    (user=%user.name container=%container.name
     shell=%proc.name parent=%proc.pname)
  priority: WARNING

- rule: Read sensitive file after startup
  desc: Sensitive file read after container started
  condition: >
    open_read and container and
    fd.name in (/etc/shadow, /etc/passwd) and
    not proc.name in (login, passwd)
  output: >
    Sensitive file read (file=%fd.name container=%container.name)
  priority: CRITICAL
```

### Seccomp Profiles

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "openat", "close", "fstat",
                "mmap", "mprotect", "munmap", "brk", "futex",
                "getpid", "clone", "execve", "exit_group"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

---

## 6. Secrets Management

```yaml
# NEVER store secrets in plaintext ConfigMaps or env vars
# Use External Secrets Operator with a vault backend

apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: app-secrets
  data:
    - secretKey: database-url
      remoteRef:
        key: production/database
        property: url
    - secretKey: api-key
      remoteRef:
        key: production/api
        property: key
```

---

## Security Scanning Tools

| Tool | Layer | Open Source |
|------|-------|------------|
| **Trivy** | Image + IaC + SBOM | Yes |
| **Kubescape** | Cluster + workload | Yes |
| **kube-bench** | CIS benchmarks | Yes |
| **Falco** | Runtime | Yes |
| **Kyverno** | Policy engine | Yes |
| **Tetragon** | eBPF runtime | Yes |
| **Prowler** | KSPM | Yes |

```bash
# Quick cluster audit
kubescape scan framework cis-v1.23-t1.0.1

# CIS Kubernetes benchmark
kube-bench run --targets master,node

# Prowler Kubernetes scan
prowler kubernetes
```

## References

- [Kubernetes Security — kubernetes.io](https://kubernetes.io/docs/concepts/security/)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [CIS Kubernetes Benchmarks](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [Falco — falco.org](https://falco.org/)
- [Kyverno — kyverno.io](https://kyverno.io/)
