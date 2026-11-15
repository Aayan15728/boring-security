# Pack: Cloud and infrastructure

## When to use

IAM policies, Terraform/Pulumi/CloudFormation/CDK/Bicep, Kubernetes manifests and Helm, containers, service meshes, serverless and edge functions, ingress and gateways, runtime configuration, managed storage and event sources.

## Discipline

```text
- A finding needs a principal lower-trust than the resource it reaches: an internet client, a tenant
  workload, a CI job, a less-trusted service, or an attacker holding a limited foothold (SSRF, code
  execution in one component). "This role is broad" with no reachable lower-trust holder is hardening.
- The repo shows intent, not deployed state. Prefer static reading and offline renders (helm
  template, kustomize build, offline policy evaluators). Anything that needs provider state or a
  backend (terraform plan against state, cloud CLIs) is out of bounds.
- Effective permission = identity policies ∩ boundaries ∩ SCPs/org policies ∩ resource policies ∩
  conditions. Show every layer visible in source; name the invisible ones as blockers.
- State files, kubeconfigs and secret manifests may hold real secrets: read only what you need and
  never copy values into notes.
```

## Workload identity and IAM

**Workload identity overreach**
Pods, functions or VMs with roles granting far more than their code uses, reachable through a lower-trust input (SSRF, RCE in a less-trusted container, a tenant job).

**Cross-account or cross-tenant role confusion**
Trust policies with wildcard principals, missing `sts:ExternalId`, OIDC federation with wildcard `sub`/`aud`, workload identity bindings to whole namespaces.

**Application authorization delegated to cloud metadata**
Tags, labels or headers that tenants can set, used for authorization (ABAC on user-writable tags).

## Ingress, network, control plane

**Unexpected service or management-plane reachability**
Admin consoles, debug ports, databases, Kubelet/etcd, dashboards exposed through ingress, security groups, `LoadBalancer` services or `0.0.0.0/0` rules.

**Trusted-proxy and mesh identity bypass**
Identity headers (`X-User`, `X-Forwarded-Client-Cert`) trusted from any hop; mesh mTLS in `PERMISSIVE` mode where policy assumes strict; authorization policies missing for some ports or paths.

**Metadata and internal-service reachability**
SSRF-capable components able to reach IMDS (v1, or v2 with hop limit > 1 inside containers), cluster-internal APIs or cloud control endpoints.

## Containers and orchestration

**Host or control-plane capability exposure**
`privileged`, `hostPath`, `hostNetwork`/`hostPID`, `docker.sock` mounts, `CAP_SYS_ADMIN`, writable `/proc`/`/sys`; RBAC with `*` verbs, `secrets` get/list, `pods/exec`, `escalate`/`bind`/`impersonate`.

**Admission and policy path inconsistency**
Policies enforced on Deployments but not on CronJobs, Jobs, ephemeral containers or other namespaces; exemptions keyed on labels users control.

**Namespace and label trust confusion**
NetworkPolicies, authz or routing keyed on labels or namespaces that tenants can create or edit.

## Configuration and secrets

**Security-control precedence drift**
An env var, flag or overlay that disables a security default in some environments, with no guard preventing it in production.

**Secret exposure across workload boundaries**
Shared secrets mounted into less-trusted workloads; secrets in env exposed via debug endpoints, crash dumps or logs; secrets in image layers or build args.

**Credential renewal and outage fallback**
When refresh fails, code falls back to static, broader or no credentials.

## Storage, events, edge

**Object and signed-URL policy confusion**
Public buckets holding private data; signed URLs scoped too broadly or living too long; object keys built from user input.

**Event-source identity confusion**
Functions trusting event fields (bucket, sender, topic, `source`) that any publisher with put/publish access can set.

**Edge/runtime boundary mismatch**
The edge worker assumes the origin enforces auth, and the origin assumes the edge did; origin reachable directly, bypassing the edge.

## Moves

- Map each workload → identity → effective permissions → which untrusted inputs reach it.
- Render manifests offline and diff environments and overlays.
- Evaluate policies offline with dummy principals where a local tool exists.

## Gate

1. Name the lower-trust principal, its path to the resource, the permission or rule that allows it, and the resource at stake.
2. Show each policy layer visible in source; deployed state, org policies and drift are blockers when decisive.
