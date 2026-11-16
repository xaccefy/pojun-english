---
name: cloud-attack-methods
description: Use when the target uses cloud services/containers/K8s, or when cloud credentials (AK/SK/Token) are obtained or SSRF and metadata services are discovered — cloud metadata exploitation, STS/IAM privilege escalation, object storage, K8s escape, CI/CD credential chains.
tags:
  cwe: [CWE-918, CWE-522, CWE-269, CWE-284]
  attack: [T1552.005, T1078.004, T1611, T1195]
  class: [cloud, kubernetes, container, cicd, metadata]
---

# Cloud and Container Attack Techniques

## Cloud metadata (the first stop after SSRF/command execution)

- AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (IMDSv1);
  IMDSv2 needs a PUT to get the token: `TOKEN=$(curl -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds:21600' http://169.254.169.254/latest/api/token)`;
- Alibaba Cloud: `http://100.100.100.200/latest/meta-data/` (including ram/security-credentials);
- Tencent Cloud: `http://metadata.tencentyun.com/latest/meta-data/`;
- GCP: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (needs `Metadata-Flavor: Google`);
- Azure: `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` (needs Metadata: true);
- Once you have temporary credentials, verify permissions immediately (`aws sts get-caller-identity`); **read-only verification**, no writes, no deletes.

## Cloud credential abuse (within scope)

- AWS: `aws configure` then `aws sts get-caller-identity` → `aws iam list-users/list-attached-user-policies`;
  S3: `aws s3 ls`, `aws s3 cp s3://bucket/file -` (read-only sample);
- Alibaba Cloud: `aliyun sts GetCallerIdentity`, `aliyun oss ls` (via ossutil);
- Object storage direct access: bucket domain + directory listing characteristics (`?prefix=&max-keys=10`); unauthenticated listing/download counts as L3;
- AK/SK leaked from metadata must be **written to a fact in full** (including owning account/service), noting the source file/endpoint.

## Common IAM / STS privilege-escalation paths

- `iam:PassRole` + `ec2:RunInstances` (use with care, may incur cost);
- `iam:CreatePolicyVersion` / `AttachUserPolicy` self-escalation;
- Role trust policy too broad (`Principal: *`);
- Misconfigured OIDC federated trust (GitHub Actions → AWS, watch the subject condition).
> All write operations in the cloud are forbidden; at most use `simulate-principal-policy` to verify the permission surface.

## Kubernetes / Containers

- Inside a Pod, look first at: `/var/run/secrets/kubernetes.io/serviceaccount/token`, `env | grep -i kube`;
- Probe permissions with the token: `kubectl --token=<t> --server=https://kubernetes.default.svc auth can-i --list`;
- Escape surfaces: privileged containers, `hostPath` mounts, `hostPID/hostNetwork`, mounted docker.sock
  (`/var/run/docker.sock` can list host containers);
- Common in-container credentials: environment variables, ConfigMap mounts, image layer history (`docker history`);
- Conclusions must carry evidence: screenshots showing host files / host process lists / other namespaces' resources.

## CI/CD and supply chain

- Jenkins: unauthenticated `/script`, `/computer/(master)/script`, credential binding (credentials page);
- GitLab: CI variable leaks, unauthenticated `/api/v4/projects`, runner tokens;
- GitHub Actions: `pull_request_target` injection, secrets references in workflows;
- Dependency poisoning: internal npm/pypi registries, internal mirrors pointed at by `.npmrc`/`pip.conf`.

## Boundaries

- No write operations on the cloud control plane (do not create resources, change policies, or delete data);
- For object storage, take only the minimum sample proving readability;
- For production clusters, stop escape verification at "can read a host file"; do not move laterally to other tenants.
